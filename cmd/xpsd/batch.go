// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// FindingResult is the outcome of analyzing one scan finding.
type FindingResult struct {
	Finding Finding
	Raw     string   // extracted verdict JSON text (may be empty on error)
	Verdict *verdict // parsed verdict, nil when the output was unparseable
	Report  string   // rendered markdown report ("" when skipped or failed)
	Err     error    // analysis error, nil on success
}

// ScanDeps carries the per-finding work functions. Analyze runs the reachability
// session and returns the raw model output; Render turns a verdict into a
// markdown report.
type ScanDeps struct {
	Analyze func(ctx context.Context, f Finding, description string) (string, error)
	Render  func(ctx context.Context, description, verdictJSON string) (string, error)
	RunDir  string
}

// maxPromptDescriptionLen caps the advisory description embedded in the
// analysis prompt.
const maxPromptDescriptionLen = 4000

// findingDirRe strips anything unsafe from a finding id for use as a dir name.
var findingDirRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// verdictEnvelope is one entry in the aggregated verdicts.json.
type verdictEnvelope struct {
	Finding Finding         `json:"finding"`
	Verdict json.RawMessage `json:"verdict,omitempty"`
	Raw     string          `json:"raw_output,omitempty"` // set when verdict did not parse
	Error   string          `json:"error,omitempty"`
}

// ScanCounts tallies verdicts for exit-code and log summaries.
type ScanCounts struct {
	Reachable, NotReachable, Uncertain, Unparsed, Errors int
}

// BuildFindingDescription renders a normalized finding into the vulnerability
// description text fed to the analysis agent.
func BuildFindingDescription(f Finding) string {
	var sb strings.Builder

	fmt.Fprintf(&sb, "%s in package %s", f.ID, f.Package)
	if f.Version != "" {
		fmt.Fprintf(&sb, " version %s", f.Version)
	}
	if f.Ecosystem != "" {
		fmt.Fprintf(&sb, " (%s)", f.Ecosystem)
	}
	sb.WriteString(".")
	if len(f.Aliases) > 0 {
		fmt.Fprintf(&sb, " Also tracked as: %s.", strings.Join(f.Aliases, ", "))
	}
	sb.WriteString("\n")

	if f.Severity != "unknown" || f.CVSSScore > 0 {
		fmt.Fprintf(&sb, "Severity: %s", f.Severity)
		if f.CVSSScore > 0 {
			fmt.Fprintf(&sb, " (CVSS %.1f)", f.CVSSScore)
		}
		sb.WriteString(".\n")
	}
	if f.FixedVersion != "" {
		fmt.Fprintf(&sb, "Fixed in: %s.\n", f.FixedVersion)
	}
	if f.Target != "" {
		fmt.Fprintf(&sb, "Reported against: %s.\n", f.Target)
	}
	if f.Title != "" {
		fmt.Fprintf(&sb, "\n%s\n", f.Title)
	}
	if f.Description != "" {
		desc := f.Description
		if len(desc) > maxPromptDescriptionLen {
			desc = truncateUTF8(desc, maxPromptDescriptionLen) + "\n[description truncated]"
		}
		fmt.Fprintf(&sb, "\n%s\n", desc)
	}
	if len(f.URLs) > 0 {
		urls := f.URLs
		if len(urls) > 8 {
			urls = urls[:8]
		}
		sb.WriteString("\nReferences:\n")
		for _, u := range urls {
			fmt.Fprintf(&sb, "- %s\n", u)
		}
	}
	return strings.TrimSpace(sb.String())
}

// findingDirName builds a unique, filesystem-safe directory name for a
// finding's artifacts.
func findingDirName(i int, f Finding) string {
	name := fmt.Sprintf("%03d_%s", i+1, f.ID)
	if f.Package != "" {
		base := filepath.Base(f.Package) // e.g. golang.org/x/crypto -> crypto
		name += "_" + base
	}
	name = findingDirRe.ReplaceAllString(name, "_")
	name = strings.ReplaceAll(name, "..", "_") // hostile ids must not form ".." components
	if len(name) > 100 {
		name = name[:100]
	}
	return name
}

// RunScan analyzes each finding in order, persisting per-finding artifacts
// under <RunDir>/findings/. A finding whose analysis fails is recorded and the
// loop continues; the error is surfaced in its FindingResult.
func RunScan(ctx context.Context, deps ScanDeps, findings []Finding) []FindingResult {
	results := make([]FindingResult, 0, len(findings))

	for i, f := range findings {
		if ctx.Err() != nil {
			results = append(results, FindingResult{Finding: f, Err: ctx.Err()})
			continue
		}

		vlog("── finding %d/%d: %s %s@%s ──", i+1, len(findings), f.ID, f.Package, f.Version)
		desc := BuildFindingDescription(f)
		res := FindingResult{Finding: f}

		output, err := deps.Analyze(ctx, f, desc)
		if err != nil {
			log.Printf("finding %s: analysis failed: %v", f.ID, err)
			res.Err = err
		} else {
			res.Raw = extractVerdictJSON(output)
			res.Verdict = parseVerdict(res.Raw)
			if res.Verdict == nil {
				log.Printf("finding %s: warning: verdict output did not parse as JSON", f.ID)
			}
		}

		dir := filepath.Join(deps.RunDir, "findings", findingDirName(i, f))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			log.Printf("finding %s: creating %s: %v", f.ID, dir, err)
		} else {
			if res.Raw != "" {
				writeFileLogged(filepath.Join(dir, "verdict.json"), res.Raw+"\n")
			}
			writeFileLogged(filepath.Join(dir, "finding.json"), mustJSON(f))
		}

		if deps.Render != nil && res.Raw != "" {
			report, rerr := deps.Render(ctx, desc, res.Raw)
			if rerr != nil {
				log.Printf("finding %s: report rendering failed: %v", f.ID, rerr)
			} else {
				res.Report = strings.TrimSpace(report)
				writeFileLogged(filepath.Join(dir, "report.md"), res.Report+"\n")
			}
		}

		results = append(results, res)
	}
	return results
}

// parseVerdict parses extracted verdict JSON, returning nil when it does not
// parse or lacks the one required field.
func parseVerdict(raw string) *verdict {
	var v verdict
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		return nil
	}
	if v.Reachable == "" {
		return nil
	}
	return &v
}

// extractVerdictJSON pulls the verdict JSON object out of raw LLM output,
// tolerating code fences and stray prose. Falls back to the trimmed original
// when no JSON object can be found.
func extractVerdictJSON(output string) string {
	if block := ExtractJSONBlock(output); block != "" {
		return ExtractJSON(block)
	}
	return strings.TrimSpace(output)
}

// WriteScanArtifacts writes the aggregated verdicts.json and summary.md for a
// scan run. Returns the verdicts path for logging.
func WriteScanArtifacts(runDir string, results []FindingResult) (string, error) {
	envelopes := make([]verdictEnvelope, 0, len(results))
	for _, r := range results {
		env := verdictEnvelope{Finding: r.Finding}
		if r.Err != nil {
			env.Error = r.Err.Error()
		}
		if r.Verdict != nil {
			env.Verdict = json.RawMessage(r.Raw)
		} else if r.Raw != "" {
			env.Raw = r.Raw
		}
		envelopes = append(envelopes, env)
	}

	verdictsPath := filepath.Join(runDir, "verdicts.json")
	data, err := json.MarshalIndent(envelopes, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshaling verdicts: %w", err)
	}
	if err := os.WriteFile(verdictsPath, append(data, '\n'), 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", verdictsPath, err)
	}

	summaryPath := filepath.Join(runDir, "summary.md")
	if err := os.WriteFile(summaryPath, []byte(renderScanSummary(results)), 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", summaryPath, err)
	}
	return verdictsPath, nil
}

// renderScanSummary builds the aggregated markdown summary table.
func renderScanSummary(results []FindingResult) string {
	var sb strings.Builder
	sb.WriteString("# xpsd scan summary\n\n")
	fmt.Fprintf(&sb, "%d finding(s) analyzed.\n\n", len(results))
	sb.WriteString("| Vulnerability | Package | Version | Severity | Reachable | Confidence |\n")
	sb.WriteString("| --- | --- | --- | --- | --- | --- |\n")
	for _, r := range results {
		reachable, confidence := "error", "n/a"
		if r.Err == nil {
			if r.Verdict != nil {
				reachable, confidence = r.Verdict.Reachable, r.Verdict.Confidence
			} else {
				reachable, confidence = "unparsed", "n/a"
			}
		}
		fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s | %s |\n",
			r.Finding.ID, r.Finding.Package, r.Finding.Version,
			r.Finding.Severity, reachable, confidence)
	}
	sb.WriteString("\nPer-finding verdicts and reports are under findings/.\n")
	return sb.String()
}

func CountResults(results []FindingResult) ScanCounts {
	var c ScanCounts
	for _, r := range results {
		switch {
		case r.Err != nil:
			c.Errors++
		case r.Verdict == nil:
			c.Unparsed++
		case r.Verdict.Reachable == "yes":
			c.Reachable++
		case r.Verdict.Reachable == "no":
			c.NotReachable++
		default:
			c.Uncertain++
		}
	}
	return c
}

// FailOnTriggered reports whether the -fail-on policy fires for these results.
// Policy "reachable" fires on any reachable=yes verdict; "uncertain" fires on
// reachable=yes, uncertain, unparseable output, or analysis errors.
func FailOnTriggered(policy string, c ScanCounts) bool {
	switch policy {
	case "reachable":
		return c.Reachable > 0
	case "uncertain":
		return c.Reachable > 0 || c.Uncertain > 0 || c.Unparsed > 0 || c.Errors > 0
	}
	return false
}

func writeFileLogged(path, content string) {
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		log.Printf("warning: writing %s: %v", path, err)
	}
}

func mustJSON(v any) string {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data) + "\n"
}

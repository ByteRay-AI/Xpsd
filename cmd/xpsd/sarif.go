// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// verdict is the agent's output JSON (the schema in reachabilitySystemPrompt).
type verdict struct {
	CVE                   string          `json:"cve"`
	Reachable             string          `json:"reachable"`
	Confidence            string          `json:"confidence"`
	DetectedVersion       string          `json:"detected_version"`
	VersionApplicable     *bool           `json:"version_applicable"`
	VulnerableCodePresent bool            `json:"vulnerable_code_present"`
	AffectedComponent     string          `json:"affected_component"`
	Rationale             string          `json:"rationale"`
	Evidence              []evidenceEntry `json:"evidence"`
	CallPath              []string        `json:"call_path"`
}

type evidenceEntry struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Note string `json:"note"`
}

// SARIF 2.1.0 document model (the subset Xpsd emits).

type sarifLog struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool              `json:"tool"`
	Results           []sarifResult          `json:"results"`
	AutomationDetails *sarifAutomationDetail `json:"automationDetails,omitempty"`
}

// sarifAutomationDetail sets the default code-scanning category.
type sarifAutomationDetail struct {
	ID string `json:"id"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string          `json:"id"`
	Name                 string          `json:"name,omitempty"`
	ShortDescription     *sarifText      `json:"shortDescription,omitempty"`
	FullDescription      *sarifText      `json:"fullDescription,omitempty"`
	Help                 *sarifHelp      `json:"help,omitempty"`
	HelpURI              string          `json:"helpUri,omitempty"`
	DefaultConfiguration *sarifRuleCfg   `json:"defaultConfiguration,omitempty"`
	Properties           *sarifRuleProps `json:"properties,omitempty"`
}

type sarifRuleCfg struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifRuleProps struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
	Message          *sarifText            `json:"message,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

// Plain repo-relative URIs, no uriBaseId: GitHub treats relative URIs as
// repo-root-relative.
type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"` // required by GitHub code scanning
}

const (
	sarifSchemaURI = "https://json.schemastore.org/sarif-2.1.0.json"
	toolInfoURI    = "https://github.com/byteray-ai/xpsd"
	// Bound on alert message length; GitHub shows only the first sentence in the alert list.
	maxMessageLen = 8000
	// GitHub's documented limits for rule descriptions.
	maxRuleDescLen = 1024
)

// buildVersion is stamped via -ldflags "-X main.buildVersion=..."; "dev" for
// local builds.
var buildVersion = "dev"

// manifestCandidates are checked in order when a finding has no usable
// location; the first one present in the repo anchors the result.
var manifestCandidates = []string{
	"go.mod", "package-lock.json", "package.json", "yarn.lock",
	"requirements.txt", "Pipfile.lock", "pyproject.toml",
	"pom.xml", "build.gradle", "Cargo.lock", "Gemfile.lock",
	"composer.lock", "Dockerfile", "README.md",
}

// sarifLevel maps verdict + confidence to a SARIF result level.
func sarifLevel(reachable, confidence string) string {
	switch reachable {
	case "yes":
		if confidence == "low" {
			return "warning"
		}
		return "error"
	case "no":
		return "note"
	default:
		return "warning"
	}
}

// securitySeverity renders the rule's security-severity property, which GitHub
// uses to bucket alerts (critical >= 9.0, high >= 7.0, medium >= 4.0, low > 0).
// Falls back from a real CVSS score to a band-representative value.
func securitySeverity(f Finding) string {
	if f.CVSSScore > 0 {
		return fmt.Sprintf("%.1f", f.CVSSScore)
	}
	switch f.Severity {
	case "critical":
		return "9.5"
	case "high":
		return "8.0"
	case "medium":
		return "5.5"
	case "low", "negligible":
		return "2.0"
	}
	return ""
}

// BuildScanSARIF renders the results of a scan run as one SARIF 2.1.0 run:
// one rule per distinct vulnerability id, one result per analyzed finding.
// srcAbs is the analyzed source root, stripped from evidence paths. uriPrefix
// is the repo-root-relative path of srcAbs ("" when they coincide).
func BuildScanSARIF(results []FindingResult, srcAbs, uriPrefix string) ([]byte, error) {
	// GitHub requires arrays, not null.
	rules := []sarifRule{}
	ruleIndex := map[string]int{}

	sarifResults := []sarifResult{}
	for _, r := range results {
		f := r.Finding

		idx, ok := ruleIndex[f.ID]
		if !ok {
			idx = len(rules)
			ruleIndex[f.ID] = idx
			rules = append(rules, buildRule(f))
		}

		sarifResults = append(sarifResults, buildResult(r, idx, srcAbs, uriPrefix))
	}

	doc := sarifLog{
		Version: "2.1.0",
		Schema:  sarifSchemaURI,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "xpsd",
				Version:        buildVersion,
				InformationURI: toolInfoURI,
				Rules:          rules,
			}},
			Results:           sarifResults,
			AutomationDetails: &sarifAutomationDetail{ID: "xpsd/"},
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// buildRule renders the per-vulnerability SARIF rule.
func buildRule(f Finding) sarifRule {
	title := f.Title
	if title == "" {
		title = fmt.Sprintf("%s in %s", f.ID, f.Package)
	}
	title = truncateUTF8(title, maxRuleDescLen)
	fullDesc := f.Description
	if fullDesc == "" {
		fullDesc = title
	}
	fullDesc = truncateUTF8(fullDesc, maxRuleDescLen)

	helpURI := ""
	if len(f.URLs) > 0 {
		helpURI = f.URLs[0]
	} else if strings.HasPrefix(f.ID, "CVE-") {
		helpURI = "https://nvd.nist.gov/vuln/detail/" + f.ID
	}

	var help strings.Builder
	fmt.Fprintf(&help, "Reachability analysis of %s", f.ID)
	if f.Package != "" {
		fmt.Fprintf(&help, " in %s", f.Package)
		if f.Version != "" {
			fmt.Fprintf(&help, "@%s", f.Version)
		}
	}
	help.WriteString(".")
	if f.FixedVersion != "" {
		fmt.Fprintf(&help, " Remediation: upgrade to %s.", f.FixedVersion)
	}

	return sarifRule{
		ID:                   f.ID,
		Name:                 sanitizeRuleName(f.ID),
		ShortDescription:     &sarifText{Text: title},
		FullDescription:      &sarifText{Text: fullDesc},
		Help:                 &sarifHelp{Text: help.String(), Markdown: help.String()},
		HelpURI:              helpURI,
		DefaultConfiguration: &sarifRuleCfg{Level: "warning"},
		Properties: &sarifRuleProps{
			Tags:             []string{"security", "reachability", "xpsd"},
			SecuritySeverity: securitySeverity(f),
		},
	}
}

// sanitizeRuleName converts a vuln id to a SARIF rule name (alphanumeric).
func sanitizeRuleName(id string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, id)
}

// buildResult renders one finding's analysis outcome as a SARIF result.
func buildResult(r FindingResult, ruleIdx int, srcAbs, uriPrefix string) sarifResult {
	f := r.Finding

	var level, message string
	switch {
	case r.Err != nil:
		level = "warning"
		message = fmt.Sprintf("xpsd could not analyze %s in %s@%s: %v. Treat as unreviewed.",
			f.ID, f.Package, f.Version, r.Err)
	case r.Verdict == nil:
		level = "warning"
		message = fmt.Sprintf("xpsd analyzed %s in %s@%s but produced an unparseable verdict. Treat as unreviewed.",
			f.ID, f.Package, f.Version)
	default:
		v := r.Verdict
		level = sarifLevel(v.Reachable, v.Confidence)
		var sb strings.Builder
		switch v.Reachable {
		case "yes":
			fmt.Fprintf(&sb, "REACHABLE (%s confidence): ", v.Confidence)
		case "no":
			fmt.Fprintf(&sb, "Not reachable (%s confidence): ", v.Confidence)
		default:
			fmt.Fprintf(&sb, "Reachability uncertain (%s confidence): ", v.Confidence)
		}
		sb.WriteString(strings.TrimSpace(v.Rationale))
		if len(v.CallPath) > 0 {
			fmt.Fprintf(&sb, "\n\nCall path: %s", strings.Join(v.CallPath, " → "))
		}
		message = sb.String()
	}
	message = truncateUTF8(message, maxMessageLen)

	res := sarifResult{
		RuleID:    f.ID,
		RuleIndex: ruleIdx,
		Level:     level,
		Message:   sarifText{Text: message},
		Locations: buildLocations(r, srcAbs, uriPrefix),
		PartialFingerprints: map[string]string{
			"xpsdFindingKey/v1": fingerprint(f.Key()),
		},
	}

	props := map[string]any{
		"package": f.Package,
		"version": f.Version,
	}
	if r.Verdict != nil {
		props["reachable"] = r.Verdict.Reachable
		props["confidence"] = r.Verdict.Confidence
	}
	if f.FixedVersion != "" {
		props["fixedVersion"] = f.FixedVersion
	}
	res.Properties = props
	return res
}

// buildLocations converts verdict evidence into SARIF locations, falling back
// to the scanner-reported target file, then to a manifest file that exists in
// the repo. GitHub rejects results without a real file path and requires
// region.startLine on every location.
func buildLocations(r FindingResult, srcAbs, uriPrefix string) []sarifLocation {
	var locations []sarifLocation
	if r.Verdict != nil {
		for _, e := range r.Verdict.Evidence {
			if e.File == "" {
				continue
			}
			uri := relativePath(e.File, srcAbs)
			if uri == "" {
				// Evidence outside the repo (fetched dependency sources,
				// absolute host paths): anchor the note to a file that exists.
				uri = fallbackURI(r.Finding.Target, srcAbs)
			}
			line := e.Line
			if line < 1 {
				line = 1
			}
			loc := sarifLocation{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: prefixURI(uriPrefix, uri)},
					Region:           &sarifRegion{StartLine: line},
				},
			}
			note := e.Note
			if note == "" {
				note = "Evidence: " + e.File
			}
			loc.Message = &sarifText{Text: note}
			locations = append(locations, loc)
		}
	}
	if len(locations) == 0 {
		locations = []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: prefixURI(uriPrefix, fallbackURI(r.Finding.Target, srcAbs))},
				Region:           &sarifRegion{StartLine: 1},
			},
			Message: &sarifText{Text: "No specific code location; finding anchored to the scanned manifest."},
		}}
	}
	return locations
}

// prefixURI prepends the repo-root-relative source prefix to a source-relative
// URI.
func prefixURI(uriPrefix, uri string) string {
	if uriPrefix == "" {
		return uri
	}
	return path.Join(uriPrefix, uri)
}

// fallbackURI picks a repo-relative file to anchor a finding without evidence:
// the scanner-reported target when that file really exists in the repo,
// otherwise the first manifest file found, otherwise README.md.
func fallbackURI(target, srcAbs string) string {
	target = strings.TrimSpace(target)
	if target != "" {
		rel := target
		if filepath.IsAbs(target) {
			rel = relativePath(target, srcAbs)
		}
		rel = filepath.ToSlash(rel)
		if fileExistsIn(srcAbs, rel) {
			return rel
		}
	}
	for _, m := range manifestCandidates {
		if fileExistsIn(srcAbs, m) {
			return m
		}
	}
	// Last resort: prefer a real file.
	if fileExistsIn(srcAbs, "README.md") {
		return "README.md"
	}
	if rel := relativePath(target, srcAbs); rel != "" {
		return rel
	}
	return "README.md"
}

// fileExistsIn reports whether rel names a regular file under root.
func fileExistsIn(root, rel string) bool {
	if root == "" || rel == "" || strings.HasPrefix(rel, "..") {
		return false
	}
	info, err := os.Stat(filepath.Join(root, filepath.FromSlash(rel)))
	return err == nil && info.Mode().IsRegular()
}

// fingerprint builds the stable partial fingerprint for a finding key.
func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

// VerdictToSARIF converts a single raw verdict JSON string (single-CVE mode)
// to SARIF, reusing the scan-mode builder with a synthetic finding. Output
// that does not parse as a verdict still produces a SARIF file with an
// "unreviewed" warning result.
func VerdictToSARIF(verdictText, srcAbs, uriPrefix string) ([]byte, error) {
	res := FindingResult{Raw: verdictText}
	res.Verdict = parseVerdict(verdictText)

	var v verdict
	if res.Verdict != nil {
		v = *res.Verdict
	}
	res.Finding = Finding{
		ID:      v.CVE,
		Package: v.AffectedComponent,
		Version: v.DetectedVersion,
	}
	if res.Finding.ID == "" {
		res.Finding.ID = "xpsd/reachability"
	}

	return BuildScanSARIF([]FindingResult{res}, srcAbs, uriPrefix)
}

// relativePath converts an evidence file path to a source-root-relative URI.
// Paths under /src (the in-sandbox mount point the agent sees) and paths under
// srcAbs are stripped to their relative part; already-relative paths pass
// through unchanged. Returns "" when no plausible in-repo path can be derived
// (e.g. /tool_output dependency sources, absolute paths outside the source
// root, Windows-style paths).
func relativePath(file, srcAbs string) string {
	if strings.Contains(file, `\`) {
		return ""
	}
	// A scheme in a location URI is invalid SARIF.
	if strings.Contains(file, "://") {
		return ""
	}
	if rest, ok := strings.CutPrefix(file, "/src/"); ok {
		rel := filepath.ToSlash(filepath.Clean(rest))
		if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || strings.HasPrefix(rel, "/") {
			return ""
		}
		return rel
	}
	if file == "/src" || file == "" {
		return ""
	}
	if !filepath.IsAbs(file) {
		rel := filepath.ToSlash(filepath.Clean(file))
		if rel == "." || strings.HasPrefix(rel, "../") {
			return ""
		}
		return rel
	}
	if srcAbs != "" {
		if rel, err := filepath.Rel(srcAbs, file); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return ""
}

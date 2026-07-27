// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	copilot "github.com/github/copilot-sdk/go"
)

// defaultChallengeCycles is the adversarial pass's tool-call budget. It is much
// smaller than the primary loop's: the reviewer goes straight to the one claim
// the verdict rests on rather than surveying the tree.
const defaultChallengeCycles = 15

// ChallengeOpts holds the adversarial pass's own budgets, kept separate from the
// primary loop's so a short review cannot inherit a long analysis's allowance.
type ChallengeOpts struct {
	Cycles    int // tool-call budget; 0 disables the pass
	MaxTokens int // context-token ceiling; 0 = unlimited
	// Orientation is the project layout gathered once for the run, handed over
	// so the reviewer does not spend part of its small budget re-fetching it.
	Orientation string
	// UsageOut accumulates this pass's usage. It is added to, not overwritten,
	// so one accumulator totals every review across a scan.
	UsageOut *SessionUsage
}

// challengeTools is the adversarial pass's tool set: source reading and
// structural search only. No fetch_url, no osv_get_vuln, no
// fetch_dependency_source, no run_python. A dependency the primary pass already
// fetched stays readable under /tool_output with read_local_file.
var challengeTools = []string{
	"source_languages",
	"source_dirs",
	"expand_folder",
	"read_local_file",
	"get_line_count",
	"grep",
	"lang_search_pattern",
	"lang_find_calls",
	"lang_get_definition",
	"lang_get_xrefs",
	"lang_get_outline",
	"lang_get_imports",
	"lang_find_strings",
	"lang_find_similar",
}

// challenge is the adversarial pass's output JSON.
type challenge struct {
	Agrees     bool            `json:"agrees"`
	Reachable  string          `json:"reachable"`
	Confidence string          `json:"confidence"`
	Finding    string          `json:"finding"`
	Evidence   []evidenceEntry `json:"evidence"`
	CallPath   []string        `json:"call_path"`
}

// ChallengeVerdict runs the adversarial pass over a primary verdict and returns
// the verdict JSON to use downstream, plus whether it was overridden.
//
// The pass runs only on decisive verdicts. An "uncertain" verdict is already
// flagged for a human, so a second opinion changes nothing.
//
// On disagreement the reviewer's answer wins, and its evidence and call path
// replace the primary's. The primary rationale is kept in the merged verdict so
// the overridden reasoning stays visible in the report and the SARIF alert.
func ChallengeVerdict(
	ctx context.Context,
	client *copilot.Client,
	opts SessionOpts,
	cve, primaryRaw string,
	cOpts ChallengeOpts,
) (string, bool) {
	if cOpts.Cycles <= 0 {
		return primaryRaw, false
	}
	v := parseVerdict(primaryRaw)
	if v == nil {
		vlog("adversarial pass skipped: primary verdict did not parse")
		return primaryRaw, false
	}
	if v.Reachable != "yes" && v.Reachable != "no" {
		vlog("adversarial pass skipped: verdict is %q, already flagged for review", v.Reachable)
		return primaryRaw, false
	}

	var usage SessionUsage
	runOpts := opts
	runOpts.MaxCycles = cOpts.Cycles
	runOpts.MaxTokens = cOpts.MaxTokens
	runOpts.ToolAllow = challengeTools
	runOpts.UsageOut = &usage
	if cOpts.UsageOut != nil {
		defer func() {
			cOpts.UsageOut.Tokens += usage.Tokens
			cOpts.UsageOut.Requests += usage.Requests
			cOpts.UsageOut.ToolCalls += usage.ToolCalls
			cOpts.UsageOut.NanoAIU += usage.NanoAIU
			cOpts.UsageOut.HasCost = cOpts.UsageOut.HasCost || usage.HasCost
			cOpts.UsageOut.PromptTokens += usage.PromptTokens
			if cOpts.UsageOut.Model == "" {
				cOpts.UsageOut.Model = usage.Model
			}
		}()
	}

	vlog("adversarial pass: challenging %q verdict (max-cycles=%d, max-tokens=%d, source tools only)…",
		v.Reachable, cOpts.Cycles, cOpts.MaxTokens)

	out, err := RunSession(ctx, client, runOpts, challengeSystemPrompt, buildChallengeMessage(cve, v, cOpts.Orientation))
	if err != nil {
		log.Printf("warning: adversarial pass failed, keeping the original verdict: %v", err)
		return primaryRaw, false
	}

	c := parseChallenge(out)
	if c == nil {
		log.Printf("warning: adversarial pass output did not parse, keeping the original verdict")
		return primaryRaw, false
	}

	if c.Agrees || c.Reachable == "" || c.Reachable == v.Reachable {
		vlog("adversarial pass: agrees with %q", v.Reachable)
		return primaryRaw, false
	}
	// A disagreement with no code behind it is an opinion, not a finding.
	if len(c.Evidence) == 0 {
		log.Printf("warning: adversarial pass disagreed (%s -> %s) without citing code; keeping the original verdict",
			v.Reachable, c.Reachable)
		return primaryRaw, false
	}

	merged, err := mergeChallenge(v, c)
	if err != nil {
		log.Printf("warning: merging the adversarial verdict failed, keeping the original: %v", err)
		return primaryRaw, false
	}
	log.Printf("adversarial pass OVERRODE the verdict: %s -> %s (%s)",
		v.Reachable, c.Reachable, firstLine(c.Finding))
	return merged, true
}

// parseChallenge extracts the reviewer's JSON, tolerating fences and prose the
// same way the primary verdict is parsed.
func parseChallenge(raw string) *challenge {
	text := extractVerdictJSON(raw)
	var c challenge
	if err := json.Unmarshal([]byte(text), &c); err != nil {
		return nil
	}
	c.Reachable = strings.ToLower(strings.TrimSpace(c.Reachable))
	c.Confidence = strings.ToLower(strings.TrimSpace(c.Confidence))
	switch c.Reachable {
	case "yes", "no", "uncertain", "":
	default:
		return nil
	}
	return &c
}

// mergeChallenge applies the reviewer's answer to the primary verdict, keeping
// the schema the report and SARIF writers expect.
func mergeChallenge(v *verdict, c *challenge) (string, error) {
	out := *v
	out.Reachable = c.Reachable
	if c.Confidence != "" {
		out.Confidence = c.Confidence
	}
	out.Evidence = append(append([]evidenceEntry{}, c.Evidence...), v.Evidence...)
	if c.Reachable == "yes" {
		out.CallPath = c.CallPath
		out.AttemptedPath = nil
	} else {
		// The route is no longer a verified path, but it is still what was
		// walked, and a reader needs those locations to check the overturn.
		if len(out.AttemptedPath) == 0 {
			out.AttemptedPath = v.CallPath
		}
		out.CallPath = nil
	}
	out.Rationale = fmt.Sprintf(
		"Overturned by the adversarial review pass. %s\n\nThe first pass concluded %q: %s",
		strings.TrimSpace(c.Finding), v.Reachable, strings.TrimSpace(v.Rationale))

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}

// formatUsage renders the run's cumulative usage. In scan mode analysis and
// review hold the totals across every finding, not one session's.
func formatUsage(analysis, review SessionUsage) string {
	total := SessionUsage{
		Tokens:       analysis.Tokens + review.Tokens,
		Requests:     analysis.Requests + review.Requests,
		ToolCalls:    analysis.ToolCalls + review.ToolCalls,
		PromptTokens: analysis.PromptTokens + review.PromptTokens,
	}
	line := fmt.Sprintf("tokens: ~%.0f sent, %.0f in context | LLM requests: %d | tool calls: %d",
		total.PromptTokens, total.Tokens, total.Requests, total.ToolCalls)
	if review.Requests == 0 && review.ToolCalls == 0 && review.PromptTokens == 0 {
		return line
	}
	// With a review pass the numbers get long, so split the stages onto their
	// own lines rather than trailing a parenthetical off the end.
	return fmt.Sprintf("%s\n  analysis: ~%.0f tokens, %d requests, %d tool calls"+
		"\n  review:   ~%.0f tokens, %d requests, %d tool calls",
		line,
		analysis.PromptTokens, analysis.Requests, analysis.ToolCalls,
		review.PromptTokens, review.Requests, review.ToolCalls)
}

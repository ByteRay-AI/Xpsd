// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseChallenge(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want *challenge
	}{
		{
			name: "plain json",
			raw:  `{"agrees":false,"reachable":"no","confidence":"high","finding":"guard blocks"}`,
			want: &challenge{Agrees: false, Reachable: "no", Confidence: "high", Finding: "guard blocks"},
		},
		{
			name: "fenced with prose",
			raw:  "Here is my answer:\n```json\n{\"agrees\":true,\"reachable\":\"yes\"}\n```\n",
			want: &challenge{Agrees: true, Reachable: "yes"},
		},
		{
			name: "case and space normalized",
			raw:  `{"agrees":false,"reachable":" NO ","confidence":"HIGH"}`,
			want: &challenge{Agrees: false, Reachable: "no", Confidence: "high"},
		},
		{name: "not json", raw: "I could not decide.", want: nil},
		{name: "bogus verdict value", raw: `{"agrees":false,"reachable":"maybe"}`, want: nil},
	}
	for _, c := range cases {
		got := parseChallenge(c.raw)
		if c.want == nil {
			if got != nil {
				t.Errorf("%s: expected nil, got %+v", c.name, got)
			}
			continue
		}
		if got == nil {
			t.Errorf("%s: expected a parse, got nil", c.name)
			continue
		}
		if got.Reachable != c.want.Reachable || got.Confidence != c.want.Confidence ||
			got.Agrees != c.want.Agrees {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestMergeChallengeOverturnsToNotReachable(t *testing.T) {
	v := &verdict{
		CVE: "CVE-2024-45337", Reachable: "yes", Confidence: "high",
		Rationale: "pattern matches and the path is syntactically present",
		CallPath:  []string{"main", "handle", "PublicKeyCallback"},
		Evidence:  []evidenceEntry{{File: "/src/main.go", Line: 60, Note: "callback stores key"}},
	}
	c := &challenge{
		Agrees: false, Reachable: "no", Confidence: "high",
		Finding:  "no AddHostKey call, so NewServerConn errors before auth",
		Evidence: []evidenceEntry{{File: "/src/main.go", Line: 59, Note: "no host key configured"}},
	}
	merged, err := mergeChallenge(v, c)
	if err != nil {
		t.Fatal(err)
	}
	var got verdict
	if err := json.Unmarshal([]byte(merged), &got); err != nil {
		t.Fatalf("merged verdict is not valid JSON: %v", err)
	}
	if got.Reachable != "no" {
		t.Errorf("reachable = %q, want no", got.Reachable)
	}
	// A "no" carries no call path.
	if len(got.CallPath) != 0 {
		t.Errorf("call path survived an overturn to no: %v", got.CallPath)
	}
	// The reviewer's evidence leads, and the original evidence is kept.
	if len(got.Evidence) != 2 || got.Evidence[0].Line != 59 {
		t.Errorf("evidence = %+v, want the reviewer's first then the original", got.Evidence)
	}
	// Fields the reviewer does not speak to are preserved.
	if got.CVE != "CVE-2024-45337" {
		t.Errorf("cve lost: %q", got.CVE)
	}
	// Both rationales stay visible.
	for _, want := range []string{"adversarial review", "no AddHostKey", "syntactically present"} {
		if !strings.Contains(got.Rationale, want) {
			t.Errorf("rationale missing %q: %s", want, got.Rationale)
		}
	}
}

func TestMergeChallengeOverturnsToReachable(t *testing.T) {
	v := &verdict{Reachable: "no", Confidence: "high", Rationale: "symbol not used"}
	c := &challenge{
		Agrees: false, Reachable: "yes", Confidence: "medium",
		Finding:  "a second caller reaches the sink",
		CallPath: []string{"serve (a.go:10)", "parse (b.go:44)"},
		Evidence: []evidenceEntry{{File: "/src/b.go", Line: 44, Note: "reaches the sink"}},
	}
	merged, err := mergeChallenge(v, c)
	if err != nil {
		t.Fatal(err)
	}
	var got verdict
	if err := json.Unmarshal([]byte(merged), &got); err != nil {
		t.Fatal(err)
	}
	if got.Reachable != "yes" || got.Confidence != "medium" {
		t.Errorf("got %s/%s, want yes/medium", got.Reachable, got.Confidence)
	}
	if len(got.CallPath) != 2 {
		t.Errorf("corrected call path not applied: %v", got.CallPath)
	}
}

// The merged verdict must stay parseable by the same reader the rest of the
// pipeline uses, or SARIF and the report silently degrade.
func TestMergedVerdictRoundTrips(t *testing.T) {
	v := &verdict{CVE: "CVE-1", Reachable: "yes", Confidence: "high"}
	c := &challenge{Reachable: "no", Confidence: "low", Finding: "guarded",
		Evidence: []evidenceEntry{{File: "/src/x.go", Line: 1, Note: "guard"}}}
	merged, err := mergeChallenge(v, c)
	if err != nil {
		t.Fatal(err)
	}
	if got := parseVerdict(merged); got == nil || got.Reachable != "no" {
		t.Fatalf("merged verdict did not round-trip through parseVerdict: %v", got)
	}
}

// The adversary must not reach the network: no advisory lookup, no page fetch,
// no dependency download, no code execution.
func TestChallengeToolsExcludeNetworkAndExec(t *testing.T) {
	banned := map[string]bool{
		"fetch_url": true, "osv_get_vuln": true,
		"fetch_dependency_source": true, "run_python": true,
	}
	for _, name := range challengeTools {
		if banned[name] {
			t.Errorf("%s must not be available to the adversarial pass", name)
		}
	}
	// The tools it needs to check an edge must be present.
	need := []string{"read_local_file", "grep", "lang_find_calls", "lang_get_xrefs"}
	have := map[string]bool{}
	for _, n := range challengeTools {
		have[n] = true
	}
	for _, n := range need {
		if !have[n] {
			t.Errorf("%s missing from the adversarial tool set", n)
		}
	}
}

// A "no" verdict must hand the reviewer the route it explored, otherwise the
// reviewer starts blind and burns its small budget rediscovering the code.
func TestChallengeMessageCarriesLocations(t *testing.T) {
	v := &verdict{
		Reachable: "no", Confidence: "high",
		AttemptedPath: []string{
			"main (/src/main.go:58)",
			"handle (/src/main.go:21)",
			"serverHandshake (/tool_output/deps/x/ssh/server.go:253)",
		},
		Evidence:  []evidenceEntry{{File: "/src/main.go", Line: 59, Note: "no host key"}},
		Rationale: "blocked at the handshake",
	}
	msg := buildChallengeMessage("CVE-2024-45337", v, "")
	for _, want := range []string{
		"route explored",
		"main (/src/main.go:58)",
		"/tool_output/deps/x/ssh/server.go:253",
		"/src/main.go:59",
		"blocked at the handshake",
		"claims the sink is NOT reachable",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("challenge message missing %q\n---\n%s", want, msg)
		}
	}
}

// An overturn to "no" must carry the reviewer's own explored route forward.
func TestMergeKeepsAttemptedPathOnNo(t *testing.T) {
	v := &verdict{Reachable: "yes", CallPath: []string{"a (/src/a.go:1)"}}
	c := &challenge{Reachable: "no", Finding: "blocked",
		Evidence: []evidenceEntry{{File: "/src/a.go", Line: 9, Note: "early return"}}}
	merged, err := mergeChallenge(v, c)
	if err != nil {
		t.Fatal(err)
	}
	got := parseVerdict(merged)
	if got == nil || len(got.CallPath) != 0 {
		t.Fatalf("call path must be cleared on an overturn to no: %+v", got)
	}
	if len(got.AttemptedPath) == 0 || got.AttemptedPath[0] != "a (/src/a.go:1)" {
		t.Errorf("the route that was walked was lost: %+v", got.AttemptedPath)
	}
}

// The cost line must cover both stages, or a run looks cheaper than it was.
func TestFormatUsageCountsBothStages(t *testing.T) {
	got := formatUsage(
		SessionUsage{Tokens: 15258, Requests: 9, ToolCalls: 21, PromptTokens: 90000},
		SessionUsage{Tokens: 7644, Requests: 7, ToolCalls: 12, PromptTokens: 40000})
	for _, want := range []string{"~130000 sent", "22902 in context", "LLM requests: 16",
		"tool calls: 33", "analysis: ~90000 tokens, 9 requests, 21 tool calls",
		"review:   ~40000 tokens, 7 requests, 12 tool calls"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
	// With the review off, the line stays as it was.
	got = formatUsage(SessionUsage{Tokens: 100, Requests: 2, ToolCalls: 4, PromptTokens: 250}, SessionUsage{})
	if got != "tokens: ~250 sent, 100 in context | LLM requests: 2 | tool calls: 4" {
		t.Errorf("unexpected line with no review: %q", got)
	}
}

// Scan mode analyzes many findings in one process, so the closing line must be
// the total across all of them, not the last one's.
func TestScanUsageAccumulates(t *testing.T) {
	var total, review SessionUsage
	// Three findings, each an analysis plus a review.
	for i := 0; i < 3; i++ {
		total.Requests += 5
		total.ToolCalls += 9
		total.PromptTokens += 20000
		total.Tokens += 8000
		review.Requests += 2
		review.ToolCalls += 3
		review.PromptTokens += 6000
		review.Tokens += 3000
	}
	got := formatUsage(total, review)
	for _, want := range []string{
		"LLM requests: 21", // (5+2) x 3
		"tool calls: 36",   // (9+3) x 3
		"~78000 sent",      // (20000+6000) x 3
		"33000 in context", // (8000+3000) x 3
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testFindings() []Finding {
	return []Finding{
		{ID: "CVE-2024-0001", Package: "libfoo", Version: "1.0.0", Severity: "critical"},
		{ID: "CVE-2024-0002", Package: "libbar", Version: "2.0.0", Severity: "high"},
		{ID: "CVE-2024-0003", Package: "libbaz", Version: "3.0.0", Severity: "low"},
	}
}

func TestRunScanHappyPath(t *testing.T) {
	dir := t.TempDir()
	var analyzed []string
	deps := ScanDeps{
		RunDir: dir,
		Analyze: func(ctx context.Context, f Finding, description string) (string, error) {
			analyzed = append(analyzed, f.ID)
			return "```json\n" + fmt.Sprintf(
				`{"cve": %q, "reachable": "no", "confidence": "high", "rationale": "r"}`, f.ID,
			) + "\n```", nil
		},
		Render: func(ctx context.Context, description, verdictJSON string) (string, error) {
			return "# report", nil
		},
	}

	results := RunScan(context.Background(), deps, testFindings())
	if len(results) != 3 {
		t.Fatalf("results = %d", len(results))
	}
	if len(analyzed) != 3 {
		t.Fatalf("analyzed = %v", analyzed)
	}
	for _, r := range results {
		if r.Err != nil {
			t.Fatalf("%s: %v", r.Finding.ID, r.Err)
		}
		if r.Verdict == nil {
			t.Fatalf("%s: fenced verdict not parsed; raw=%q", r.Finding.ID, r.Raw)
		}
		if r.Verdict.Reachable != "no" {
			t.Errorf("%s: reachable = %s", r.Finding.ID, r.Verdict.Reachable)
		}
		if r.Report != "# report" {
			t.Errorf("%s: report = %q", r.Finding.ID, r.Report)
		}
	}

	// Per-finding artifacts on disk.
	entries, err := os.ReadDir(filepath.Join(dir, "findings"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("finding dirs = %d", len(entries))
	}
	for _, e := range entries {
		for _, want := range []string{"verdict.json", "finding.json", "report.md"} {
			if _, err := os.Stat(filepath.Join(dir, "findings", e.Name(), want)); err != nil {
				t.Errorf("%s/%s missing: %v", e.Name(), want, err)
			}
		}
	}
}

func TestRunScanContinuesAfterError(t *testing.T) {
	deps := ScanDeps{
		RunDir: t.TempDir(),
		Analyze: func(ctx context.Context, f Finding, description string) (string, error) {
			if f.ID == "CVE-2024-0002" {
				return "", errors.New("session exploded")
			}
			return `{"reachable": "yes", "confidence": "medium", "rationale": "r"}`, nil
		},
	}

	results := RunScan(context.Background(), deps, testFindings())
	if len(results) != 3 {
		t.Fatalf("results = %d, want 3 (loop must continue past errors)", len(results))
	}
	if results[0].Err != nil || results[2].Err != nil {
		t.Errorf("unexpected errors: %v / %v", results[0].Err, results[2].Err)
	}
	if results[1].Err == nil {
		t.Error("finding 2 should carry its error")
	}

	counts := CountResults(results)
	if counts.Reachable != 2 || counts.Errors != 1 {
		t.Errorf("counts = %+v", counts)
	}
}

func TestRunScanCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	deps := ScanDeps{
		RunDir: t.TempDir(),
		Analyze: func(ctx context.Context, f Finding, description string) (string, error) {
			t.Fatal("analyze must not run on a cancelled context")
			return "", nil
		},
	}
	results := RunScan(ctx, deps, testFindings())
	for _, r := range results {
		if r.Err == nil {
			t.Errorf("%s: expected context error", r.Finding.ID)
		}
	}
}

func TestExtractVerdictJSON(t *testing.T) {
	want := `{"reachable": "no"}`
	cases := map[string]string{
		"clean":        `{"reachable": "no"}`,
		"fenced":       "```json\n{\"reachable\": \"no\"}\n```",
		"plain fence":  "```\n{\"reachable\": \"no\"}\n```",
		"prose prefix": "Here is my verdict:\n\n{\"reachable\": \"no\"}",
	}
	for name, in := range cases {
		got := extractVerdictJSON(in)
		var a, b any
		if err := json.Unmarshal([]byte(got), &a); err != nil {
			t.Errorf("%s: output not JSON: %q", name, got)
			continue
		}
		_ = json.Unmarshal([]byte(want), &b)
		if fmt.Sprint(a) != fmt.Sprint(b) {
			t.Errorf("%s: got %q", name, got)
		}
	}

	// Garbage passes through.
	if got := extractVerdictJSON("no json here"); got != "no json here" {
		t.Errorf("garbage: got %q", got)
	}
	if v := parseVerdict("no json here"); v != nil {
		t.Errorf("parseVerdict accepted garbage: %+v", v)
	}
	if v := parseVerdict(`{"confidence": "high"}`); v != nil {
		t.Errorf("parseVerdict accepted verdict without reachable: %+v", v)
	}
}

func TestWriteScanArtifacts(t *testing.T) {
	dir := t.TempDir()
	results := []FindingResult{
		{
			Finding: Finding{ID: "CVE-2024-0001", Package: "libfoo", Version: "1.0.0", Severity: "critical"},
			Raw:     `{"reachable": "yes", "confidence": "high", "rationale": "r"}`,
			Verdict: &verdict{Reachable: "yes", Confidence: "high"},
		},
		{
			Finding: Finding{ID: "CVE-2024-0002", Package: "libbar", Version: "2.0.0", Severity: "high"},
			Err:     errors.New("boom"),
		},
		{
			Finding: Finding{ID: "CVE-2024-0003", Package: "libbaz", Version: "3.0.0", Severity: "low"},
			Raw:     "unparseable output",
		},
	}

	verdictsPath, err := WriteScanArtifacts(dir, results)
	if err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(verdictsPath)
	if err != nil {
		t.Fatal(err)
	}
	var envelopes []verdictEnvelope
	if err := json.Unmarshal(data, &envelopes); err != nil {
		t.Fatalf("verdicts.json does not parse: %v", err)
	}
	if len(envelopes) != 3 {
		t.Fatalf("envelopes = %d", len(envelopes))
	}
	if envelopes[0].Error != "" || len(envelopes[0].Verdict) == 0 {
		t.Errorf("envelope 0 wrong: %+v", envelopes[0])
	}
	if envelopes[1].Error == "" {
		t.Error("envelope 1 must carry the error")
	}
	if envelopes[2].Raw == "" || len(envelopes[2].Verdict) != 0 {
		t.Errorf("envelope 2 must carry raw output only: %+v", envelopes[2])
	}

	summary, err := os.ReadFile(filepath.Join(dir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CVE-2024-0001", "| yes |", "| error |", "| unparsed |"} {
		if !strings.Contains(string(summary), want) {
			t.Errorf("summary lacks %q:\n%s", want, summary)
		}
	}
}

func TestWriteScanArtifactsEmpty(t *testing.T) {
	dir := t.TempDir()
	verdictsPath, err := WriteScanArtifacts(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(verdictsPath)
	if err != nil {
		t.Fatal(err)
	}
	// Must be a JSON array, never null.
	var envelopes []verdictEnvelope
	if err := json.Unmarshal(data, &envelopes); err != nil {
		t.Fatalf("verdicts.json: %v", err)
	}
	if strings.TrimSpace(string(data)) == "null" {
		t.Fatal("empty scan serialized as null")
	}
}

func TestFailOnTriggered(t *testing.T) {
	cases := []struct {
		policy string
		counts ScanCounts
		want   bool
	}{
		{"", ScanCounts{Reachable: 5}, false},
		{"reachable", ScanCounts{Reachable: 1}, true},
		{"reachable", ScanCounts{Uncertain: 3, Errors: 2}, false},
		{"uncertain", ScanCounts{Uncertain: 1}, true},
		{"uncertain", ScanCounts{Errors: 1}, true},
		{"uncertain", ScanCounts{Unparsed: 1}, true},
		{"uncertain", ScanCounts{NotReachable: 9}, false},
	}
	for _, c := range cases {
		if got := FailOnTriggered(c.policy, c.counts); got != c.want {
			t.Errorf("FailOnTriggered(%q, %+v) = %v, want %v", c.policy, c.counts, got, c.want)
		}
	}
}

func TestBuildFindingDescription(t *testing.T) {
	f := Finding{
		ID: "CVE-2024-0001", Aliases: []string{"GHSA-abcd"},
		Package: "libfoo", Version: "1.0.0", FixedVersion: "1.0.1",
		Severity: "critical", CVSSScore: 9.8, Ecosystem: "golang",
		Title: "RCE in libfoo", Description: "long text",
		URLs: []string{"https://example.com/adv"}, Target: "go.mod",
	}
	desc := BuildFindingDescription(f)
	for _, want := range []string{
		"CVE-2024-0001", "GHSA-abcd", "libfoo", "1.0.0", "golang",
		"critical", "9.8", "1.0.1", "go.mod", "RCE in libfoo",
		"long text", "https://example.com/adv",
	} {
		if !strings.Contains(desc, want) {
			t.Errorf("description lacks %q:\n%s", want, desc)
		}
	}

	// Oversized advisory text gets truncated.
	f.Description = strings.Repeat("x", maxPromptDescriptionLen+1000)
	desc = BuildFindingDescription(f)
	if len(desc) > maxPromptDescriptionLen+2000 {
		t.Errorf("description not truncated: %d bytes", len(desc))
	}
	if !strings.Contains(desc, "[description truncated]") {
		t.Error("truncation marker missing")
	}
}

func TestFindingDirName(t *testing.T) {
	f := Finding{ID: "CVE-2024-0001", Package: "golang.org/x/crypto"}
	got := findingDirName(0, f)
	if got != "001_CVE-2024-0001_crypto" {
		t.Errorf("findingDirName = %q", got)
	}

	// Hostile ids must not escape the findings dir.
	f = Finding{ID: "../../etc/passwd", Package: "a/b"}
	got = findingDirName(1, f)
	if strings.Contains(got, "/") || strings.Contains(got, "..") {
		t.Errorf("unsafe dir name %q", got)
	}
}

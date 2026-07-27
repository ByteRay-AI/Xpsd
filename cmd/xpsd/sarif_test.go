// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

const utf8RuneError = '�'

func sampleResults() []FindingResult {
	yes := &verdict{
		Reachable:  "yes",
		Confidence: "high",
		Rationale:  "external input reaches the sink",
		CallPath:   []string{"handler (a.go:10)", "parse (b.go:20)", "sink (c.go:30)"},
		Evidence: []evidenceEntry{
			{File: "/src/pkg/c.go", Line: 30, Note: "vulnerable sink"},
			{File: "/src/pkg/a.go", Line: 10, Note: "entry point"},
		},
	}
	no := &verdict{
		Reachable:  "no",
		Confidence: "medium",
		Rationale:  "package never imported",
	}
	uncertain := &verdict{
		Reachable:  "uncertain",
		Confidence: "low",
		Rationale:  "component could not be retrieved",
	}
	return []FindingResult{
		{
			Finding: Finding{ID: "CVE-2024-0001", Package: "libfoo", Version: "1.0.0",
				Severity: "critical", CVSSScore: 9.8, Title: "RCE in libfoo",
				Description: "remote code execution", FixedVersion: "1.0.1",
				URLs: []string{"https://example.com/advisory"}},
			Raw: "{}", Verdict: yes,
		},
		{
			Finding: Finding{ID: "CVE-2024-0002", Package: "libbar", Version: "2.0.0",
				Severity: "high", CVSSScore: 8.1, Target: "go.mod"},
			Raw: "{}", Verdict: no,
		},
		{
			Finding: Finding{ID: "CVE-2024-0003", Package: "libbaz", Version: "3.0.0",
				Severity: "unknown"},
			Raw: "{}", Verdict: uncertain,
		},
		{
			Finding: Finding{ID: "CVE-2024-0004", Package: "libqux", Version: "4.0.0",
				Severity: "medium", CVSSScore: 5.5},
			Err: errors.New("session timed out"),
		},
		{
			// Same vulnerability as the first, different package: same rule.
			Finding: Finding{ID: "CVE-2024-0001", Package: "libfoo-fork", Version: "1.0.0",
				Severity: "critical", CVSSScore: 9.8},
			Raw: "not json", Verdict: nil,
		},
	}
}

func decodeSARIF(t *testing.T, data []byte) sarifLog {
	t.Helper()
	var doc sarifLog
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("SARIF does not parse: %v", err)
	}
	return doc
}

// tempSrcDir creates a fake source root containing a go.mod.
func tempSrcDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBuildScanSARIF(t *testing.T) {
	srcDir := tempSrcDir(t)
	data, err := BuildScanSARIF(sampleResults(), srcDir, "")
	if err != nil {
		t.Fatal(err)
	}
	doc := decodeSARIF(t, data)

	if doc.Version != "2.1.0" {
		t.Errorf("version = %s", doc.Version)
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(doc.Runs))
	}
	run := doc.Runs[0]
	if run.Tool.Driver.Name != "xpsd" {
		t.Errorf("driver name = %s", run.Tool.Driver.Name)
	}

	// 5 results, but only 4 rules (CVE-2024-0001 deduped).
	if len(run.Results) != 5 {
		t.Fatalf("results = %d, want 5", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 4 {
		t.Fatalf("rules = %d, want 4 (dedup failed)", len(run.Tool.Driver.Rules))
	}

	// ruleIndex must point at the rule with the matching id.
	for _, res := range run.Results {
		if res.RuleIndex < 0 || res.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Fatalf("result %s: ruleIndex %d out of range", res.RuleID, res.RuleIndex)
		}
		if rid := run.Tool.Driver.Rules[res.RuleIndex].ID; rid != res.RuleID {
			t.Errorf("result %s: ruleIndex points at rule %s", res.RuleID, rid)
		}
	}

	// Verdict → level mapping.
	wantLevels := []string{"error", "note", "warning", "warning", "warning"}
	for i, want := range wantLevels {
		if run.Results[i].Level != want {
			t.Errorf("result %d level = %s, want %s", i, run.Results[i].Level, want)
		}
	}

	// Evidence paths rooted at /src must become repo-relative.
	loc := run.Results[0].Locations[0]
	if loc.PhysicalLocation.ArtifactLocation.URI != "pkg/c.go" {
		t.Errorf("evidence URI = %q, want pkg/c.go", loc.PhysicalLocation.ArtifactLocation.URI)
	}
	if loc.PhysicalLocation.Region == nil || loc.PhysicalLocation.Region.StartLine != 30 {
		t.Errorf("evidence region wrong: %+v", loc.PhysicalLocation.Region)
	}

	// A result without evidence anchors to the scanner target (which exists
	// in the source dir).
	if uri := run.Results[1].Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "go.mod" {
		t.Errorf("fallback URI = %q, want go.mod", uri)
	}
	// Without a target either, it anchors to the first manifest found.
	if uri := run.Results[2].Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "go.mod" {
		t.Errorf("manifest fallback URI = %q, want go.mod", uri)
	}
	// Every location must carry a region with startLine >= 1 (GitHub
	// requires it).
	for i, res := range run.Results {
		for j, loc := range res.Locations {
			r := loc.PhysicalLocation.Region
			if r == nil || r.StartLine < 1 {
				t.Errorf("result %d location %d: missing startLine", i, j)
			}
		}
	}

	// Fingerprints are present and stable per finding key.
	seen := map[string]string{}
	for _, res := range run.Results {
		fp := res.PartialFingerprints["xpsdFindingKey/v1"]
		if fp == "" {
			t.Fatalf("result %s: missing fingerprint", res.RuleID)
		}
		seen[fp] = res.RuleID
	}
	if len(seen) != 5 {
		t.Errorf("fingerprints not unique per finding: %d distinct", len(seen))
	}

	// security-severity must reflect the CVSS score.
	rule := run.Tool.Driver.Rules[0]
	if rule.Properties == nil || rule.Properties.SecuritySeverity != "9.8" {
		t.Errorf("security-severity = %+v, want 9.8", rule.Properties)
	}

	// The failed analysis must say so.
	if !strings.Contains(run.Results[3].Message.Text, "could not analyze") {
		t.Errorf("error result message = %q", run.Results[3].Message.Text)
	}
	if !strings.Contains(run.Results[4].Message.Text, "unparseable") {
		t.Errorf("unparsed result message = %q", run.Results[4].Message.Text)
	}

	// Message contains the call path.
	if !strings.Contains(run.Results[0].Message.Text, "Call path:") {
		t.Errorf("reachable message lacks call path: %q", run.Results[0].Message.Text)
	}
}

func TestVerdictToSARIF(t *testing.T) {
	verdictJSON := `{
		"cve": "CVE-2024-45337",
		"reachable": "no",
		"confidence": "high",
		"detected_version": "v0.3.4",
		"version_applicable": true,
		"vulnerable_code_present": false,
		"affected_component": "golang.org/x/crypto/ssh",
		"evidence": [{"file": "/src/go.mod", "line": 12, "note": "pins x/crypto v0.17.0"}],
		"call_path": [],
		"rationale": "the ssh subpackage is never imported"
	}`
	data, err := VerdictToSARIF(verdictJSON, tempSrcDir(t), "")
	if err != nil {
		t.Fatal(err)
	}
	doc := decodeSARIF(t, data)
	res := doc.Runs[0].Results[0]
	if res.RuleID != "CVE-2024-45337" {
		t.Errorf("ruleId = %s", res.RuleID)
	}
	if res.Level != "note" {
		t.Errorf("level = %s, want note", res.Level)
	}
	if uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI; uri != "go.mod" {
		t.Errorf("URI = %s, want go.mod", uri)
	}

	// Unparseable verdict output must still yield a SARIF file with an
	// "unreviewed" warning result.
	data, err = VerdictToSARIF("not json at all", tempSrcDir(t), "")
	if err != nil {
		t.Fatalf("unparseable verdict must still produce SARIF: %v", err)
	}
	doc = decodeSARIF(t, data)
	res = doc.Runs[0].Results[0]
	if res.Level != "warning" || !strings.Contains(res.Message.Text, "unparseable") {
		t.Errorf("unparseable verdict result = level %s, message %q", res.Level, res.Message.Text)
	}
}

func TestFallbackURI(t *testing.T) {
	srcDir := tempSrcDir(t)

	// Target exists → used as-is.
	if got := fallbackURI("go.mod", srcDir); got != "go.mod" {
		t.Errorf("existing target: got %q", got)
	}
	// Target does not exist → first manifest present in the repo.
	if got := fallbackURI("sbom.cdx.json", srcDir); got != "go.mod" {
		t.Errorf("missing target: got %q", got)
	}
	// Non-file targets (image names, descriptions) fall through too.
	if got := fallbackURI("alpine:3.18 (alpine 3.18.4)", srcDir); got != "go.mod" {
		t.Errorf("image target: got %q", got)
	}
	// Nothing in the repo at all → README.md as documented last resort.
	if got := fallbackURI("", t.TempDir()); got != "README.md" {
		t.Errorf("empty repo: got %q", got)
	}
}

func TestTruncateUTF8(t *testing.T) {
	s := strings.Repeat("a", 6) + "→→" // arrows are 3 bytes each
	got := truncateUTF8(s, 7)          // cuts inside the first arrow
	if got != strings.Repeat("a", 6) {
		t.Errorf("got %q", got)
	}
	if truncateUTF8("short", 100) != "short" {
		t.Error("short string modified")
	}
	for _, max := range []int{0, 1, 2, 3, 4} {
		out := truncateUTF8("→→", max)
		if len(out) > max {
			t.Errorf("max %d: output %d bytes", max, len(out))
		}
		for _, r := range out {
			if r == utf8RuneError {
				t.Errorf("max %d: invalid rune in %q", max, out)
			}
		}
	}
}

func TestRelativePath(t *testing.T) {
	cases := []struct {
		file, src, want string
	}{
		{"/src/pkg/a.go", "/host/proj", "pkg/a.go"},
		{"/src", "/host/proj", ""}, // "." is not a valid SARIF URI; caller falls back
		// Hostile evidence paths under /src must not escape into an invalid URI.
		{"/src/../../../etc/passwd", "/host/proj", ""},
		{"/src//etc/passwd", "/host/proj", ""},
		{"/src/../etc", "/host/proj", ""},
		{"/host/proj/pkg/a.go", "/host/proj", "pkg/a.go"},
		// Repo-relative paths pass through unchanged.
		{"internal/pkg/foo.go", "/host/proj", "internal/pkg/foo.go"},
		{"rel/c.go", "", "rel/c.go"},
		// Paths that cannot name a repo file: fall back.
		{"/elsewhere/b.go", "/host/proj", ""},
		{"/tool_output/deps/x/crypto/ssh/cipher.go", "/host/proj", ""},
		{`C:\src\foo.go`, "/host/proj", ""},
		{"../outside.go", "/host/proj", ""},
		{"", "/host/proj", ""},
		// URLs must not become a location URI.
		{"https://nvd.nist.gov/vuln/detail/CVE-2024-45337", "/host/proj", ""},
		{"http://example.com/x", "/host/proj", ""},
		{"/src/https://x", "/host/proj", ""},
	}
	for _, c := range cases {
		if got := relativePath(c.file, c.src); got != c.want {
			t.Errorf("relativePath(%q, %q) = %q, want %q", c.file, c.src, got, c.want)
		}
	}
}

// TestBuildLocationsFallsBack ensures evidence outside the repo is anchored to
// a real file instead of a bogus basename URI.
func TestBuildLocationsFallsBack(t *testing.T) {
	srcDir := tempSrcDir(t)
	r := FindingResult{
		Finding: Finding{ID: "CVE-2024-0001", Package: "x"},
		Verdict: &verdict{
			Reachable: "yes",
			Evidence: []evidenceEntry{
				{File: "/tool_output/deps/x/crypto/ssh/cipher.go", Line: 10, Note: "sink"},
			},
		},
	}
	locs := buildLocations(r, srcDir, "")
	if len(locs) != 1 {
		t.Fatalf("locations = %d", len(locs))
	}
	if uri := locs[0].PhysicalLocation.ArtifactLocation.URI; uri != "go.mod" {
		t.Errorf("URI = %q, want go.mod fallback", uri)
	}
}

// TestBuildScanSARIFURIPrefix checks that URIs carry the source subdirectory
// prefix when the analyzed source is not the checkout root.
func TestBuildScanSARIFURIPrefix(t *testing.T) {
	results := []FindingResult{{
		Finding: Finding{ID: "CVE-2024-0001", Package: "libfoo", Version: "1.0.0", Severity: "high"},
		Raw:     "{}",
		Verdict: &verdict{
			Reachable:  "yes",
			Confidence: "high",
			Evidence:   []evidenceEntry{{File: "/src/handler.go", Line: 5, Note: "sink"}},
		},
	}}
	data, err := BuildScanSARIF(results, tempSrcDir(t), "services/api")
	if err != nil {
		t.Fatal(err)
	}
	doc := decodeSARIF(t, data)
	uri := doc.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if uri != "services/api/handler.go" {
		t.Errorf("URI = %q, want services/api/handler.go", uri)
	}
}

// TestSARIFAgainstSchema validates generated SARIF against the official
// SARIF 2.1.0 JSON schema.
func TestSARIFAgainstSchema(t *testing.T) {
	schemaData, err := os.ReadFile("testdata/sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatalf("reading vendored schema: %v", err)
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(schemaData)))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("sarif-schema-2.1.0.json", schemaDoc); err != nil {
		t.Fatal(err)
	}
	schema, err := compiler.Compile("sarif-schema-2.1.0.json")
	if err != nil {
		t.Fatal(err)
	}

	validate := func(name string, data []byte) {
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := schema.Validate(doc); err != nil {
			t.Errorf("%s: SARIF fails schema validation: %v", name, err)
		}
	}

	data, err := BuildScanSARIF(sampleResults(), tempSrcDir(t), "")
	if err != nil {
		t.Fatal(err)
	}
	validate("scan-mode", data)

	// Empty scan: still a valid SARIF file.
	data, err = BuildScanSARIF(nil, tempSrcDir(t), "")
	if err != nil {
		t.Fatal(err)
	}
	validate("empty", data)
}

// GitHub reads security-severity from the rule, so a ruled-out critical must not
// keep a 9.8 and render as "Critical" in the Security tab.
func TestNotReachableDropsRuleSeverity(t *testing.T) {
	f := Finding{ID: "CVE-2024-0001", Package: "libfoo", Version: "1.0",
		Severity: "critical", CVSSScore: 9.8}

	cases := []struct {
		name      string
		reachable string
		wantSev   string
		wantLevel string
	}{
		{"reachable keeps its real score", "yes", "9.8", "error"},
		{"uncertain keeps its real score", "uncertain", "9.8", "warning"},
		{"not reachable drops to the low band", "no", notReachableSeverity, "note"},
	}
	for _, c := range cases {
		res := FindingResult{Finding: f, Verdict: &verdict{
			Reachable: c.reachable, Confidence: "high", CVE: f.ID}}
		data, err := BuildScanSARIF([]FindingResult{res}, "/src", "")
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var doc sarifLog
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		gotSev := doc.Runs[0].Tool.Driver.Rules[0].Properties.SecuritySeverity
		if gotSev != c.wantSev {
			t.Errorf("%s: security-severity = %q, want %q", c.name, gotSev, c.wantSev)
		}
		if got := doc.Runs[0].Results[0].Level; got != c.wantLevel {
			t.Errorf("%s: level = %q, want %q", c.name, got, c.wantLevel)
		}
	}
}

// The low band is 0.1 to 3.9; anything else and GitHub buckets it wrong.
func TestNotReachableSeverityIsInLowBand(t *testing.T) {
	var v float64
	if _, err := fmt.Sscanf(notReachableSeverity, "%f", &v); err != nil {
		t.Fatalf("not a number: %q", notReachableSeverity)
	}
	if v < 0.1 || v > 3.9 {
		t.Errorf("security-severity %v falls outside GitHub's low band (0.1-3.9)", v)
	}
}

// One rule can back several findings. A single reachable one must keep the whole
// rule at its real severity rather than being buried by ruled-out siblings.
func TestMixedResultsKeepRuleSeverity(t *testing.T) {
	id := "CVE-2024-0002"
	mk := func(pkg, reachable string) FindingResult {
		return FindingResult{
			Finding: Finding{ID: id, Package: pkg, Version: "1.0", CVSSScore: 8.1},
			Verdict: &verdict{Reachable: reachable, Confidence: "high", CVE: id},
		}
	}
	data, err := BuildScanSARIF([]FindingResult{mk("a", "no"), mk("b", "yes")}, "/src", "")
	if err != nil {
		t.Fatal(err)
	}
	var doc sarifLog
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Runs[0].Tool.Driver.Rules) != 1 {
		t.Fatalf("expected one shared rule, got %d", len(doc.Runs[0].Tool.Driver.Rules))
	}
	if got := doc.Runs[0].Tool.Driver.Rules[0].Properties.SecuritySeverity; got != "8.1" {
		t.Errorf("a reachable finding was downgraded by its siblings: %q", got)
	}
	// Each result still carries its own level.
	levels := []string{doc.Runs[0].Results[0].Level, doc.Runs[0].Results[1].Level}
	if levels[0] != "note" || levels[1] != "error" {
		t.Errorf("per-result levels = %v, want [note error]", levels)
	}
}

// An errored or unparseable analysis must never be downgraded: it is unreviewed.
func TestUnreviewedKeepsSeverity(t *testing.T) {
	f := Finding{ID: "CVE-2024-0003", CVSSScore: 9.1}
	for _, r := range []FindingResult{
		{Finding: f, Err: fmt.Errorf("boom")},
		{Finding: f, Raw: "not json"},
	} {
		data, err := BuildScanSARIF([]FindingResult{r}, "/src", "")
		if err != nil {
			t.Fatal(err)
		}
		var doc sarifLog
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		if got := doc.Runs[0].Tool.Driver.Rules[0].Properties.SecuritySeverity; got != "9.1" {
			t.Errorf("unreviewed finding downgraded to %q", got)
		}
	}
}

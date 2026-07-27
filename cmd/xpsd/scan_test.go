// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "scans", name))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return data
}

func TestDetectScanFormat(t *testing.T) {
	cases := []struct {
		fixture string
		want    string
	}{
		{"grype.json", FormatGrype},
		{"trivy.json", FormatTrivy},
		{"osv.json", FormatOSV},
		{"snyk.json", FormatSnyk},
		{"snyk-multi.json", FormatSnyk},
		{"grype.sarif", FormatSARIF},
		{"trivy.sarif", FormatSARIF},
	}
	for _, c := range cases {
		got, err := DetectScanFormat(readFixture(t, c.fixture))
		if err != nil {
			t.Errorf("DetectScanFormat(%s): %v", c.fixture, err)
			continue
		}
		if got != c.want {
			t.Errorf("DetectScanFormat(%s) = %s, want %s", c.fixture, got, c.want)
		}
	}
}

// TestDetectScanFormatCleanTrivy: a Trivy run that finds nothing omits the
// Results key entirely; autodetection must still recognize the report.
func TestDetectScanFormatCleanTrivy(t *testing.T) {
	doc := `{"SchemaVersion": 2, "CreatedAt": "2026-01-01T00:00:00Z",
		"ArtifactName": ".", "ArtifactType": "filesystem", "Metadata": {}}`
	got, err := DetectScanFormat([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if got != FormatTrivy {
		t.Fatalf("got %s, want trivy", got)
	}
	findings, _, err := ParseScan([]byte(doc), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("clean report produced %d findings", len(findings))
	}
}

func TestDetectScanFormatRejects(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":       "hello",
		"empty object":   "{}",
		"foreign object": `{"foo": 1, "bar": 2}`,
		"foreign array":  `[{"foo": 1}]`,
	} {
		if got, err := DetectScanFormat([]byte(doc)); err == nil {
			t.Errorf("%s: detected as %s, want error", name, got)
		}
	}
}

// checkFindingInvariants asserts properties every parsed finding must satisfy
// regardless of scanner.
func checkFindingInvariants(t *testing.T, findings []Finding, minCount int) {
	t.Helper()
	if len(findings) < minCount {
		t.Fatalf("got %d findings, want at least %d", len(findings), minCount)
	}
	for i, f := range findings {
		if f.ID == "" {
			t.Errorf("finding %d: empty ID", i)
		}
		if f.Package == "" {
			t.Errorf("finding %d (%s): empty package", i, f.ID)
		}
		if _, ok := severityRank[f.Severity]; !ok {
			t.Errorf("finding %d (%s): severity %q not normalized", i, f.ID, f.Severity)
		}
		if f.CVSSScore < 0 || f.CVSSScore > 10 {
			t.Errorf("finding %d (%s): CVSS score %f out of range", i, f.ID, f.CVSSScore)
		}
	}
}

func TestParseGrypeFixture(t *testing.T) {
	findings, format, err := ParseScan(readFixture(t, "grype.json"), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if format != FormatGrype {
		t.Fatalf("detected %s, want grype", format)
	}
	checkFindingInvariants(t, findings, 6)
	for i, f := range findings {
		if f.Version == "" {
			t.Errorf("finding %d (%s): empty version", i, f.ID)
		}
	}

	// Grype reports GHSA as primary id with the CVE in
	// relatedVulnerabilities; canonicalization must surface the CVE.
	f := findByID(t, findings, "CVE-2024-45337")
	if f.Package != "golang.org/x/crypto" || f.Version != "v0.17.0" {
		t.Errorf("got %s@%s", f.Package, f.Version)
	}
	if !contains(f.Aliases, "GHSA-v778-237x-gjrc") {
		t.Errorf("GHSA alias missing: %v", f.Aliases)
	}
	if f.Severity != "critical" || f.CVSSScore != 9.1 {
		t.Errorf("severity=%s cvss=%.1f", f.Severity, f.CVSSScore)
	}
	if f.FixedVersion != "0.31.0" {
		t.Errorf("fixed = %q", f.FixedVersion)
	}
}

func findByID(t *testing.T, findings []Finding, id string) Finding {
	t.Helper()
	for _, f := range findings {
		if f.ID == id {
			return f
		}
	}
	t.Fatalf("%s not found in %v", id, ids(findings))
	return Finding{}
}

func TestParseTrivyFixture(t *testing.T) {
	findings, format, err := ParseScan(readFixture(t, "trivy.json"), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if format != FormatTrivy {
		t.Fatalf("detected %s, want trivy", format)
	}
	checkFindingInvariants(t, findings, 7)
	for i, f := range findings {
		if f.Version == "" {
			t.Errorf("finding %d (%s): empty version", i, f.ID)
		}
	}

	f := findByID(t, findings, "CVE-2021-44228")
	if f.Package != "org.apache.logging.log4j:log4j-core" || f.Version != "2.14.1" {
		t.Errorf("got %s@%s", f.Package, f.Version)
	}
	if f.Severity != "critical" || f.CVSSScore != 10.0 {
		t.Errorf("severity=%s cvss=%.1f", f.Severity, f.CVSSScore)
	}
	if f.FixedVersion != "2.15.0" {
		t.Errorf("fixed = %q", f.FixedVersion)
	}
	if f.Target != "app/lib/log4j-core-2.14.1.jar" {
		t.Errorf("target = %q", f.Target)
	}

	// The Trivy SARIF flavor must yield the same finding identity, with
	// package and version recovered from the message conventions.
	sarifFindings, _, err := ParseScan(readFixture(t, "trivy.sarif"), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	sf := findByID(t, sarifFindings, "CVE-2021-44228")
	if sf.Package != f.Package || sf.Version != f.Version {
		t.Errorf("sarif flavor: got %s@%s, want %s@%s", sf.Package, sf.Version, f.Package, f.Version)
	}
}

func TestParseOSVFixture(t *testing.T) {
	findings, format, err := ParseScan(readFixture(t, "osv.json"), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if format != FormatOSV {
		t.Fatalf("detected %s, want osv", format)
	}
	checkFindingInvariants(t, findings, 5)
	for i, f := range findings {
		if f.Version == "" {
			t.Errorf("finding %d (%s): empty version", i, f.ID)
		}
	}

	// OSV primary id is a GHSA; the CVE alias must become canonical, the
	// CVSS score must come from groups[].max_severity, and the fixed version
	// from the affected ranges.
	f := findByID(t, findings, "CVE-2021-44228")
	if f.Package != "org.apache.logging.log4j:log4j-core" || f.Version != "2.14.1" {
		t.Errorf("got %s@%s", f.Package, f.Version)
	}
	if !contains(f.Aliases, "GHSA-jfh8-c2jp-5v3q") {
		t.Errorf("GHSA alias missing: %v", f.Aliases)
	}
	if f.CVSSScore != 10.0 {
		t.Errorf("cvss = %.1f, want 10.0 (from groups.max_severity)", f.CVSSScore)
	}
	if f.Severity != "critical" {
		t.Errorf("severity = %s", f.Severity)
	}
	if f.FixedVersion != "2.15.0" {
		t.Errorf("fixed = %q", f.FixedVersion)
	}
	if f.Ecosystem != "Maven" {
		t.Errorf("ecosystem = %s", f.Ecosystem)
	}
}

func TestParseSARIFFixtures(t *testing.T) {
	for _, fixture := range []string{"grype.sarif", "trivy.sarif"} {
		findings, format, err := ParseScan(readFixture(t, fixture), FormatAuto)
		if err != nil {
			t.Fatalf("%s: %v", fixture, err)
		}
		if format != FormatSARIF {
			t.Fatalf("%s: detected %s, want sarif", fixture, format)
		}
		if len(findings) < 3 {
			t.Fatalf("%s: got %d findings, want at least 3", fixture, len(findings))
		}
		for i, f := range findings {
			if f.ID == "" {
				t.Errorf("%s finding %d: empty ID", fixture, i)
			}
			// Decorated rule ids ("GHSA-...-lodash") must be reduced to the
			// bare vulnerability id.
			if !strings.HasPrefix(f.ID, "CVE-") && !strings.HasPrefix(f.ID, "GHSA-") {
				t.Errorf("%s finding %d: id %q not canonicalized", fixture, i, f.ID)
			}
			if strings.HasPrefix(f.ID, "GHSA-") && len(f.ID) != len("GHSA-xxxx-xxxx-xxxx") {
				t.Errorf("%s finding %d: GHSA id %q still decorated", fixture, i, f.ID)
			}
			if f.Description == "" && f.Title == "" {
				t.Errorf("%s finding %d (%s): no description at all", fixture, i, f.ID)
			}
			if f.Severity == "unknown" {
				t.Errorf("%s finding %d (%s): severity not derived", fixture, i, f.ID)
			}
		}
	}
}

// TestParseSARIFProseCVENotPromoted: a CVE mentioned in a rule's description
// prose ("the fix for CVE-X was incomplete") must never become the finding's
// canonical id.
func TestParseSARIFProseCVENotPromoted(t *testing.T) {
	doc := `{
	  "version": "2.1.0",
	  "runs": [{
	    "tool": {"driver": {"name": "osv-scanner", "rules": [
	      {"id": "GHSA-7rjr-3q55-vv33", "shortDescription": {"text": "log4j RCE"},
	       "fullDescription": {"text": "The fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete."}},
	      {"id": "CVE-2021-44228", "shortDescription": {"text": "log4shell"},
	       "fullDescription": {"text": "JNDI features do not protect against attacker controlled LDAP."}}
	    ]}},
	    "results": [
	      {"ruleId": "GHSA-7rjr-3q55-vv33", "level": "error",
	       "message": {"text": "Package: log4j-core"}, "locations": []},
	      {"ruleId": "CVE-2021-44228", "level": "error",
	       "message": {"text": "Package: log4j-core"}, "locations": []}
	    ]
	  }]
	}`
	findings, err := parseSARIF([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("findings = %d, want 2", len(findings))
	}
	if findings[0].ID != "GHSA-7rjr-3q55-vv33" {
		t.Errorf("prose CVE promoted: finding 0 id = %s", findings[0].ID)
	}
	kept, _, err := FilterFindings(findings, "", 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 {
		t.Fatalf("dedup collapsed distinct vulnerabilities: kept %v", ids(kept))
	}
}

// TestParseOSVMultiRangeFixed: with fix events across several release
// branches, all of them must be reported, not just the oldest backport.
func TestParseOSVMultiRangeFixed(t *testing.T) {
	doc := `{"results": [{"source": {"path": "pom.xml"}, "packages": [{
	  "package": {"name": "org.apache.logging.log4j:log4j-core", "version": "2.14.1", "ecosystem": "Maven"},
	  "vulnerabilities": [{
	    "id": "GHSA-jfh8-c2jp-5v3q",
	    "aliases": ["CVE-2021-44228"],
	    "affected": [{
	      "package": {"name": "org.apache.logging.log4j:log4j-core"},
	      "ranges": [{"type": "ECOSYSTEM", "events": [
	        {"introduced": "2.0-beta9"}, {"fixed": "2.3.1"},
	        {"introduced": "2.4"}, {"fixed": "2.12.2"},
	        {"introduced": "2.13.0"}, {"fixed": "2.15.0"}
	      ]}]
	    }]
	  }],
	  "groups": [{"ids": ["GHSA-jfh8-c2jp-5v3q"], "max_severity": "10.0"}]
	}]}]}`
	findings, err := parseOSV([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 {
		t.Fatalf("findings = %d", len(findings))
	}
	if got := findings[0].FixedVersion; got != "2.3.1, 2.12.2, 2.15.0" {
		t.Errorf("fixed = %q, want all branch fixes", got)
	}
}

func TestParseSnykFixture(t *testing.T) {
	findings, format, err := ParseScan(readFixture(t, "snyk.json"), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if format != FormatSnyk {
		t.Fatalf("detected %s, want snyk", format)
	}
	checkFindingInvariants(t, findings, 6)

	// The SNYK id must be swapped for its CVE alias.
	var lodash *Finding
	for i := range findings {
		if findings[i].ID == "CVE-2020-8203" {
			lodash = &findings[i]
		}
	}
	if lodash == nil {
		t.Fatal("CVE-2020-8203 not found; id canonicalization to CVE failed")
	}
	if lodash.Package != "lodash" || lodash.Version != "4.17.15" {
		t.Errorf("lodash finding: got %s@%s", lodash.Package, lodash.Version)
	}
	if !contains(lodash.Aliases, "SNYK-JS-LODASH-567746") {
		t.Errorf("SNYK id not kept as alias: %v", lodash.Aliases)
	}
	if lodash.Severity != "high" {
		t.Errorf("severity = %s, want high", lodash.Severity)
	}
	if lodash.CVSSScore != 7.4 {
		t.Errorf("cvss = %.1f, want 7.4", lodash.CVSSScore)
	}
	if lodash.FixedVersion == "" {
		t.Error("fixed version missing")
	}
	if !strings.Contains(lodash.Description, "Dependency path:") {
		t.Error("dependency path not embedded in description")
	}
	if lodash.Ecosystem != "npm" {
		t.Errorf("ecosystem = %s, want npm", lodash.Ecosystem)
	}
}

func TestParseSnykMultiProject(t *testing.T) {
	findings, format, err := ParseScan(readFixture(t, "snyk-multi.json"), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if format != FormatSnyk {
		t.Fatalf("detected %s, want snyk", format)
	}
	checkFindingInvariants(t, findings, 5)
}

func TestCanonicalizeID(t *testing.T) {
	cases := []struct {
		primary     string
		aliases     []string
		wantID      string
		wantAliases []string
	}{
		{"CVE-2024-1234", []string{"GHSA-xxxx"}, "CVE-2024-1234", []string{"GHSA-xxxx"}},
		{"GHSA-xxxx", []string{"CVE-2024-1234"}, "CVE-2024-1234", []string{"GHSA-xxxx"}},
		{"GHSA-xxxx", nil, "GHSA-xxxx", nil},
		{"GHSA-xxxx", []string{"SNYK-1", "CVE-2024-1234", "CVE-2024-9999"}, "CVE-2024-1234", []string{"GHSA-xxxx", "SNYK-1", "CVE-2024-9999"}},
		{"CVE-2024-1234", []string{"CVE-2024-1234"}, "CVE-2024-1234", nil},
	}
	for _, c := range cases {
		id, aliases := canonicalizeID(c.primary, c.aliases)
		if id != c.wantID {
			t.Errorf("canonicalizeID(%q, %v) id = %q, want %q", c.primary, c.aliases, id, c.wantID)
		}
		if !equalStrings(aliases, c.wantAliases) {
			t.Errorf("canonicalizeID(%q, %v) aliases = %v, want %v", c.primary, c.aliases, aliases, c.wantAliases)
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"CRITICAL": "critical", "Critical": "critical",
		"HIGH": "high", "important": "high",
		"Moderate": "medium", "MEDIUM": "medium",
		"low": "low", "informational": "low",
		"Negligible":  "negligible",
		"":            "unknown",
		"weird-value": "unknown",
	}
	for in, want := range cases {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFilterFindings(t *testing.T) {
	in := []Finding{
		{ID: "CVE-1", Package: "a", Version: "1", Severity: "low", CVSSScore: 2},
		{ID: "CVE-2", Package: "b", Version: "1", Severity: "critical", CVSSScore: 9.8},
		{ID: "CVE-2", Package: "b", Version: "1", Severity: "critical", CVSSScore: 9.8}, // dup
		{ID: "CVE-3", Package: "c", Version: "1", Severity: "high", CVSSScore: 8.1},
		{ID: "", Package: "d", Version: "1", Severity: "high"}, // no id
		{ID: "CVE-4", Package: "e", Version: "1", Severity: "unknown"},
	}

	kept, skipped, err := FilterFindings(in, "", 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 4 || skipped != 2 {
		t.Fatalf("got %d kept %d skipped, want 4/2", len(kept), skipped)
	}
	// Deterministic order: severity desc.
	wantOrder := []string{"CVE-2", "CVE-3", "CVE-1", "CVE-4"}
	for i, w := range wantOrder {
		if kept[i].ID != w {
			t.Fatalf("order[%d] = %s, want %s (full: %v)", i, kept[i].ID, w, ids(kept))
		}
	}

	// The severity floor drops low-severity findings but NOT unknown-severity
	// ones.
	kept, skipped, err = FilterFindings(in, "high", 0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 3 || kept[0].ID != "CVE-2" || kept[1].ID != "CVE-3" || kept[2].ID != "CVE-4" {
		t.Fatalf("min-severity high: got %v (skipped %d)", ids(kept), skipped)
	}

	kept, _, err = FilterFindings(in, "", 0, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || kept[0].ID != "CVE-2" {
		t.Fatalf("max-findings 1: got %v", ids(kept))
	}

	if _, _, err := FilterFindings(in, "bogus", 0, 0, nil); err == nil {
		t.Fatal("invalid min-severity accepted")
	}

	// -min-cvss drops findings with a known score below the threshold, but
	// keeps the unscored one (CVE-4, score 0).
	kept, _, err = FilterFindings(in, "", 8.5, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 || kept[0].ID != "CVE-2" || kept[1].ID != "CVE-4" {
		t.Fatalf("min-cvss 8.5: got %v", ids(kept))
	}

	// min-cvss combines with min-severity.
	kept, _, err = FilterFindings(in, "high", 9.0, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 || kept[0].ID != "CVE-2" || kept[1].ID != "CVE-4" {
		t.Fatalf("min-severity high + min-cvss 9.0: got %v", ids(kept))
	}

	if _, _, err := FilterFindings(in, "", 11, 0, nil); err == nil {
		t.Fatal("out-of-range min-cvss accepted")
	}
}

func TestFilterFindingsOnlyIDs(t *testing.T) {
	in := []Finding{
		{ID: "CVE-1", Aliases: []string{"GHSA-aaaa"}, Package: "a", Version: "1", Severity: "low"},
		{ID: "CVE-2", Package: "b", Version: "1", Severity: "critical"},
		{ID: "CVE-3", Package: "c", Version: "1", Severity: "high"},
	}

	// Match by canonical id (case-insensitive).
	kept, _, err := FilterFindings(in, "", 0, 0, []string{"cve-2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || kept[0].ID != "CVE-2" {
		t.Fatalf("only cve-2: got %v", ids(kept))
	}

	// Match by alias.
	kept, _, err = FilterFindings(in, "", 0, 0, []string{"GHSA-aaaa"})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || kept[0].ID != "CVE-1" {
		t.Fatalf("only alias: got %v", ids(kept))
	}

	// Multiple ids, with whitespace as -only "a, b" would produce.
	kept, _, err = FilterFindings(in, "", 0, 0, []string{" CVE-1", "CVE-3 "})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 2 {
		t.Fatalf("only two ids: got %v", ids(kept))
	}

	// -only combines with -min-severity.
	kept, _, err = FilterFindings(in, "high", 0, 0, []string{"CVE-1", "CVE-3"})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 1 || kept[0].ID != "CVE-3" {
		t.Fatalf("only + min-severity: got %v", ids(kept))
	}

	// Unknown id matches nothing.
	kept, _, err = FilterFindings(in, "", 0, 0, []string{"CVE-9999"})
	if err != nil {
		t.Fatal(err)
	}
	if len(kept) != 0 {
		t.Fatalf("unknown id: got %v", ids(kept))
	}
}

func ids(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBuildUserMessageGuidance(t *testing.T) {
	const g = "The daemon is never network-exposed."

	msg := buildUserMessage("CVE-2024-0001 in libfoo", g, "")
	if !strings.Contains(msg, g) {
		t.Errorf("guidance text missing:\n%s", msg)
	}
	if !strings.Contains(msg, "Authoritative project guidance") {
		t.Errorf("guidance heading missing:\n%s", msg)
	}
	if !strings.Contains(msg, "CVE-2024-0001 in libfoo") {
		t.Error("cve description missing")
	}

	// No guidance: no heading, and the CVE section still renders.
	msg = buildUserMessage("CVE-2024-0001 in libfoo", "   ", "")
	if strings.Contains(msg, "Authoritative project guidance") {
		t.Errorf("guidance heading present for empty guidance:\n%s", msg)
	}
	if !strings.Contains(msg, "## CVE / Vulnerability description") {
		t.Error("cve heading missing")
	}
}

// TestParsersCaptureCVSSVector: the -is-remote gate needs the vector, so the
// parsers must keep it, not just the score.
func TestParsersCaptureCVSSVector(t *testing.T) {
	for _, c := range []struct{ fixture, id string }{
		{"grype.json", "CVE-2024-45337"},
		{"trivy.json", "CVE-2021-44228"},
		{"osv.json", "CVE-2021-44228"},
		{"snyk.json", "CVE-2020-8203"},
	} {
		findings, _, err := ParseScan(readFixture(t, c.fixture), FormatAuto)
		if err != nil {
			t.Fatalf("%s: %v", c.fixture, err)
		}
		f := findByID(t, findings, c.id)
		if f.CVSSVector == "" {
			t.Errorf("%s: %s has no CVSS vector", c.fixture, c.id)
			continue
		}
		if _, ok := IsRemote(f.CVSSVector); !ok {
			t.Errorf("%s: %s vector %q has no AV field", c.fixture, c.id, f.CVSSVector)
		}
	}
}

func TestDedupFindings(t *testing.T) {
	in := []Finding{
		{ID: "CVE-1", Package: "a", Version: "1"},
		{ID: "CVE-1", Package: "a", Version: "1"}, // exact dup
		{ID: "CVE-1", Package: "a", Version: "2"}, // different version, kept
		{ID: "", Package: "b", Version: "1"},      // no id, dropped
	}
	kept, removed := DedupFindings(in)
	if len(kept) != 2 || removed != 2 {
		t.Fatalf("kept %v removed %d, want 2/2", ids(kept), removed)
	}
}

func TestRankAndCap(t *testing.T) {
	in := []Finding{
		{ID: "CVE-low", Severity: "low", CVSSScore: 2},
		{ID: "CVE-crit", Severity: "critical", CVSSScore: 9.8},
		{ID: "CVE-high", Severity: "high", CVSSScore: 8.1},
	}
	kept, dropped := RankAndCap(in, 0)
	if dropped != 0 || kept[0].ID != "CVE-crit" || kept[2].ID != "CVE-low" {
		t.Fatalf("no cap: %v dropped %d", ids(kept), dropped)
	}
	// Input order must not change.
	if in[0].ID != "CVE-low" {
		t.Error("RankAndCap mutated its input slice")
	}
	kept, dropped = RankAndCap(in, 2)
	if len(kept) != 2 || dropped != 1 || kept[0].ID != "CVE-crit" {
		t.Fatalf("cap 2: %v dropped %d", ids(kept), dropped)
	}
}

// TestPipelineOrderSpendsNoWastedSession: the severity floor must decide on
// enriched data, so a finding that enrichment scores below the floor never
// reaches analysis.
func TestPipelineOrderSpendsNoWastedSession(t *testing.T) {
	// Unscored on arrival, as a bare SARIF report would be.
	in := []Finding{
		{ID: "CVE-crit", Package: "a", Version: "1", Severity: "unknown"},
		{ID: "CVE-mid", Package: "b", Version: "1", Severity: "unknown"},
	}
	deduped, _ := DedupFindings(in)

	// Stand in for enrichment.
	deduped[0].Severity, deduped[0].CVSSScore = "critical", 9.8
	deduped[1].Severity, deduped[1].CVSSScore = "medium", 5.5

	selected, skipped, err := SelectFindings(deduped, "high", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(selected) != 1 || selected[0].ID != "CVE-crit" || skipped != 1 {
		t.Fatalf("selected %v skipped %d, want just CVE-crit", ids(selected), skipped)
	}
}

// TestGrypeScoreVectorPaired: grype carries a vendor CVSS on the match and NVD's
// on the related CVE. The stored vector must belong to the stored score.
func TestGrypeScoreVectorPaired(t *testing.T) {
	doc := `{"descriptor":{"name":"grype"},"matches":[{
	  "vulnerability":{"id":"CVE-2022-1271","severity":"Medium",
	    "cvss":[{"metrics":{"baseScore":6.5},"vector":"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"}]},
	  "relatedVulnerabilities":[{"id":"CVE-2022-1271",
	    "cvss":[{"metrics":{"baseScore":8.8},"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"}]}],
	  "artifact":{"name":"gzip","version":"1.10"}}]}`
	findings, err := parseGrype([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	f := findings[0]
	if f.CVSSScore != 8.8 {
		t.Errorf("score = %.1f, want 8.8", f.CVSSScore)
	}
	if remote, _ := IsRemote(f.CVSSVector); !remote {
		t.Errorf("vector %q does not match the 8.8 NVD entry", f.CVSSVector)
	}
}

// TestGrypeVectorlessWinnerLeavesVectorEmpty: when the winning entry has no
// vector, none is invented, so enrichment can supply a matching one.
func TestGrypeVectorlessWinnerLeavesVectorEmpty(t *testing.T) {
	doc := `{"descriptor":{"name":"grype"},"matches":[{
	  "vulnerability":{"id":"CVE-2024-0001","severity":"High",
	    "cvss":[{"metrics":{"baseScore":4.0},"vector":"AV:L/AC:L/Au:N/C:P/I:P/A:P"},
	            {"metrics":{"baseScore":9.1},"vector":""}]},
	  "artifact":{"name":"x","version":"1"}}]}`
	findings, err := parseGrype([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if findings[0].CVSSScore != 9.1 || findings[0].CVSSVector != "" {
		t.Errorf("got score %.1f vector %q, want 9.1 and empty",
			findings[0].CVSSScore, findings[0].CVSSVector)
	}
}

func TestSelectByIDs(t *testing.T) {
	in := []Finding{
		{ID: "CVE-1", Aliases: []string{"GHSA-aaaa"}},
		{ID: "CVE-2"},
	}
	if kept, skipped := SelectByIDs(in, nil); len(kept) != 2 || skipped != 0 {
		t.Errorf("empty selector filtered: %v", ids(kept))
	}
	kept, skipped := SelectByIDs(in, []string{" ghsa-aaaa "})
	if len(kept) != 1 || kept[0].ID != "CVE-1" || skipped != 1 {
		t.Errorf("alias match: %v skipped %d", ids(kept), skipped)
	}
}

// The gathered layout must reach the prompt, and must be marked as already
// fetched so the agent does not spend a turn re-running those tools.
func TestBuildUserMessageOrientation(t *testing.T) {
	const layout = "### source_languages\n\nGo: 20 files (100%)"
	msg := buildUserMessage("CVE-2024-0001", "", layout)
	for _, want := range []string{"Project layout", "do not re-fetch", "Go: 20 files"} {
		if !strings.Contains(msg, want) {
			t.Errorf("missing %q in:\n%s", want, msg)
		}
	}
	// With nothing gathered, the section is omitted entirely.
	if msg := buildUserMessage("CVE-2024-0001", "", "  "); strings.Contains(msg, "Project layout") {
		t.Errorf("empty orientation still emitted a section:\n%s", msg)
	}
}

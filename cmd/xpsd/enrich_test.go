// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNeedsEnrichment(t *testing.T) {
	cases := []struct {
		f          Finding
		wantVector bool
		want       bool
	}{
		{Finding{Severity: "high", CVSSScore: 7.5}, false, false},
		{Finding{Severity: "unknown", CVSSScore: 7.5}, false, true},
		{Finding{Severity: "high", CVSSScore: 0}, false, true},
		{Finding{Severity: "unknown", CVSSScore: 0}, false, true},
		// A complete finding still needs a lookup when the vector is wanted.
		{Finding{Severity: "high", CVSSScore: 7.5}, true, true},
		{Finding{Severity: "high", CVSSScore: 7.5, CVSSVector: "CVSS:3.1/AV:N"}, true, false},
	}
	for _, c := range cases {
		if got := needsEnrichment(c.f, c.wantVector); got != c.want {
			t.Errorf("needsEnrichment(%+v, wantVector=%v) = %v, want %v", c.f, c.wantVector, got, c.want)
		}
	}
}

func TestApplyOSV(t *testing.T) {
	// Score recovered from a CVSS v3 vector; severity derived from the score.
	v := &osvVuln{}
	v.Severity = []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	}{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}

	f := Finding{ID: "CVE-x", Severity: "unknown"}
	if !applyOSV(&f, v) {
		t.Fatal("applyOSV made no change")
	}
	if f.CVSSScore != 9.8 {
		t.Errorf("score = %.1f, want 9.8", f.CVSSScore)
	}
	if f.Severity != "critical" {
		t.Errorf("severity = %s, want critical", f.Severity)
	}

	// A scanner-provided severity is not overridden; only the missing score fills.
	f = Finding{ID: "CVE-x", Severity: "medium"}
	applyOSV(&f, v)
	if f.Severity != "medium" {
		t.Errorf("severity overridden to %s", f.Severity)
	}
	if f.CVSSScore != 9.8 {
		t.Errorf("score not filled: %.1f", f.CVSSScore)
	}

	// No CVSS vector, but a database_specific severity band is available.
	v2 := &osvVuln{}
	v2.DatabaseSpecific.Severity = "HIGH"
	f = Finding{ID: "CVE-y", Severity: "unknown"}
	applyOSV(&f, v2)
	if f.Severity != "high" {
		t.Errorf("band-only severity = %s, want high", f.Severity)
	}
}

func TestEnrichFindings(t *testing.T) {
	// Stub OSV: the CVE id 404s, its GHSA alias resolves.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/GHSA-aaaa-bbbb-cccc"):
			fmt.Fprint(w, `{"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	old := osvVulnBaseURL
	osvVulnBaseURL = srv.URL + "/"
	defer func() { osvVulnBaseURL = old }()

	findings := []Finding{
		{ID: "CVE-2023-0001", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Severity: "unknown"},
		{ID: "CVE-2023-0002", Severity: "critical", CVSSScore: 9.8}, // already complete: untouched
		{ID: "CVE-2023-0003", Severity: "unknown"},                  // no OSV record: stays unknown
	}

	n := EnrichFindings(context.Background(), findings, false)
	if n != 1 {
		t.Fatalf("enriched %d, want 1", n)
	}
	if findings[0].CVSSScore != 9.8 || findings[0].Severity != "critical" {
		t.Errorf("finding 0 not enriched: %+v", findings[0])
	}
	if findings[1].CVSSScore != 9.8 || findings[1].Severity != "critical" {
		t.Errorf("finding 1 changed: %+v", findings[1])
	}
	if findings[2].Severity != "unknown" {
		t.Errorf("finding 2 should stay unknown: %+v", findings[2])
	}
}

func TestEnrichFindingsNoWork(t *testing.T) {
	// Nothing missing: no lookups, returns 0.
	old := osvVulnBaseURL
	osvVulnBaseURL = "http://127.0.0.1:0/"
	defer func() { osvVulnBaseURL = old }()

	findings := []Finding{{ID: "CVE-x", Severity: "high", CVSSScore: 7.0}}
	if n := EnrichFindings(context.Background(), findings, false); n != 0 {
		t.Fatalf("enriched %d, want 0", n)
	}
}

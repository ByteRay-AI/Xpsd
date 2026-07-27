// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// osvVulnBaseURL is the OSV single-vulnerability endpoint.
var osvVulnBaseURL = "https://api.osv.dev/v1/vulns/"

// enrichHTTPClient talks to api.osv.dev and does not follow redirects.
var enrichHTTPClient = &http.Client{
	Timeout: 20 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// osvVuln is the slice of an OSV record used to recover a severity / CVSS score.
type osvVuln struct {
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

// EnrichFindings fills in severity and CVSS for findings the scanner left
// without either, by looking them up in the OSV database. It mutates findings
// in place and returns the number it changed. Best-effort: a lookup that fails
// or carries no score leaves the finding untouched.
// wantVector also fetches the CVSS vector for findings that already have a
// score, which only the -is-remote gate needs.
func EnrichFindings(ctx context.Context, findings []Finding, wantVector bool) int {
	var todo []int
	for i := range findings {
		if needsEnrichment(findings[i], wantVector) {
			todo = append(todo, i)
		}
	}
	if len(todo) == 0 {
		return 0
	}

	var (
		mu      sync.Mutex
		cache   = map[string]*osvVuln{} // negative entries (nil) cached too
		changed int
	)
	lookup := func(id string) *osvVuln {
		mu.Lock()
		v, ok := cache[id]
		mu.Unlock()
		if ok {
			return v
		}
		res := fetchOSVVuln(ctx, id)
		mu.Lock()
		cache[id] = res
		mu.Unlock()
		return res
	}

	const workers = 6
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for _, idx := range todo {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int) {
			defer wg.Done()
			defer func() { <-sem }()
			f := &findings[idx]
			// OSV is keyed by any of the vuln's ids.
			// Keep walking the ids until nothing is missing: one record may fill
			// only part of the gap, and an alias record can supply the rest.
			any := false
			for _, id := range append([]string{f.ID}, f.Aliases...) {
				if ctx.Err() != nil {
					break
				}
				v := lookup(id)
				if v == nil {
					continue
				}
				if applyOSV(f, v) {
					any = true
				}
				if !needsEnrichment(*f, wantVector) {
					break
				}
			}
			if any {
				mu.Lock()
				changed++
				mu.Unlock()
			}
		}(idx)
	}
	wg.Wait()
	return changed
}

// needsEnrichment reports whether a finding is missing data a lookup could fill.
func needsEnrichment(f Finding, wantVector bool) bool {
	if f.CVSSScore == 0 || f.Severity == "unknown" {
		return true
	}
	return wantVector && f.CVSSVector == ""
}

// applyOSV fills a missing score / severity on f from an OSV record without
// overriding values the scanner already provided. Returns true if it changed
// anything.
func applyOSV(f *Finding, v *osvVuln) bool {
	changed := false
	var bestVector string
	var best float64
	for _, s := range v.Severity {
		if !strings.HasPrefix(s.Type, "CVSS_V3") {
			continue
		}
		if score, ok := CVSS3BaseScore(s.Score); ok && score > best {
			best, bestVector = score, s.Score
		}
	}
	if f.CVSSVector == "" && bestVector != "" {
		f.CVSSVector = bestVector
		changed = true
	}
	if f.CVSSScore == 0 && best > 0 {
		f.CVSSScore = best
		changed = true
	}
	if f.Severity == "unknown" {
		if f.CVSSScore > 0 {
			f.Severity = scoreToSeverity(f.CVSSScore)
			changed = true
		} else if s := NormalizeSeverity(v.DatabaseSpecific.Severity); s != "unknown" {
			f.Severity = s
			changed = true
		}
	}
	return changed
}

// fetchOSVVuln retrieves one OSV record, returning nil on any failure.
func fetchOSVVuln(ctx context.Context, id string) *osvVuln {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvVulnBaseURL+url.PathEscape(id), nil)
	if err != nil {
		return nil
	}
	resp, err := enrichHTTPClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil
	}
	var v osvVuln
	if err := json.Unmarshal(data, &v); err != nil {
		return nil
	}
	return &v
}

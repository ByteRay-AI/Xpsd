// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Finding is one vulnerability finding normalized from a scanner report.
type Finding struct {
	ID           string   // canonical vulnerability id, CVE preferred
	Aliases      []string // other ids for the same vulnerability (GHSA, SNYK, ...)
	Package      string   // affected package name
	Version      string   // installed / detected version
	FixedVersion string   // fixed version(s) the scanner reports; may list several across release branches
	Severity     string   // normalized: critical, high, medium, low, negligible, unknown
	CVSSScore    float64  // 0 when unknown
	CVSSVector   string   // CVSS v2/v3 vector string, when the scanner reports one
	Title        string
	Description  string
	URLs         []string
	Ecosystem    string // package ecosystem (npm, golang, maven, ...), when known
	Target       string // scanner-reported target (lockfile, image layer, SBOM path)
}

// Scan report formats accepted by -scan.
const (
	FormatAuto  = "auto"
	FormatGrype = "grype"
	FormatTrivy = "trivy"
	FormatOSV   = "osv"
	FormatSnyk  = "snyk"
	FormatSARIF = "sarif"
)

var scanFormats = []string{FormatGrype, FormatTrivy, FormatOSV, FormatSnyk, FormatSARIF}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

var ghsaRe = regexp.MustCompile(`GHSA(-[a-hj-np-z2-9]{4}){3}`)

// Severity ranks for -min-severity filtering and sorting.
var severityRank = map[string]int{
	"critical":   5,
	"high":       4,
	"medium":     3,
	"low":        2,
	"negligible": 1,
	"unknown":    0,
}

// cvssPick keeps the highest CVSS score seen together with the vector it came
// from, so the two are never taken from different entries. A winning entry with
// no vector leaves the vector empty, letting enrichment supply a matching one.
type cvssPick struct {
	score  float64
	vector string
}

// --- SARIF (generic scanner output) ---

var versionInMsgRe = regexp.MustCompile(`(?i)Installed Version:\s*([^\s,;]+)`)

var packageInMsgRe = regexp.MustCompile(`(?i)Package:\s*([^\s,;]+)`)

// Key returns the dedup identity of a finding.
func (f Finding) Key() string {
	return f.ID + "|" + f.Package + "|" + f.Version
}

// ParseScan parses a scanner report into normalized findings. Format is one of
// the Format* constants; FormatAuto probes the document structure.
func ParseScan(data []byte, format string) ([]Finding, string, error) {
	if format == "" || format == FormatAuto {
		detected, err := DetectScanFormat(data)
		if err != nil {
			return nil, "", err
		}
		format = detected
	}

	var (
		findings []Finding
		err      error
	)
	switch format {
	case FormatGrype:
		findings, err = parseGrype(data)
	case FormatTrivy:
		findings, err = parseTrivy(data)
	case FormatOSV:
		findings, err = parseOSV(data)
	case FormatSnyk:
		findings, err = parseSnyk(data)
	case FormatSARIF:
		findings, err = parseSARIF(data)
	default:
		return nil, "", fmt.Errorf("unknown scan format %q (want %s)", format, strings.Join(scanFormats, "|"))
	}
	if err != nil {
		return nil, format, fmt.Errorf("parsing %s report: %w", format, err)
	}
	return findings, format, nil
}

// DetectScanFormat identifies the scanner that produced the report by probing
// its top-level structure.
func DetectScanFormat(data []byte) (string, error) {
	trimmed := strings.TrimLeftFunc(string(data), func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})

	// Snyk with --all-projects emits a top-level array of project reports.
	if strings.HasPrefix(trimmed, "[") {
		var arr []map[string]json.RawMessage
		if err := json.Unmarshal(data, &arr); err != nil {
			return "", fmt.Errorf("not a JSON document: %w", err)
		}
		if len(arr) > 0 {
			if _, ok := arr[0]["vulnerabilities"]; ok {
				return FormatSnyk, nil
			}
		}
		return "", fmt.Errorf("unrecognized scan report: JSON array without Snyk project objects")
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(data, &top); err != nil {
		return "", fmt.Errorf("not a JSON document: %w", err)
	}

	has := func(key string) bool { _, ok := top[key]; return ok }

	switch {
	case has("matches") && has("descriptor"):
		return FormatGrype, nil
	// A clean Trivy report omits Results entirely (omitempty).
	case has("SchemaVersion") && (has("Results") || has("ArtifactName") || has("ArtifactType")):
		return FormatTrivy, nil
	case has("runs") && has("version"):
		return FormatSARIF, nil
	case has("vulnerabilities") && (has("ok") || has("packageManager") || has("projectName")):
		return FormatSnyk, nil
	case has("results"):
		// OSV-Scanner: results[].packages[].vulnerabilities
		var probe struct {
			Results []struct {
				Packages []json.RawMessage `json:"packages"`
			} `json:"results"`
		}
		if json.Unmarshal(data, &probe) == nil {
			for _, r := range probe.Results {
				if len(r.Packages) > 0 {
					return FormatOSV, nil
				}
			}
			// An OSV report with zero packages is still an OSV report.
			return FormatOSV, nil
		}
	}
	return "", fmt.Errorf("unrecognized scan report format; pass -scan-format (%s)", strings.Join(scanFormats, "|"))
}

// canonicalizeID prefers a CVE id over vendor ids: if primary is not a CVE but
// one of the aliases is, they are swapped. Returns (id, aliases).
func canonicalizeID(primary string, aliases []string) (string, []string) {
	primary = strings.TrimSpace(primary)
	if strings.HasPrefix(primary, "CVE-") {
		return primary, dedupeStrings(aliases, primary)
	}
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			rest := dedupeStrings(append([]string{primary}, aliases...), a)
			return a, rest
		}
	}
	return primary, dedupeStrings(aliases, primary)
}

// dedupeStrings removes duplicates, empties, and the excluded value while
// preserving order.
func dedupeStrings(in []string, exclude string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || s == exclude || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// NormalizeSeverity maps scanner severity spellings onto the canonical set.
func NormalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low", "informational", "info":
		return "low"
	case "negligible":
		return "negligible"
	default:
		return "unknown"
	}
}

// scoreToSeverity converts a CVSS base score to a severity band
// (CVSS v3 qualitative rating scale).
func scoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "unknown"
	}
}

// offer records (score, vector) when it beats what is held. A zero score is
// derived from the vector when possible.
func (p *cvssPick) offer(score float64, vector string) {
	if score <= 0 && vector != "" {
		if s, ok := CVSS3BaseScore(vector); ok {
			score = s
		}
	}
	if score > p.score {
		p.score, p.vector = score, vector
	}
}

// finishFinding fills derived fields: canonical id, severity fallback from
// CVSS score, and normalization.
func finishFinding(f Finding) Finding {
	f.ID, f.Aliases = canonicalizeID(f.ID, f.Aliases)
	f.Severity = NormalizeSeverity(f.Severity)
	if f.Severity == "unknown" && f.CVSSScore > 0 {
		f.Severity = scoreToSeverity(f.CVSSScore)
	}
	f.URLs = dedupeStrings(f.URLs, "")
	return f
}

// FilterFindings applies dedup, the -only id selection, the -min-severity and
// -min-cvss floors, deterministic ordering (severity desc, then CVSS desc, then
// id/package), and the -max-findings cap. Returns the kept findings plus the
// number skipped. onlyIDs match the finding's canonical id or any alias,
// case-insensitively.
func FilterFindings(in []Finding, minSeverity string, minCVSS float64, maxFindings int, onlyIDs []string) ([]Finding, int, error) {
	kept, skipped, err := SelectFindings(in, minSeverity, minCVSS, onlyIDs)
	if err != nil {
		return nil, 0, err
	}
	capped, dropped := RankAndCap(kept, maxFindings)
	return capped, skipped + dropped, nil
}

// DedupFindings drops findings with no id and collapses repeats of the same
// id, package, and version. Returns the kept findings and the number removed.
func DedupFindings(in []Finding) ([]Finding, int) {
	seen := map[string]bool{}
	kept := make([]Finding, 0, len(in))
	for _, f := range in {
		if f.ID == "" || seen[f.Key()] {
			continue
		}
		seen[f.Key()] = true
		kept = append(kept, f)
	}
	return kept, len(in) - len(kept)
}

// RankAndCap orders findings by severity, then CVSS, then id and package, and
// keeps at most maxFindings (0 = all). Returns the kept findings and the number
// dropped by the cap.
func RankAndCap(in []Finding, maxFindings int) ([]Finding, int) {
	kept := make([]Finding, len(in))
	copy(kept, in)
	sort.SliceStable(kept, func(i, j int) bool {
		if a, b := severityRank[kept[i].Severity], severityRank[kept[j].Severity]; a != b {
			return a > b
		}
		if kept[i].CVSSScore != kept[j].CVSSScore {
			return kept[i].CVSSScore > kept[j].CVSSScore
		}
		if kept[i].ID != kept[j].ID {
			return kept[i].ID < kept[j].ID
		}
		return kept[i].Package < kept[j].Package
	})
	if maxFindings > 0 && len(kept) > maxFindings {
		dropped := len(kept) - maxFindings
		return kept[:maxFindings], dropped
	}
	return kept, 0
}

// SelectByIDs keeps only findings whose canonical id or an alias appears in
// onlyIDs, case-insensitively. An empty onlyIDs keeps everything. Returns the
// kept findings and the number skipped.
func SelectByIDs(in []Finding, onlyIDs []string) ([]Finding, int) {
	wanted := map[string]bool{}
	for _, id := range onlyIDs {
		if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
			wanted[id] = true
		}
	}
	if len(wanted) == 0 {
		return in, 0
	}
	kept := make([]Finding, 0, len(in))
	for _, f := range in {
		match := wanted[strings.ToLower(f.ID)]
		for _, a := range f.Aliases {
			if match {
				break
			}
			match = wanted[strings.ToLower(a)]
		}
		if match {
			kept = append(kept, f)
		}
	}
	return kept, len(in) - len(kept)
}

// SelectFindings applies dedup, the -only id selection, and the -min-severity
// and -min-cvss floors. Ordering and the cap are left to RankAndCap. Returns the
// kept findings plus the number skipped. onlyIDs match the finding's canonical
// id or any alias, case-insensitively.
func SelectFindings(in []Finding, minSeverity string, minCVSS float64, onlyIDs []string) ([]Finding, int, error) {
	minRank := 0
	if minSeverity != "" {
		r, ok := severityRank[NormalizeSeverity(minSeverity)]
		if !ok || NormalizeSeverity(minSeverity) == "unknown" {
			return nil, 0, fmt.Errorf("invalid -min-severity %q (want low|medium|high|critical)", minSeverity)
		}
		minRank = r
	}
	if minCVSS < 0 || minCVSS > 10 {
		return nil, 0, fmt.Errorf("invalid -min-cvss %.1f (want 0.0-10.0)", minCVSS)
	}

	wanted := map[string]bool{}
	for _, id := range onlyIDs {
		if id = strings.ToLower(strings.TrimSpace(id)); id != "" {
			wanted[id] = true
		}
	}
	matchesOnly := func(f Finding) bool {
		if len(wanted) == 0 {
			return true
		}
		if wanted[strings.ToLower(f.ID)] {
			return true
		}
		for _, a := range f.Aliases {
			if wanted[strings.ToLower(a)] {
				return true
			}
		}
		return false
	}

	seen := map[string]bool{}
	var kept []Finding
	for _, f := range in {
		if f.ID == "" {
			continue
		}
		if seen[f.Key()] {
			continue
		}
		seen[f.Key()] = true
		if !matchesOnly(f) {
			continue
		}
		if minRank > 0 && f.Severity != "unknown" && severityRank[f.Severity] < minRank {
			continue
		}
		if minCVSS > 0 && f.CVSSScore > 0 && f.CVSSScore < minCVSS {
			continue
		}
		kept = append(kept, f)
	}

	return kept, len(in) - len(kept), nil
}

// --- Grype ---

func parseGrype(data []byte) ([]Finding, error) {
	var doc struct {
		Matches []struct {
			Vulnerability struct {
				ID          string   `json:"id"`
				Severity    string   `json:"severity"`
				Description string   `json:"description"`
				URLs        []string `json:"urls"`
				DataSource  string   `json:"dataSource"`
				CVSS        []struct {
					Metrics struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"metrics"`
					Vector string `json:"vector"`
				} `json:"cvss"`
				Fix struct {
					Versions []string `json:"versions"`
					State    string   `json:"state"`
				} `json:"fix"`
			} `json:"vulnerability"`
			RelatedVulnerabilities []struct {
				ID          string   `json:"id"`
				Description string   `json:"description"`
				URLs        []string `json:"urls"`
				CVSS        []struct {
					Metrics struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"metrics"`
					Vector string `json:"vector"`
				} `json:"cvss"`
			} `json:"relatedVulnerabilities"`
			Artifact struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Type      string `json:"type"`
				PURL      string `json:"purl"`
				Locations []struct {
					Path string `json:"path"`
				} `json:"locations"`
			} `json:"artifact"`
		} `json:"matches"`
		Source struct {
			Target json.RawMessage `json:"target"`
		} `json:"source"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var out []Finding
	for _, m := range doc.Matches {
		f := Finding{
			ID:          m.Vulnerability.ID,
			Severity:    m.Vulnerability.Severity,
			Description: m.Vulnerability.Description,
			URLs:        m.Vulnerability.URLs,
			Package:     m.Artifact.Name,
			Version:     m.Artifact.Version,
			Ecosystem:   m.Artifact.Type,
		}
		if len(m.Vulnerability.Fix.Versions) > 0 {
			f.FixedVersion = strings.Join(m.Vulnerability.Fix.Versions, ", ")
		}
		var pick cvssPick
		for _, c := range m.Vulnerability.CVSS {
			pick.offer(c.Metrics.BaseScore, c.Vector)
		}
		for _, rv := range m.RelatedVulnerabilities {
			f.Aliases = append(f.Aliases, rv.ID)
			if f.Description == "" {
				f.Description = rv.Description
			}
			f.URLs = append(f.URLs, rv.URLs...)
			for _, c := range rv.CVSS {
				pick.offer(c.Metrics.BaseScore, c.Vector)
			}
		}
		f.CVSSScore, f.CVSSVector = pick.score, pick.vector
		if len(m.Artifact.Locations) > 0 {
			f.Target = m.Artifact.Locations[0].Path
		}
		if m.Vulnerability.DataSource != "" {
			f.URLs = append(f.URLs, m.Vulnerability.DataSource)
		}
		out = append(out, finishFinding(f))
	}
	return out, nil
}

// --- Trivy ---

func parseTrivy(data []byte) ([]Finding, error) {
	var doc struct {
		ArtifactName string `json:"ArtifactName"`
		Results      []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				VulnerabilityID  string   `json:"VulnerabilityID"`
				PkgName          string   `json:"PkgName"`
				InstalledVersion string   `json:"InstalledVersion"`
				FixedVersion     string   `json:"FixedVersion"`
				Severity         string   `json:"Severity"`
				Title            string   `json:"Title"`
				Description      string   `json:"Description"`
				PrimaryURL       string   `json:"PrimaryURL"`
				References       []string `json:"References"`
				CVSS             map[string]struct {
					V3Score  float64 `json:"V3Score"`
					V3Vector string  `json:"V3Vector"`
					V2Score  float64 `json:"V2Score"`
				} `json:"CVSS"`
			} `json:"Vulnerabilities"`
			Type string `json:"Type"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var out []Finding
	for _, r := range doc.Results {
		for _, v := range r.Vulnerabilities {
			f := Finding{
				ID:           v.VulnerabilityID,
				Package:      v.PkgName,
				Version:      v.InstalledVersion,
				FixedVersion: v.FixedVersion,
				Severity:     v.Severity,
				Title:        v.Title,
				Description:  v.Description,
				Ecosystem:    r.Type,
				Target:       r.Target,
			}
			if v.PrimaryURL != "" {
				f.URLs = append(f.URLs, v.PrimaryURL)
			}
			f.URLs = append(f.URLs, v.References...)
			// Prefer NVD's V3 score, fall back to the max across sources.
			if nvd, ok := v.CVSS["nvd"]; ok && nvd.V3Score > 0 {
				f.CVSSScore = nvd.V3Score
				f.CVSSVector = nvd.V3Vector
			} else {
				for _, c := range v.CVSS {
					if c.V3Score > f.CVSSScore {
						f.CVSSScore = c.V3Score
						f.CVSSVector = c.V3Vector
					}
				}
			}
			out = append(out, finishFinding(f))
		}
	}
	return out, nil
}

// --- OSV-Scanner ---

func parseOSV(data []byte) ([]Finding, error) {
	var doc struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
				Type string `json:"type"`
			} `json:"source"`
			Packages []struct {
				Package struct {
					Name      string `json:"name"`
					Version   string `json:"version"`
					Ecosystem string `json:"ecosystem"`
				} `json:"package"`
				Vulnerabilities []struct {
					ID       string   `json:"id"`
					Aliases  []string `json:"aliases"`
					Summary  string   `json:"summary"`
					Details  string   `json:"details"`
					Severity []struct {
						Type  string `json:"type"`
						Score string `json:"score"`
					} `json:"severity"`
					References []struct {
						URL string `json:"url"`
					} `json:"references"`
					Affected []struct {
						Package struct {
							Name string `json:"name"`
						} `json:"package"`
						Ranges []struct {
							Type   string `json:"type"`
							Events []struct {
								Introduced string `json:"introduced"`
								Fixed      string `json:"fixed"`
							} `json:"events"`
						} `json:"ranges"`
					} `json:"affected"`
					DatabaseSpecific struct {
						Severity string `json:"severity"`
					} `json:"database_specific"`
				} `json:"vulnerabilities"`
				Groups []struct {
					IDs         []string `json:"ids"`
					MaxSeverity string   `json:"max_severity"`
				} `json:"groups"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var out []Finding
	for _, r := range doc.Results {
		for _, p := range r.Packages {
			// groups[].max_severity carries the numeric CVSS score per
			// vulnerability group; index it by member id.
			groupScore := map[string]float64{}
			for _, g := range p.Groups {
				score, err := strconv.ParseFloat(g.MaxSeverity, 64)
				if err != nil {
					continue
				}
				for _, id := range g.IDs {
					groupScore[id] = score
				}
			}

			for _, v := range p.Vulnerabilities {
				f := Finding{
					ID:          v.ID,
					Aliases:     v.Aliases,
					Package:     p.Package.Name,
					Version:     p.Package.Version,
					Ecosystem:   p.Package.Ecosystem,
					Title:       v.Summary,
					Description: v.Details,
					Severity:    v.DatabaseSpecific.Severity,
					Target:      r.Source.Path,
				}
				for _, ref := range v.References {
					f.URLs = append(f.URLs, ref.URL)
				}
				var pick cvssPick
				for _, sev := range v.Severity {
					if strings.HasPrefix(sev.Type, "CVSS_V3") {
						pick.offer(0, sev.Score)
					}
				}
				f.CVSSScore, f.CVSSVector = pick.score, pick.vector
				// groups[].max_severity is the group maximum, so it can belong to
				// another member; use it only when no vector gave a score.
				if f.CVSSScore == 0 {
					if s, ok := groupScore[v.ID]; ok {
						f.CVSSScore = s
					}
				}
				// Collect every fixed version for the matching package: ranges
				// cover multiple release branches.
				var fixed []string
				for _, a := range v.Affected {
					if a.Package.Name != "" && a.Package.Name != p.Package.Name {
						continue
					}
					for _, rg := range a.Ranges {
						for _, ev := range rg.Events {
							if ev.Fixed != "" {
								fixed = append(fixed, ev.Fixed)
							}
						}
					}
				}
				f.FixedVersion = strings.Join(dedupeStrings(fixed, ""), ", ")
				out = append(out, finishFinding(f))
			}
		}
	}
	return out, nil
}

// --- Snyk ---

func parseSnyk(data []byte) ([]Finding, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var projects []json.RawMessage
		if err := json.Unmarshal(data, &projects); err != nil {
			return nil, err
		}
		var out []Finding
		for _, p := range projects {
			fs, err := parseSnykProject(p)
			if err != nil {
				return nil, err
			}
			out = append(out, fs...)
		}
		return out, nil
	}
	return parseSnykProject(data)
}

func parseSnykProject(data []byte) ([]Finding, error) {
	var doc struct {
		Vulnerabilities []struct {
			ID          string   `json:"id"`
			Title       string   `json:"title"`
			Severity    string   `json:"severity"`
			CVSSScore   float64  `json:"cvssScore"`
			CVSSv3      string   `json:"CVSSv3"`
			Description string   `json:"description"`
			PackageName string   `json:"packageName"`
			Version     string   `json:"version"`
			From        []string `json:"from"`
			FixedIn     []string `json:"fixedIn"`
			Identifiers struct {
				CVE  []string `json:"CVE"`
				GHSA []string `json:"GHSA"`
			} `json:"identifiers"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"vulnerabilities"`
		PackageManager    string `json:"packageManager"`
		ProjectName       string `json:"projectName"`
		DisplayTargetFile string `json:"displayTargetFile"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	target := doc.DisplayTargetFile
	if target == "" {
		target = doc.ProjectName
	}

	var out []Finding
	for _, v := range doc.Vulnerabilities {
		f := Finding{
			ID:          v.ID,
			Title:       v.Title,
			Severity:    v.Severity,
			CVSSScore:   v.CVSSScore,
			Description: v.Description,
			Package:     v.PackageName,
			Version:     v.Version,
			Ecosystem:   doc.PackageManager,
			Target:      target,
		}
		f.Aliases = append(f.Aliases, v.Identifiers.CVE...)
		f.Aliases = append(f.Aliases, v.Identifiers.GHSA...)
		if len(v.FixedIn) > 0 {
			f.FixedVersion = strings.Join(v.FixedIn, ", ")
		}
		f.CVSSVector = v.CVSSv3
		if f.CVSSScore == 0 && v.CVSSv3 != "" {
			if s, ok := CVSS3BaseScore(v.CVSSv3); ok {
				f.CVSSScore = s
			}
		}
		for _, ref := range v.References {
			f.URLs = append(f.URLs, ref.URL)
		}
		if len(v.From) > 1 {
			f.Description = fmt.Sprintf("Dependency path: %s\n\n%s",
				strings.Join(v.From, " > "), f.Description)
		}
		out = append(out, finishFinding(f))
	}
	return out, nil
}

func parseSARIF(data []byte) ([]Finding, error) {
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID               string `json:"id"`
						Name             string `json:"name"`
						ShortDescription struct {
							Text string `json:"text"`
						} `json:"shortDescription"`
						FullDescription struct {
							Text string `json:"text"`
						} `json:"fullDescription"`
						Help struct {
							Text string `json:"text"`
						} `json:"help"`
						HelpURI    string `json:"helpUri"`
						Properties struct {
							SecuritySeverity string   `json:"security-severity"`
							Tags             []string `json:"tags"`
						} `json:"properties"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex *int   `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct {
					Text string `json:"text"`
				} `json:"message"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	var out []Finding
	for _, run := range doc.Runs {
		rules := run.Tool.Driver.Rules
		ruleByID := map[string]int{}
		for i, r := range rules {
			ruleByID[r.ID] = i
		}

		for _, res := range run.Results {
			f := Finding{
				ID: res.RuleID,
			}

			// Attach rule metadata when resolvable.
			ruleIdx := -1
			if res.RuleIndex != nil && *res.RuleIndex >= 0 && *res.RuleIndex < len(rules) {
				ruleIdx = *res.RuleIndex
			} else if i, ok := ruleByID[res.RuleID]; ok {
				ruleIdx = i
			}
			if ruleIdx >= 0 {
				rule := rules[ruleIdx]
				f.Title = rule.ShortDescription.Text
				f.Description = rule.FullDescription.Text
				if f.Description == "" {
					f.Description = rule.Help.Text
				}
				if rule.HelpURI != "" {
					f.URLs = append(f.URLs, rule.HelpURI)
				}
				if rule.Properties.SecuritySeverity != "" {
					if s, err := strconv.ParseFloat(rule.Properties.SecuritySeverity, 64); err == nil {
						f.CVSSScore = s
					}
				}
			}

			// The result message usually carries the package/version context.
			msg := strings.TrimSpace(res.Message.Text)
			if msg != "" {
				if f.Description == "" {
					f.Description = msg
				} else if !strings.Contains(f.Description, msg) {
					f.Description = msg + "\n\n" + f.Description
				}
			}

			// Structured extraction from conventional message shapes
			// (Trivy/Grype SARIF embed "Package: x / Installed Version: y").
			combined := msg + "\n" + f.Description + "\n" + f.Title
			if m := packageInMsgRe.FindStringSubmatch(combined); m != nil {
				f.Package = m[1]
			}
			if m := versionInMsgRe.FindStringSubmatch(combined); m != nil {
				f.Version = m[1]
			}

			// Rule ids are often decorated ("GHSA-xxxx-...-lodash",
			// "CVE-2021-44228-log4j-core"); extract the bare vulnerability id
			// and keep the decorated one as an alias.
			if bare := cveRe.FindString(res.RuleID); bare != "" && bare != f.ID {
				f.Aliases = append(f.Aliases, f.ID)
				f.ID = bare
			} else if bare := ghsaRe.FindString(res.RuleID); bare != "" && bare != f.ID {
				f.Aliases = append(f.Aliases, f.ID)
				f.ID = bare
			}

			if res.Level != "" {
				f.Severity = sarifLevelToSeverity(res.Level, f.CVSSScore)
			}
			if len(res.Locations) > 0 {
				f.Target = res.Locations[0].PhysicalLocation.ArtifactLocation.URI
			}
			out = append(out, finishFinding(f))
		}
	}
	return out, nil
}

// sarifLevelToSeverity maps a SARIF result level to a severity band, letting a
// security-severity score take precedence when present.
func sarifLevelToSeverity(level string, score float64) string {
	if score > 0 {
		return scoreToSeverity(score)
	}
	switch level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	default:
		return "unknown"
	}
}

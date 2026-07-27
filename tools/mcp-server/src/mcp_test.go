// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// skipIfNoNetwork skips a test when the host has no outbound network.
func skipIfNoNetwork(t *testing.T) {
	t.Helper()
	c := &http.Client{Timeout: 8 * time.Second}
	resp, err := c.Head("https://github.com")
	if err != nil {
		t.Skipf("no outbound network; skipping: %v", err)
	}
	resp.Body.Close()
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// skipIfNoAstGrep skips a test when ast-grep is not installed on the host.
func skipIfNoAstGrep(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("ast-grep"); err != nil {
		t.Skip("ast-grep not available; skipping")
	}
}

// writeTempSource creates a temp source tree (path -> contents) plus a
// tool-output dir.
func writeTempSource(t *testing.T, files map[string]string) (srcDir, outDir string) {
	t.Helper()
	srcDir, outDir = t.TempDir(), t.TempDir()
	for rel, content := range files {
		full := filepath.Join(srcDir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return srcDir, outDir
}

// ---------------------------------------------------------------------------
// source_languages: stats building
// ---------------------------------------------------------------------------

func TestBuildLanguageStats(t *testing.T) {
	// Per-extension counts as sourceExtCounts would return them.
	counts := map[string]int{"go": 2, "py": 1, "md": 5} // md is not a recognized source ext

	stats, total := buildLanguageStats(counts)
	byLang := map[string]int{}
	for _, s := range stats {
		byLang[s.Language] = s.Files
	}
	if byLang["Go"] != 2 {
		t.Errorf("Go files = %d, want 2 (%v)", byLang["Go"], byLang)
	}
	if byLang["Python"] != 1 {
		t.Errorf("Python files = %d, want 1 (%v)", byLang["Python"], byLang)
	}
	if total != 3 { // 2 go + 1 py; md excluded
		t.Errorf("total source files = %d, want 3", total)
	}
	// Most-used language sorts first.
	if len(stats) == 0 || stats[0].Language != "Go" {
		t.Errorf("expected Go first, got %+v", stats)
	}
}

// ---------------------------------------------------------------------------
// fetch_dependency_source helpers
// ---------------------------------------------------------------------------

func TestIsArchiveURL(t *testing.T) {
	cases := map[string]bool{
		"https://github.com/google/fscrypt":                                 false,
		"https://github.com/google/fscrypt.git":                             false,
		"https://github.com/google/fscrypt/archive/refs/tags/v0.3.4.tar.gz": true,
		"https://example.com/pkg-1.2.3.zip":                                 true,
		"https://example.com/pkg.tar?token=abc":                             true,
		"https://example.com/pkg.tgz#frag":                                  true,
	}
	for url, want := range cases {
		if got := isArchiveURL(url); got != want {
			t.Errorf("isArchiveURL(%q) = %v, want %v", url, got, want)
		}
	}
}

func TestSafeJoin(t *testing.T) {
	base := "/tmp/dest"
	if _, ok := safeJoin(base, "a/b/c.go"); !ok {
		t.Error("safeJoin rejected a legitimate nested path")
	}
	if _, ok := safeJoin(base, "../escape"); ok {
		t.Error("safeJoin allowed a path traversal escape")
	}
	if _, ok := safeJoin(base, "a/../../escape"); ok {
		t.Error("safeJoin allowed a nested traversal escape")
	}
}

func TestSanitizeSlug(t *testing.T) {
	if got := depSlug("https://github.com/google/fscrypt", "v0.3.4"); got != "github.com-google-fscrypt@v0.3.4" {
		t.Errorf("depSlug = %q", got)
	}
	if got := depSlug("https://github.com/google/fscrypt.git", ""); got != "github.com-google-fscrypt" {
		t.Errorf("depSlug (no ref) = %q", got)
	}
}

// TestFetchDependencySource exercises both fetch modes end-to-end against real
// upstream (fscrypt v0.3.4). Requires network.
func TestFetchDependencySource(t *testing.T) {
	skipIfNoNetwork(t)
	out := t.TempDir()
	ctx := context.Background()

	t.Run("git", func(t *testing.T) {
		if _, err := exec.LookPath("git"); err != nil {
			t.Skip("git not installed")
		}
		dest := filepath.Join(out, "deps", "git")
		mode, root, err := fetchDependency(ctx, "https://github.com/google/fscrypt", "v0.3.4", dest)
		if err != nil {
			t.Fatalf("git fetch: %v", err)
		}
		if mode != "git" {
			t.Errorf("mode = %q, want git", mode)
		}
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
			t.Fatalf("go.mod missing in clone: %v", err)
		}

		cpath := toContainerPath(root, "", out)
		ssh, err := runGrep(`golang.org/x/crypto/ssh`, "", []string{cpath}, 50, 0, "", out)
		if err != nil {
			t.Fatalf("grep ssh: %v", err)
		}
		if len(ssh) != 0 {
			t.Errorf("fscrypt should not reference x/crypto/ssh, got %+v", ssh)
		}
		kdf, err := runGrep(`golang.org/x/crypto/(argon2|hkdf)`, "", []string{cpath}, 50, 0, "", out)
		if err != nil {
			t.Fatalf("grep kdf: %v", err)
		}
		if len(kdf) == 0 {
			t.Error("expected fscrypt to import argon2/hkdf")
		}
	})

	t.Run("archive", func(t *testing.T) {
		dest := filepath.Join(out, "deps", "arc")
		mode, root, err := fetchDependency(ctx,
			"https://github.com/google/fscrypt/archive/refs/tags/v0.3.4.tar.gz", "", dest)
		if err != nil {
			t.Fatalf("archive fetch: %v", err)
		}
		if mode != "archive" {
			t.Errorf("mode = %q, want archive", mode)
		}
		if !strings.Contains(root, "fscrypt") {
			t.Errorf("expected single top-level dir collapsed, got %q", root)
		}
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
			t.Fatalf("go.mod missing after extract: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// source_languages: extension walk (local)
// ---------------------------------------------------------------------------

func TestSourceExtCounts(t *testing.T) {
	src, out := writeTempSource(t, map[string]string{
		"a.go":            "package a\n",
		"b.go":            "package b\n",
		"c.py":            "print(1)\n",
		"README.md":       "# not source\n",
		"vendor/x/dep.go": "package x\n", // pruned: under vendor/
	})

	counts, err := sourceExtCounts(containerSrcDir, src, out)
	if err != nil {
		t.Fatalf("sourceExtCounts: %v", err)
	}
	if counts["go"] != 2 {
		t.Errorf("go count = %d, want 2 (vendor/ pruned) (%v)", counts["go"], counts)
	}
	if counts["py"] != 1 {
		t.Errorf("py count = %d, want 1 (%v)", counts["py"], counts)
	}

	stats, total := buildLanguageStats(counts)
	if total != 3 {
		t.Errorf("total recognized = %d, want 3 (%+v)", total, stats)
	}
}

// ---------------------------------------------------------------------------
// file tools: grep / read_local_file / get_line_count / expand_folder
// ---------------------------------------------------------------------------

func TestFileTools(t *testing.T) {
	src, out := writeTempSource(t, map[string]string{
		"pkg/app.go": "package app\n\nfunc Vulnerable(x string) string {\n\treturn x\n}\n",
	})

	t.Run("grep", func(t *testing.T) {
		matches, err := runGrep("Vulnerable", ".go", []string{containerSrcDir}, 100, 0, src, out)
		if err != nil {
			t.Fatalf("runGrep: %v", err)
		}
		if len(matches) == 0 {
			t.Fatal("expected at least one grep match for 'Vulnerable'")
		}
		if !strings.HasSuffix(matches[0].File, "app.go") || matches[0].Line != 3 {
			t.Errorf("unexpected match: %+v", matches[0])
		}
	})

	t.Run("read_local_file", func(t *testing.T) {
		got, err := getSource(containerSrcDir+"/pkg/app.go", 1, 3, src, out)
		if err != nil {
			t.Fatalf("getSource: %v", err)
		}
		if !strings.Contains(got, "package app") || !strings.Contains(got, "func Vulnerable") {
			t.Errorf("getSource missing expected content:\n%s", got)
		}
	})

	t.Run("get_line_count", func(t *testing.T) {
		n, err := lineCount(containerSrcDir+"/pkg/app.go", src, out)
		if err != nil {
			t.Fatalf("lineCount: %v", err)
		}
		if n != 5 {
			t.Errorf("lineCount = %d, want 5", n)
		}
	})

	t.Run("expand_folder", func(t *testing.T) {
		entries, err := expandFolder(containerSrcDir, src, out)
		if err != nil {
			t.Fatalf("expandFolder: %v", err)
		}
		var sawPkg bool
		for _, e := range entries {
			if e.IsDir && strings.HasSuffix(e.Path, "pkg") {
				sawPkg = true
			}
		}
		if !sawPkg {
			t.Errorf("expandFolder did not list the 'pkg' directory: %+v", entries)
		}
	})
}

// ---------------------------------------------------------------------------
// ast-grep (requires ast-grep binary)
// ---------------------------------------------------------------------------

func TestRunAstGrep(t *testing.T) {
	skipIfNoAstGrep(t)

	src, out := writeTempSource(t, map[string]string{
		"app.go": "package app\n\nfunc Vulnerable(x string) {\n\tprintln(x)\n}\n",
	})

	results, err := runAstGrep("func Vulnerable($$$) { $$$ }", "go", containerSrcDir, 50, src, out)
	if err != nil {
		t.Fatalf("runAstGrep: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("expected at least one ast-grep match for the Vulnerable func")
	}
	if !strings.Contains(results[0].Text, "func Vulnerable") {
		t.Errorf("unexpected ast-grep match text: %q", results[0].Text)
	}
	if results[0].Line != 3 {
		t.Errorf("match line = %d, want 3", results[0].Line)
	}
}

// ---------------------------------------------------------------------------
// osv_get_vuln (requires network to api.osv.dev)
// ---------------------------------------------------------------------------

func TestOSVGetVuln(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	got, err := osvGet(ctx, osvBaseURL+"/v1/vulns/CVE-2021-44228")
	if err != nil {
		t.Skipf("skipping: OSV API unreachable (%v)", err)
	}
	rec, ok := got.(map[string]any)
	if !ok {
		t.Fatalf("expected a JSON object, got %T", got)
	}
	if rec["id"] != "CVE-2021-44228" {
		t.Errorf("id = %v, want CVE-2021-44228", rec["id"])
	}
	if _, hasAffected := rec["affected"]; !hasAffected {
		t.Error("advisory missing 'affected' field")
	}
}

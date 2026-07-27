// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolvePathConfinement(t *testing.T) {
	src, out := "/data/project", "/data/out"
	cases := []struct {
		in   string
		want string
	}{
		{"/src", src},
		{"/src/pkg/a.go", src + "/pkg/a.go"},
		{"/tool_output/r.json", out + "/r.json"},
		{"/tool_output", out},
		{"/src/../../../etc/passwd", src + "/etc/passwd"},
		{"/src/pkg/../../../../etc/shadow", src + "/etc/shadow"},
		{"/tool_output/../../etc/passwd", src + "/etc/passwd"},
		// Paths outside the virtual namespace resolve under the source root.
		{"/etc/passwd", src + "/etc/passwd"},
		{"main.go", src + "/main.go"},
		{"../secrets.txt", src},
	}
	for _, c := range cases {
		got := resolvePath(c.in, src, out)
		if got != c.want {
			t.Errorf("resolvePath(%q) = %q, want %q", c.in, got, c.want)
		}
		if !strings.HasPrefix(got, src) && !strings.HasPrefix(got, out) {
			t.Errorf("resolvePath(%q) escaped both roots: %q", c.in, got)
		}
	}
}

// TestConfineSymlinkEscape: a symlink inside the analyzed tree must not open
// files outside the source root.
func TestConfineSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("s3cret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "evil")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "ok"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ok", "a.go"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// Symlink pointing INSIDE the tree stays usable.
	if err := os.Symlink(filepath.Join(root, "ok"), filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}

	// Resolve t.TempDir itself (macOS /tmp is a symlink).
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}

	// Escaping symlink degrades to the root.
	if got := confine(root, "evil/secret.txt"); got != root {
		t.Errorf("symlink escape not confined: %q", got)
	}
	// Legit paths, existing and not-yet-existing, are untouched.
	if got := confine(root, "ok/a.go"); got != filepath.Join(root, "ok", "a.go") {
		t.Errorf("plain path broken: %q", got)
	}
	if got := confine(root, "ok/new.go"); got != filepath.Join(root, "ok", "new.go") {
		t.Errorf("nonexistent path broken: %q", got)
	}
	// In-tree symlinks keep working.
	if got := confine(root, "alias/a.go"); got != filepath.Join(root, "alias", "a.go") {
		t.Errorf("in-tree symlink broken: %q", got)
	}
}

func TestValidGitRef(t *testing.T) {
	ok := []string{"v1.2.3", "main", "release/1.x", "abc123def", "a_b-c.d"}
	bad := []string{"--upload-pack=touch /tmp/x", "--foo", "-x", "a b", "a;b", "a'b", "a|b", "", "a\nb"}
	for _, r := range ok {
		if !validGitRef(r) {
			t.Errorf("validGitRef(%q) = false, want true", r)
		}
	}
	for _, r := range bad {
		if validGitRef(r) {
			t.Errorf("validGitRef(%q) = true, want false", r)
		}
	}
}

func TestValidLang(t *testing.T) {
	for _, l := range []string{"go", "python", "javascript", "typescript", "rust", "c", "cpp", "java"} {
		if !validLang(l) {
			t.Errorf("validLang(%q) = false, want true", l)
		}
	}
	for _, l := range []string{"go\nrule: evil", "go --json", "go;rm", "", "GO", "-x", "a b", "go'x"} {
		if validLang(l) {
			t.Errorf("validLang(%q) = true, want false", l)
		}
	}
}

func TestValidSymbolName(t *testing.T) {
	for _, n := range []string{"append", "fmt.Sprintf", "std::vector", "handle_request", "Vec<T>", "os.Exec"} {
		if !validSymbolName(n) {
			t.Errorf("validSymbolName(%q) = false, want true", n)
		}
	}
	for _, n := range []string{"", "a\nrule: x", "a'b", "a\"b", "a`b", "a\\b", "a\x00b"} {
		if validSymbolName(n) {
			t.Errorf("validSymbolName(%q) = true, want false", n)
		}
	}
}

func TestYamlRegexBody(t *testing.T) {
	// A name with a single quote / newline must not be able to break out of a
	// single-quoted YAML regex scalar: quotes doubled, newlines stripped.
	got := yamlRegexBody("foo'\n  bar: baz")
	if strings.Contains(got, "\n") {
		t.Errorf("newline survived: %q", got)
	}
	if strings.Count(got, "'")%2 != 0 {
		t.Errorf("unbalanced single quotes (breakout risk): %q", got)
	}
	// Regex metacharacters in the name are escaped (QuoteMeta), e.g. '.'.
	if !strings.Contains(yamlRegexBody("a.b"), `\.`) {
		t.Errorf("dot not regex-escaped: %q", yamlRegexBody("a.b"))
	}
}

func TestExtractBudget(t *testing.T) {
	var b extractBudget
	if err := b.add(1000); err != nil {
		t.Fatalf("first add: %v", err)
	}
	// Blow the total-bytes cap.
	if err := b.add(maxTotalExtractBytes); err == nil {
		t.Error("aggregate byte cap not enforced")
	}
	// Blow the entry-count cap.
	var c extractBudget
	var lastErr error
	for i := 0; i <= maxExtractEntries+1; i++ {
		lastErr = c.add(0)
	}
	if lastErr == nil {
		t.Error("entry-count cap not enforced")
	}
}

func TestYamlSingleQuote(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"plain", "'plain'"},
		{"O'Brien", "'O''Brien'"},
		{"a'b'c", "'a''b''c'"},
		{"multi\nline: injected", "'multiline: injected'"},
		{"carriage\rreturn", "'carriagereturn'"},
		{"tab\tok", "'tab\tok'"},
	}
	for _, c := range cases {
		if got := yamlSingleQuote(c.in); got != c.want {
			t.Errorf("yamlSingleQuote(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCappedBuilder(t *testing.T) {
	b := newCappedBuilder(10)
	n, err := b.Write([]byte("12345"))
	if n != 5 || err != nil {
		t.Fatalf("first write: n=%d err=%v", n, err)
	}
	// Second write crosses the cap: reports full length, stores the prefix.
	n, err = b.Write([]byte("6789ABCDEF"))
	if n != 10 || err != nil {
		t.Fatalf("second write: n=%d err=%v", n, err)
	}
	if b.String() != "123456789A" {
		t.Errorf("stored %q", b.String())
	}
	if !b.truncated {
		t.Error("truncated flag not set")
	}
	// Writes past the cap are swallowed without error.
	if n, err := b.Write([]byte("zzz")); n != 3 || err != nil {
		t.Errorf("post-cap write: n=%d err=%v", n, err)
	}
	if b.String() != "123456789A" {
		t.Errorf("post-cap contents changed: %q", b.String())
	}
}

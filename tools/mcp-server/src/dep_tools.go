// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"archive/tar"
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const (
	// depFetchTimeout bounds a single clone/download+extract.
	depFetchTimeout = 5 * time.Minute
	// maxArchiveBytes caps both the download and any single extracted file.
	maxArchiveBytes = 512 << 20 // 512 MiB
	// maxTotalExtractBytes and maxExtractEntries cap the aggregate extraction.
	maxTotalExtractBytes = 1 << 30 // 1 GiB total uncompressed
	maxExtractEntries    = 20000
)

// extractBudget bounds the total size and file count of one archive extraction.
type extractBudget struct {
	bytes   int64
	entries int
}

// archiveExts are the suffixes that trigger download-and-extract mode.
var archiveExts = []string{".zip", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar"}

// validGitRef reports whether an agent-supplied git ref is safe to pass as a
// positional argument (no leading '-', no shell/path surprises).
var gitRefRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]*$`)

// depHTTPClient routes archive downloads through the loopback validating proxy.
var depHTTPClient = &http.Client{
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return checkURLAllowed(req.URL.String())
	},
	Transport: &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) {
			if safeProxyURL == "" {
				return nil, fmt.Errorf("SSRF-validating proxy unavailable")
			}
			return url.Parse(safeProxyURL)
		},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				return nil, fmt.Errorf("archive fetch must use the local proxy, not %s", address)
			}
			return (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, address)
		},
	},
}

func (b *extractBudget) add(n int64) error {
	b.entries++
	b.bytes += n
	if b.entries > maxExtractEntries {
		return fmt.Errorf("archive has more than %d files; refusing", maxExtractEntries)
	}
	if b.bytes > maxTotalExtractBytes {
		return fmt.Errorf("archive expands beyond %d bytes total; refusing", maxTotalExtractBytes)
	}
	return nil
}

// registerDepTools adds fetch_dependency_source: it brings the source of a
// dependency not vendored in /src into the sandbox under /tool_output.
func registerDepTools(s *server.MCPServer, maxBytes int, outDir string) {
	s.AddTool(
		mcp.NewTool("fetch_dependency_source",
			mcp.WithDescription(
				"Fetch the source of a dependency that is NOT vendored in /src — e.g. one a "+
					"Dockerfile or build script pulls from upstream at build time — into the "+
					"analysis sandbox, and return a path to it. Pass that path to the other tools "+
					"to analyze the dependency exactly like /src: as `path` to grep / "+
					"source_languages / source_dirs, as `dir` to the lang_* tools, or as `file` "+
					"to read_local_file.\n\n"+
					"Two modes, auto-detected from the URL:\n"+
					"  • archive — a .zip / .tar / .tar.gz / .tgz / .tar.bz2 URL is downloaded and extracted.\n"+
					"  • git     — any other URL is cloned (optionally at a tag/branch/commit `ref`).",
			),
			mcp.WithString("url",
				mcp.Required(),
				mcp.Description("Git repo URL (e.g. https://github.com/google/fscrypt) or archive URL "+
					"(e.g. https://github.com/google/fscrypt/archive/refs/tags/v0.3.4.tar.gz)"),
			),
			mcp.WithString("ref",
				mcp.Description("Git tag / branch / commit to check out (git mode only; default: the repo's default branch)"),
			),
			mcp.WithString("name",
				mcp.Description("Optional sandbox folder name for the fetched source (default: derived from the URL + ref)"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			rawURL, err := getStringArg(req, "url")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			rawURL = strings.TrimSpace(rawURL)
			if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
				return mcp.NewToolResultError("url must start with http:// or https://"), nil
			}
			if err := checkURLAllowed(rawURL); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if safeProxyURL == "" {
				return mcp.NewToolResultError("dependency fetching unavailable: SSRF-validating proxy is not running"), nil
			}
			if outDir == "" {
				return mcp.NewToolResultError("fetch_dependency_source unavailable: no tool-output dir configured"), nil
			}
			ref := strings.TrimSpace(getOptionalStringArg(req, "ref"))
			if ref != "" && !validGitRef(ref) {
				return mcp.NewToolResultError("invalid ref: only letters, digits and . _ / - are allowed, and it may not start with '-'"), nil
			}
			slug := sanitizeSlug(getOptionalStringArg(req, "name"))
			if slug == "" {
				slug = depSlug(rawURL, ref)
			}
			destRoot := filepath.Join(outDir, "deps", slug)

			ctx, cancel := context.WithTimeout(ctx, depFetchTimeout)
			defer cancel()

			mode, srcRootHost, err := fetchDependency(ctx, rawURL, ref, destRoot)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			makeReadable(destRoot)

			containerPath := toContainerPath(srcRootHost, "", outDir)
			entries, _ := expandFolder(containerPath, "", outDir)
			top := make([]string, 0, len(entries))
			for i, e := range entries {
				if i >= 50 {
					break
				}
				top = append(top, e.Name)
			}
			return toolResultJSON(map[string]any{
				"path":      containerPath,
				"mode":      mode,
				"url":       rawURL,
				"ref":       ref,
				"top_level": top,
				"note": "Analyze this like /src: pass `path` to grep/source_languages/source_dirs, " +
					"`dir` to the lang_* tools, and read files with read_local_file.",
			}, maxBytes, outDir)
		},
	)
}

// fetchDependency places the dependency source under destRoot and returns the
// fetch mode and the host path of the source root to analyze. Existing non-empty
// destinations are reused (idempotent across repeated calls in a session).
func fetchDependency(ctx context.Context, rawURL, ref, destRoot string) (mode, srcRootHost string, err error) {
	archive := isArchiveURL(rawURL)
	if fi, statErr := os.Stat(destRoot); statErr == nil && fi.IsDir() && dirNotEmpty(destRoot) {
		return "cached", resolveSrcRoot(destRoot, archive), nil
	}
	_ = os.RemoveAll(destRoot)

	if archive {
		if err := os.MkdirAll(destRoot, 0o755); err != nil {
			return "", "", err
		}
		tmp := filepath.Join(filepath.Dir(destRoot), ".dl-"+randomHex(8))
		if err := downloadFile(ctx, rawURL, tmp); err != nil {
			os.RemoveAll(destRoot)
			return "", "", err
		}
		defer os.Remove(tmp)
		if err := extractArchive(rawURL, tmp, destRoot); err != nil {
			os.RemoveAll(destRoot)
			return "", "", err
		}
		return "archive", resolveSrcRoot(destRoot, true), nil
	}

	if err := gitFetch(ctx, rawURL, ref, destRoot); err != nil {
		os.RemoveAll(destRoot)
		return "", "", err
	}
	return "git", destRoot, nil
}

func isArchiveURL(rawURL string) bool {
	p := strings.ToLower(rawURL)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	for _, ext := range archiveExts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return strings.HasSuffix(p, ".tar.xz") || strings.HasSuffix(p, ".txz") // detected, but rejected in extractArchive with a clear message
}

// checkURLAllowed rejects URLs whose host resolves to a non-public address
// (loopback, RFC1918, link-local incl. the cloud metadata endpoint, and IPv6
// equivalents).
func checkURLAllowed(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("url has no host")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return fmt.Errorf("cannot resolve host %s: %w", host, err)
	}
	for _, ip := range ips {
		if !isGlobalIP(ip) {
			return fmt.Errorf("host %s resolves to non-public address %s; refusing to fetch", host, ip)
		}
	}
	return nil
}

func isGlobalIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified())
}

func validGitRef(ref string) bool {
	return gitRefRe.MatchString(ref)
}

// downloadFile streams url to dest, capped at maxArchiveBytes.
func downloadFile(ctx context.Context, url, dest string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := depHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("downloading %s: HTTP %d", url, resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxArchiveBytes+1))
	if err != nil {
		return fmt.Errorf("saving download: %w", err)
	}
	if n > maxArchiveBytes {
		return fmt.Errorf("archive exceeds %d bytes; refusing", maxArchiveBytes)
	}
	return nil
}

// extractArchive unpacks the archive at file into destDir, dispatching on the
// URL's extension. Entry paths are sanitized against path traversal.
func extractArchive(rawURL, file, destDir string) error {
	p := strings.ToLower(rawURL)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	switch {
	case strings.HasSuffix(p, ".zip"):
		return extractZip(file, destDir)
	case strings.HasSuffix(p, ".tar.gz"), strings.HasSuffix(p, ".tgz"):
		return extractTar(file, destDir, "gzip")
	case strings.HasSuffix(p, ".tar.bz2"), strings.HasSuffix(p, ".tbz2"):
		return extractTar(file, destDir, "bzip2")
	case strings.HasSuffix(p, ".tar"):
		return extractTar(file, destDir, "none")
	case strings.HasSuffix(p, ".tar.xz"), strings.HasSuffix(p, ".txz"):
		return fmt.Errorf(".tar.xz is not supported; provide a .tar.gz or .zip URL instead")
	default:
		return fmt.Errorf("unrecognized archive type for %s", rawURL)
	}
}

func extractZip(file, destDir string) error {
	zr, err := zip.OpenReader(file)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer zr.Close()
	var budget extractBudget
	for _, f := range zr.File {
		target, ok := safeJoin(destDir, f.Name)
		if !ok {
			return fmt.Errorf("unsafe path in archive: %q", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			continue
		}
		if !f.Mode().IsRegular() {
			continue // skip symlinks and other special files
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		n, err := writeCapped(target, rc)
		rc.Close()
		if err != nil {
			return err
		}
		if err := budget.add(n); err != nil {
			return err
		}
	}
	return nil
}

func extractTar(file, destDir, compression string) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	switch compression {
	case "gzip":
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("opening gzip: %w", err)
		}
		defer gz.Close()
		r = gz
	case "bzip2":
		r = bzip2.NewReader(f)
	}

	tr := tar.NewReader(r)
	var budget extractBudget
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}
		target, ok := safeJoin(destDir, hdr.Name)
		if !ok {
			return fmt.Errorf("unsafe path in archive: %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			n, err := writeCapped(target, tr)
			if err != nil {
				return err
			}
			if err := budget.add(n); err != nil {
				return err
			}
		default:
			// skip symlinks, devices, fifos
		}
	}
	return nil
}

// writeCapped writes src to path, refusing to exceed maxArchiveBytes, and
// returns the number of bytes written.
func writeCapped(path string, src io.Reader) (int64, error) {
	out, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	n, err := io.Copy(out, io.LimitReader(src, maxArchiveBytes+1))
	if err != nil {
		return n, err
	}
	if n > maxArchiveBytes {
		return n, fmt.Errorf("extracted file %q exceeds %d bytes; refusing", filepath.Base(path), maxArchiveBytes)
	}
	return n, nil
}

// safeJoin joins name onto base, returning false if the result escapes base
// (zip-slip / tar traversal protection).
func safeJoin(base, name string) (string, bool) {
	target := filepath.Join(base, name)
	cleanBase := filepath.Clean(base)
	if target != cleanBase && !strings.HasPrefix(target, cleanBase+string(os.PathSeparator)) {
		return "", false
	}
	return target, true
}

// gitFetch clones rawURL into dest at the given ref. An empty ref clones the
// default branch shallowly; a tag/branch is fetched via --branch; anything else
// (e.g. a commit SHA) falls back to init + fetch + checkout.
func gitFetch(ctx context.Context, rawURL, ref, dest string) error {
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git is not installed on the host; pass an archive URL (.tar.gz / .zip) instead")
	}
	if ref == "" {
		return runGit(ctx, "", "clone", "--depth", "1", rawURL, dest)
	}
	// Tags and branches: shallow --branch clone.
	if err := runGit(ctx, "", "clone", "--depth", "1", "--branch", ref, rawURL, dest); err == nil {
		return nil
	}
	// Fallback for commit SHAs (and refs --branch can't name).
	_ = os.RemoveAll(dest)
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	if err := runGit(ctx, dest, "init", "-q"); err != nil {
		return err
	}
	if err := runGit(ctx, dest, "remote", "add", "origin", rawURL); err != nil {
		return err
	}
	if err := runGit(ctx, dest, "fetch", "--depth", "1", "origin", ref); err != nil {
		if err2 := runGit(ctx, dest, "fetch", "origin", ref); err2 != nil {
			return fmt.Errorf("git fetch %q: %w", ref, err)
		}
	}
	return runGit(ctx, dest, "checkout", "-q", "--detach", "FETCH_HEAD")
}

func runGit(ctx context.Context, dir string, args ...string) error {
	// Disable redirect-following and restrict the wire protocols to http(s).
	cfg := []string{
		"-c", "http.followRedirects=false",
		"-c", "protocol.allow=never",
		"-c", "protocol.https.allow=always",
		"-c", "protocol.http.allow=always",
	}
	// Route git through the validating proxy.
	if safeProxyURL != "" {
		cfg = append(cfg, "-c", "http.proxy="+safeProxyURL)
	}
	cmd := exec.CommandContext(ctx, "git", append(cfg, args...)...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=http:https")
	if dir != "" {
		cmd.Dir = dir
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		// Cap the surfaced output.
		msg := strings.TrimSpace(string(out))
		if len(msg) > 400 {
			msg = msg[:400] + "…(truncated)"
		}
		return fmt.Errorf("git %s: %v: %s", strings.Join(args, " "), err, msg)
	}
	return nil
}

// resolveSrcRoot collapses a single top-level directory (common in archives,
// e.g. "repo-1.2.3/") so the returned path points at the actual source root.
// Git checkouts are returned unchanged.
func resolveSrcRoot(destRoot string, archive bool) string {
	if !archive {
		return destRoot
	}
	entries, err := os.ReadDir(destRoot)
	if err != nil {
		return destRoot
	}
	if len(entries) == 1 && entries[0].IsDir() {
		return filepath.Join(destRoot, entries[0].Name())
	}
	return destRoot
}

func dirNotEmpty(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

// makeReadable best-effort chmods the tree world-readable/traversable.
func makeReadable(root string) {
	filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			os.Chmod(p, 0o755)
		} else {
			os.Chmod(p, 0o644)
		}
		return nil
	})
}

// depSlug derives a stable, filesystem-safe folder name from a URL and ref.
func depSlug(rawURL, ref string) string {
	s := rawURL
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimSuffix(s, ".git")
	if ref != "" {
		s += "@" + ref
	}
	slug := sanitizeSlug(s)
	if slug == "" {
		slug = "dep-" + randomHex(4)
	}
	const maxLen = 80
	if len(slug) > maxLen {
		slug = slug[len(slug)-maxLen:]
	}
	return slug
}

// sanitizeSlug keeps only path-safe characters, collapsing the rest to '-'.
func sanitizeSlug(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-', r == '@':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

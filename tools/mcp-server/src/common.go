// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Virtual path constants the agent sees; the server translates them to real paths.
const (
	containerSrcDir = "/src"
	containerOutDir = "/tool_output"
)

// GrepMatch represents a single line match from source code grep.
type GrepMatch struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Content string `json:"content"`
}

// DirEntry represents a single item in a directory listing.
type DirEntry struct {
	Name  string `json:"name"`
	Path  string `json:"path"`
	IsDir bool   `json:"is_directory"`
	Size  int64  `json:"size,omitempty"`
}

// resolvePath translates a virtual path (/src/..., /tool_output/...) to its
// real host equivalent, confined to the two roots.
func resolvePath(p, srcDir, outDir string) string {
	p = filepath.Clean(p)
	if p == containerSrcDir || strings.HasPrefix(p, containerSrcDir+"/") {
		return confine(srcDir, strings.TrimPrefix(p, containerSrcDir))
	}
	if p == containerOutDir || strings.HasPrefix(p, containerOutDir+"/") {
		return confine(outDir, strings.TrimPrefix(p, containerOutDir))
	}
	// Not in the virtual namespace: treat as relative to the source root.
	return confine(srcDir, p)
}

// confine joins rel onto root and guarantees the result stays inside root,
// both lexically and after resolving symlinks. Escaping paths degrade to root.
func confine(root, rel string) string {
	joined := filepath.Join(root, rel) // Join cleans the result
	if joined != root && !strings.HasPrefix(joined, root+string(filepath.Separator)) {
		return root
	}
	rootRes, err := filepath.EvalSymlinks(root)
	if err != nil {
		return joined
	}
	// Resolve the deepest existing ancestor of joined.
	probe := joined
	for {
		res, err := filepath.EvalSymlinks(probe)
		if err == nil {
			if res != rootRes && !strings.HasPrefix(res, rootRes+string(filepath.Separator)) {
				return root
			}
			return joined
		}
		if probe == root {
			return joined
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return joined
		}
		probe = parent
	}
}

// runGrep runs grep -rnE across files matching ext in the given virtual paths.
func runGrep(pattern, ext string, virtualDirs []string, limit, maxOutputBytes int, srcDir, outDir string) ([]GrepMatch, error) {
	perFileCap := limit * 2
	args := []string{
		"-rnE",
		"--exclude-dir=vendor",
		"--exclude-dir=.git",
		fmt.Sprintf("-m%d", perFileCap),
	}
	if ext = strings.TrimSpace(ext); ext != "" {
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		args = append(args, "--include=*"+ext)
	}
	// -e keeps a pattern starting with "-" from being read as a flag; "--" ends option parsing.
	args = append(args, "-e", pattern, "--")
	for _, d := range virtualDirs {
		args = append(args, resolvePath(d, srcDir, outDir))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "grep", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("grep timeout")
		} else {
			return nil, fmt.Errorf("grep: %w", runErr)
		}
	}
	if exitCode > 1 {
		return nil, fmt.Errorf("grep error (exit %d): %s", exitCode, strings.TrimSpace(stderr.String()))
	}

	var results []GrepMatch
	var approxBytes int
	for _, line := range strings.Split(stdout.String(), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		lineNum := 0
		fmt.Sscanf(parts[1], "%d", &lineNum)
		m := GrepMatch{
			File:    toContainerPath(parts[0], srcDir, outDir),
			Line:    lineNum,
			Content: strings.TrimSpace(parts[2]),
		}
		approxBytes += len(m.File) + len(m.Content) + 50
		results = append(results, m)
		if limit > 0 && len(results) >= limit {
			break
		}
		if maxOutputBytes > 0 && approxBytes >= maxOutputBytes {
			break
		}
	}
	return results, nil
}

// lineCount returns the total number of lines in a file. file is a virtual path.
func lineCount(file, srcDir, outDir string) (int, error) {
	data, err := os.ReadFile(resolvePath(file, srcDir, outDir))
	if err != nil {
		return 0, fmt.Errorf("could not read '%s': %w", file, err)
	}
	n := bytes.Count(data, []byte("\n"))
	if len(data) > 0 && data[len(data)-1] != '\n' {
		n++
	}
	return n, nil
}

// getSource reads source code lines from a file. file is a virtual path.
// Returns lines formatted as "NNNN | content".
func getSource(file string, startLine, endLine int, srcDir, outDir string) (string, error) {
	if startLine <= 0 || endLine < startLine {
		return "", fmt.Errorf("invalid line range %d-%d", startLine, endLine)
	}
	f, err := os.Open(resolvePath(file, srcDir, outDir))
	if err != nil {
		return "", fmt.Errorf("could not read '%s': %w", file, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	// Large cap for files with very long lines (minified bundles, generated JSON).
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum > endLine {
			break
		}
		if lineNum >= startLine {
			lines = append(lines, fmt.Sprintf("%4d | %s", lineNum, scanner.Text()))
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("reading '%s': %w", file, err)
	}
	if len(lines) == 0 {
		return "", fmt.Errorf("no lines found in range %d-%d", startLine, endLine)
	}
	return strings.Join(lines, "\n"), nil
}

// expandFolder lists the immediate children of a directory. dir is a virtual path.
// Returns sorted entries (directories first, then files) with virtual paths.
func expandFolder(dir, srcDir, outDir string) ([]DirEntry, error) {
	dir = strings.TrimRight(dir, "/")
	infos, err := os.ReadDir(resolvePath(dir, srcDir, outDir))
	if err != nil {
		return nil, fmt.Errorf("could not access '%s': %w", dir, err)
	}

	var entries []DirEntry
	for _, info := range infos {
		if info.Name() == ".git" {
			continue
		}
		var size int64
		if fi, err := info.Info(); err == nil && !info.IsDir() {
			size = fi.Size()
		}
		entries = append(entries, DirEntry{
			Name:  info.Name(),
			Path:  dir + "/" + info.Name(),
			IsDir: info.IsDir(),
			Size:  size,
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir != entries[j].IsDir {
			return entries[i].IsDir
		}
		return entries[i].Name < entries[j].Name
	})
	return entries, nil
}

// sourceExtCounts walks dir (a virtual path) and returns a map of lowercased
// file extension to file count, pruning VCS/dependency/build directories.
func sourceExtCounts(dir, srcDir, outDir string) (map[string]int, error) {
	realPath := resolvePath(dir, srcDir, outDir)
	prune := map[string]bool{
		".git": true, ".hg": true, ".svn": true, "node_modules": true,
		"vendor": true, ".venv": true, "venv": true, "__pycache__": true,
		".tox": true, "dist": true, "build": true, ".idea": true, ".vscode": true,
	}
	counts := map[string]int{}
	err := filepath.WalkDir(realPath, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() && prune[d.Name()] {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(d.Name()), "."))
			if ext != "" {
				counts[ext]++
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("could not scan '%s': %w", dir, err)
	}
	return counts, nil
}

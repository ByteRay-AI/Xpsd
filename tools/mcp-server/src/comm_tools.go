// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"sort"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// extLanguage maps a lowercased file extension (without the dot) to a
// human-readable source language.
var extLanguage = map[string]string{
	"c": "C", "h": "C/C++ header",
	"cc": "C++", "cpp": "C++", "cxx": "C++", "hpp": "C++", "hh": "C++", "hxx": "C++", "ipp": "C++",
	"go": "Go",
	"py": "Python", "pyi": "Python",
	"js": "JavaScript", "jsx": "JavaScript", "mjs": "JavaScript", "cjs": "JavaScript",
	"ts": "TypeScript", "tsx": "TypeScript",
	"java": "Java",
	"kt":   "Kotlin", "kts": "Kotlin",
	"rs":    "Rust",
	"rb":    "Ruby",
	"php":   "PHP",
	"cs":    "C#",
	"swift": "Swift",
	"m":     "Objective-C", "mm": "Objective-C++",
	"scala": "Scala",
	"sh":    "Shell", "bash": "Shell",
	"pl": "Perl", "pm": "Perl",
	"lua": "Lua",
	"sql": "SQL",
}

// sourceLanguageStat is one row of the source_languages report.
type sourceLanguageStat struct {
	Language string  `json:"language"`
	Files    int     `json:"files"`
	Percent  float64 `json:"percent"` // share of total scanned source files, by file count
}

// buildLanguageStats maps per-extension file counts (from sourceExtCounts) to
// per-language rows, dropping unrecognized extensions, and returns the rows
// sorted by descending file count plus the total of recognized source files.
func buildLanguageStats(extCounts map[string]int) ([]sourceLanguageStat, int) {
	langCounts := map[string]int{}
	total := 0
	for ext, n := range extCounts {
		lang, ok := extLanguage[ext]
		if !ok {
			continue
		}
		langCounts[lang] += n
		total += n
	}
	stats := make([]sourceLanguageStat, 0, len(langCounts))
	for lang, n := range langCounts {
		pct := 0.0
		if total > 0 {
			pct = float64(n) * 100 / float64(total)
		}
		stats = append(stats, sourceLanguageStat{Language: lang, Files: n, Percent: float64(int(pct*100+0.5)) / 100})
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].Files != stats[j].Files {
			return stats[i].Files > stats[j].Files
		}
		return stats[i].Language < stats[j].Language
	})
	return stats, total
}

func registerCommonTools(s *server.MCPServer, srcDir string, maxBytes int, outDir string) {
	s.AddTool(
		mcp.NewTool("grep",
			mcp.WithDescription(
				"Grep the analyzed project's source code using 'grep -rnE'. "+
					"Fast even on large codebases. "+
					"Returns absolute file path, line number, and matching line content "+
					"for each hit. Use the returned file + line with get_source "+
					"to view surrounding context. "+
					"Pattern uses POSIX extended regex syntax. "+
					"Use [Pp]attern or similar for case-insensitive matching.",
			),
			mcp.WithString("pattern",
				mcp.Required(),
				mcp.Description(
					"POSIX extended regex pattern "+
						"(e.g. 'func.*Parse', 'os\\.Exec', 'password|secret')",
				),
			),
			mcp.WithString("path",
				mcp.Description(
					"Optional path to search. Can be an absolute file (e.g. /src/lib/vtls/hostcheck.c) "+
						"or a directory (e.g. /src/lib/vtls). Defaults to /src (entire source tree).",
				),
			),
			mcp.WithNumber("limit",
				mcp.Description(
					"Max results to return (default: 100)",
				),
			),
			mcp.WithString("ext",
				mcp.Description(
					"File extension to search (default: '*'), leading dot is optional.",
				),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			pattern, perr := getStringArg(req, "pattern")
			if perr != nil {
				return mcp.NewToolResultError(perr.Error()), nil
			}
			limit := getIntArg(req, "limit", 100)
			if limit <= 0 {
				limit = 100
			}
			ext := getOptionalStringArg(req, "ext")
			if _, present := req.GetArguments()["ext"]; !present {
				ext = ""
			}
			if ext == "*" {
				ext = ""
			}

			searchPath := containerSrcDir
			if p := getOptionalStringArg(req, "path"); p != "" {
				searchPath = p
			}

			if srcDir == "" {
				return mcp.NewToolResultError("grep unavailable: server was started without -source <dir>"), nil
			}
			matches, err := runGrep(pattern, ext, []string{searchPath}, limit, maxBytes, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			truncated := limit > 0 && len(matches) >= limit
			return toolResultJSON(map[string]any{"matches": matches, "count": len(matches), "truncated": truncated}, maxBytes, outDir)
		},
	)

	s.AddTool(
		mcp.NewTool("read_local_file",
			mcp.WithDescription(
				"Read N lines from a file. "+
					"File paths are as returned by other tools. "+
					"Lines are prefixed with the line number ('NNNN | <content>').",
			),
			mcp.WithString("file",
				mcp.Required(),
				mcp.Description(
					"File path",
				),
			),
			mcp.WithNumber("line",
				mcp.Required(),
				mcp.Description("Start line number"),
			),
			mcp.WithNumber("end_line",
				mcp.Description(
					"End line number (optional — if omitted, reads 50 lines from the start line)",
				),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			file, err := getStringArg(req, "file")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			startLine := getIntArg(req, "line", 0)
			if startLine <= 0 {
				return mcp.NewToolResultError("'line' must be a positive integer"), nil
			}
			endLine := getIntArg(req, "end_line", 0)
			if endLine <= 0 {
				endLine = startLine + 50
			}

			source, err := getSource(file, startLine, endLine, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return toolResultJSON(map[string]any{
				"file":       file,
				"start_line": startLine,
				"end_line":   endLine,
				"source":     source,
			}, 0, outDir)
		},
	)

	s.AddTool(
		mcp.NewTool("get_line_count",
			mcp.WithDescription(
				"Returns the total number of lines in a file. "+
					"Accepts a file path as returned by other tools. "+
					"Useful for understanding file size before requesting read file ranges.",
			),
			mcp.WithString("file",
				mcp.Required(),
				mcp.Description(
					"File path",
				),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			file, err := getStringArg(req, "file")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			count, err := lineCount(file, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return toolResultJSON(map[string]any{"file": file, "lines": count}, maxBytes, outDir)
		},
	)

	s.AddTool(
		mcp.NewTool("expand_folder",
			mcp.WithDescription(
				"List the immediate contents of a directory. "+
					"Returns sorted entries (directories first, then files) "+
					"with file paths and sizes. "+
					"Use to explore project layout, find config files, test directories, "+
					"routing files, Dockerfiles, Makefiles, and other non-code files "+
					"relevant to vulnerability analysis. "+
					"Start with /src (from source_dirs) and drill down. Skips .git.",
			),
			mcp.WithString("path",
				mcp.Required(),
				mcp.Description(
					"Directory path to list (e.g. /src, /src/handlers)",
				),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			dir, err := getStringArg(req, "path")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			entries, err := expandFolder(dir, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return toolResultJSON(map[string]any{"path": dir, "entries": entries, "count": len(entries)}, maxBytes, outDir)
		},
	)

	s.AddTool(
		mcp.NewTool("source_dirs",
			mcp.WithDescription(
				"Returns a source root and its top-level entries. Defaults to /src (the "+
					"analyzed project). Pass a path returned by fetch_dependency_source to "+
					"explore a fetched dependency the same way. Use as the starting point for "+
					"expand_folder.",
			),
			mcp.WithString("path",
				mcp.Description("Optional directory to inspect (default: /src). e.g. a fetch_dependency_source path like /tool_output/deps/<name>."),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			path := containerSrcDir
			if p := getOptionalStringArg(req, "path"); p != "" {
				path = p
			}
			if path == containerSrcDir && srcDir == "" {
				return mcp.NewToolResultError("source_dirs unavailable: server was started without -source <dir>"), nil
			}
			entries, err := expandFolder(path, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return toolResultJSON(map[string]any{"source_dirs": []string{path}, "entries": entries}, maxBytes, outDir)
		},
	)

	s.AddTool(
		mcp.NewTool("source_languages",
			mcp.WithDescription(
				"Returns the programming languages used in a source tree, with the file count "+
					"and percentage (by file count) for each, sorted most-used first. Defaults to "+
					"/src (the analyzed project); pass a path returned by fetch_dependency_source "+
					"to profile a fetched dependency instead. Call this early to discover whether "+
					"the codebase is multi-language and to decide which language to pass to the "+
					"lang_* (ast-grep) tools.",
			),
			mcp.WithString("path",
				mcp.Description("Optional directory to scan (default: /src). e.g. a fetch_dependency_source path like /tool_output/deps/<name>."),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			path := containerSrcDir
			if p := getOptionalStringArg(req, "path"); p != "" {
				path = p
			}
			if path == containerSrcDir && srcDir == "" {
				return mcp.NewToolResultError("source_languages unavailable: server was started without -source <dir>"), nil
			}
			counts, err := sourceExtCounts(path, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			stats, total := buildLanguageStats(counts)
			return toolResultJSON(map[string]any{
				"path":        path,
				"languages":   stats,
				"total_files": total,
			}, maxBytes, outDir)
		},
	)

}

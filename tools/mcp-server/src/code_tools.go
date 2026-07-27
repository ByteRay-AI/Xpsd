// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"encoding/json"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func registerAstGrepTools(s *server.MCPServer, srcDir string, maxBytes int, outDir string) {
	if srcDir == "" {
		return
	}

	// ast-grep must be installed on the host.
	if _, err := exec.LookPath("ast-grep"); err != nil {
		return
	}

	s.AddTool(
		mcp.NewTool("lang_search_pattern",
			mcp.WithDescription(
				"ast-grep structural code search using AST pattern matching. "+
					"Use $NAME for single nodes, $$$ for variadic. "+
					"Example: '$FN($A, $B)' finds all two-argument calls. "+
					"For qualified calls like pkg.Func, use lang_find_calls instead.",
			),
			mcp.WithString("pattern",
				mcp.Required(),
				mcp.Description("AST pattern (e.g. '$FN($A, $B)', 'if $X != nil { return $X }')"),
			),
			mcp.WithString("lang",
				mcp.Description("Language (default: 'go'). Supports: go, python, javascript, typescript, rust, java, c, cpp, etc."),
			),
			mcp.WithString("dir",
				mcp.Description("Directory to search (default: project source root)"),
			),
			mcp.WithNumber("limit",
				mcp.Description("Max results (default: 50)"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			pattern, err := getStringArg(req, "pattern")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			lang := getOptionalStringArg(req, "lang")
			if lang == "" {
				lang = "go"
			}
			if !validLang(lang) {
				return mcp.NewToolResultError("invalid lang: use a plain language name (e.g. go, python, javascript, typescript, rust, java, c, cpp)"), nil
			}
			dir := getOptionalStringArg(req, "dir")
			if dir == "" {
				dir = containerSrcDir
			}
			limit := getIntArg(req, "limit", 50)

			results, err := runAstGrep(pattern, lang, dir, limit, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return astgrepResponse(results, limit, maxBytes, outDir, srcDir)
		},
	)

	s.AddTool(
		mcp.NewTool("lang_get_outline",
			mcp.WithDescription(
				"Extract top-level definitions (functions, methods, structs, interfaces) "+
					"from a file. Returns kind, name, and line for each definition.",
			),
			mcp.WithString("file",
				mcp.Required(),
				mcp.Description("File path as returned by other tools (e.g. /src/main.go)"),
			),
			mcp.WithString("lang",
				mcp.Description("Language (default: 'go')"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			file, err := getStringArg(req, "file")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			lang := getOptionalStringArg(req, "lang")
			if lang == "" {
				lang = "go"
			}
			if !validLang(lang) {
				return mcp.NewToolResultError("invalid lang: use a plain language name (e.g. go, python, javascript, typescript, rust, java, c, cpp)"), nil
			}

			entries, err := getOutline(file, lang, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if len(entries) == 0 {
				out, _ := json.Marshal(map[string]any{"definitions": []any{}, "count": 0, "file": file})
				return mcp.NewToolResultText(string(out)), nil
			}
			return toolResultJSON(map[string]any{"definitions": entries, "count": len(entries), "file": file}, maxBytes, outDir)
		},
	)

	s.AddTool(
		mcp.NewTool("lang_find_calls",
			mcp.WithDescription(
				"Find all call expressions matching a function name. "+
					"Works for both unqualified (e.g. 'append') and qualified calls "+
					"(e.g. 'fmt.Errorf', 'http.ListenAndServe').",
			),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Function name to find calls for (e.g. 'append', 'fmt.Sprintf', 'os.Exec')"),
			),
			mcp.WithString("lang",
				mcp.Description("Language (default: 'go')"),
			),
			mcp.WithString("dir",
				mcp.Description("Directory to search (default: /src)"),
			),
			mcp.WithNumber("limit",
				mcp.Description("Max results (default: 50)"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name, err := getStringArg(req, "name")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if !validSymbolName(name) {
				return mcp.NewToolResultError("invalid symbol name"), nil
			}
			lang := getOptionalStringArg(req, "lang")
			if lang == "" {
				lang = "go"
			}
			if !validLang(lang) {
				return mcp.NewToolResultError("invalid lang: use a plain language name (e.g. go, python, javascript, typescript, rust, java, c, cpp)"), nil
			}
			dir := getOptionalStringArg(req, "dir")
			if dir == "" {
				dir = containerSrcDir
			}
			limit := getIntArg(req, "limit", 50)

			results, err := findCalls(name, lang, dir, limit, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return astgrepResponse(results, limit, maxBytes, outDir, srcDir)
		},
	)

	s.AddTool(
		mcp.NewTool("lang_get_imports",
			mcp.WithDescription(
				"Extract import statements from a file. "+
					"Supports Go, Python, JS/TS, Rust, and Java.",
			),
			mcp.WithString("file",
				mcp.Required(),
				mcp.Description("File path as returned by other tools (e.g. /src/main.go)"),
			),
			mcp.WithString("lang",
				mcp.Description("Language (default: 'go')"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			file, err := getStringArg(req, "file")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			lang := getOptionalStringArg(req, "lang")
			if lang == "" {
				lang = "go"
			}
			if !validLang(lang) {
				return mcp.NewToolResultError("invalid lang: use a plain language name (e.g. go, python, javascript, typescript, rust, java, c, cpp)"), nil
			}

			entries, err := getImports(file, lang, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if len(entries) == 0 {
				out, _ := json.Marshal(map[string]any{"imports": []any{}, "count": 0, "file": file})
				return mcp.NewToolResultText(string(out)), nil
			}
			return toolResultJSON(map[string]any{"imports": entries, "count": len(entries), "file": file}, maxBytes, outDir)
		},
	)

	s.AddTool(
		mcp.NewTool("lang_find_strings",
			mcp.WithDescription(
				"ast-grep: find string literals matching a value or regex pattern. "+
					"Useful for finding hardcoded secrets, URLs, config values.",
			),
			mcp.WithString("pattern",
				mcp.Required(),
				mcp.Description(
					"String to search for. For exact match, use the full string "+
						"(e.g. 'password'). For substring/regex, any regex pattern "+
						"(e.g. 'api[_-]?key', 'https?://').",
				),
			),
			mcp.WithString("lang",
				mcp.Description("Language (default: 'go')"),
			),
			mcp.WithString("dir",
				mcp.Description("Directory to search (default: /src)"),
			),
			mcp.WithNumber("limit",
				mcp.Description("Max results (default: 50)"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			pattern, err := getStringArg(req, "pattern")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			lang := getOptionalStringArg(req, "lang")
			if lang == "" {
				lang = "go"
			}
			if !validLang(lang) {
				return mcp.NewToolResultError("invalid lang: use a plain language name (e.g. go, python, javascript, typescript, rust, java, c, cpp)"), nil
			}
			dir := getOptionalStringArg(req, "dir")
			if dir == "" {
				dir = containerSrcDir
			}
			limit := getIntArg(req, "limit", 50)

			results, err := findStrings(pattern, lang, dir, limit, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return astgrepResponse(results, limit, maxBytes, outDir, srcDir)
		},
	)

	s.AddTool(
		mcp.NewTool("lang_find_similar",
			mcp.WithDescription(
				"ast-grep: find structurally similar code blocks. Matches by AST structure, "+
					"ignoring whitespace and formatting differences. Supports $METAVAR placeholders. "+
					"Example: 'if err != nil { return err }' or 'if $X != nil { return $X }'.",
			),
			mcp.WithString("snippet",
				mcp.Required(),
				mcp.Description("Code snippet to search for (can include $METAVAR placeholders)"),
			),
			mcp.WithString("lang",
				mcp.Description("Language (default: 'go')"),
			),
			mcp.WithString("dir",
				mcp.Description("Directory to search (default: /src)"),
			),
			mcp.WithNumber("limit",
				mcp.Description("Max results (default: 50)"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			snippet, err := getStringArg(req, "snippet")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			lang := getOptionalStringArg(req, "lang")
			if lang == "" {
				lang = "go"
			}
			if !validLang(lang) {
				return mcp.NewToolResultError("invalid lang: use a plain language name (e.g. go, python, javascript, typescript, rust, java, c, cpp)"), nil
			}
			dir := getOptionalStringArg(req, "dir")
			if dir == "" {
				dir = containerSrcDir
			}
			limit := getIntArg(req, "limit", 50)

			results, err := runAstGrep(snippet, lang, dir, limit, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return astgrepResponse(results, limit, maxBytes, outDir, srcDir)
		},
	)

	s.AddTool(
		mcp.NewTool("lang_get_definition",
			mcp.WithDescription(
				"Find the definition of a symbol (function, type, struct, variable). "+
					"Searches the project source using language-aware AST patterns. "+
					"Best-effort: no cross-package type resolution.",
			),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Symbol name to find (e.g. 'handleRequest', 'CurlClass', 'DomainStatus')"),
			),
			mcp.WithString("lang",
				mcp.Description("Language (default: 'go'). Supports: go, c, cpp."),
			),
			mcp.WithString("dir",
				mcp.Description("Directory to search (default: /src)"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name, err := getStringArg(req, "name")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if !validSymbolName(name) {
				return mcp.NewToolResultError("invalid symbol name"), nil
			}
			lang := getOptionalStringArg(req, "lang")
			if lang == "" {
				lang = "go"
			}
			if !validLang(lang) {
				return mcp.NewToolResultError("invalid lang: use a plain language name (e.g. go, python, javascript, typescript, rust, java, c, cpp)"), nil
			}
			dir := getOptionalStringArg(req, "dir")
			if dir == "" {
				dir = containerSrcDir
			}

			defs, err := getDefinition(name, lang, dir, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if defs == nil {
				defs = []definitionResult{}
			}
			for i := range defs {
				defs[i].File = toContainerPath(defs[i].File, srcDir, outDir)
			}
			return toolResultJSON(map[string]any{"definitions": defs, "count": len(defs)}, maxBytes, outDir)
		},
	)

	s.AddTool(
		mcp.NewTool("lang_get_xrefs",
			mcp.WithDescription(
				"Find all references to a symbol (identifier) in the project source. "+
					"Matches AST identifier nodes only — skips comments and string literals. "+
					"Best-effort: no type resolution.",
			),
			mcp.WithString("name",
				mcp.Required(),
				mcp.Description("Symbol name to find references for (e.g. 'ParseConfig', 'curl_easy_setopt')"),
			),
			mcp.WithString("lang",
				mcp.Description("Language (default: 'go'). Supports: go, c, cpp."),
			),
			mcp.WithString("dir",
				mcp.Description("Directory to search (default: /src)"),
			),
			mcp.WithNumber("limit",
				mcp.Description("Max results (default: 100)"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name, err := getStringArg(req, "name")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if !validSymbolName(name) {
				return mcp.NewToolResultError("invalid symbol name"), nil
			}
			lang := getOptionalStringArg(req, "lang")
			if lang == "" {
				lang = "go"
			}
			if !validLang(lang) {
				return mcp.NewToolResultError("invalid lang: use a plain language name (e.g. go, python, javascript, typescript, rust, java, c, cpp)"), nil
			}
			dir := getOptionalStringArg(req, "dir")
			if dir == "" {
				dir = containerSrcDir
			}
			limit := getIntArg(req, "limit", 100)

			refs, err := getXrefs(name, lang, dir, limit, srcDir, outDir)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			if refs == nil {
				refs = []xrefResult{}
			}
			for i := range refs {
				refs[i].File = toContainerPath(refs[i].File, srcDir, outDir)
			}
			payload := map[string]any{
				"references": refs,
				"count":      len(refs),
			}
			if limit > 0 && len(refs) >= limit {
				payload["truncated"] = true
			}
			return toolResultJSON(payload, maxBytes, outDir)
		},
	)
}

// astgrepResponse marshals results into a JSON tool response, translating file
// paths to virtual paths for the agent.
func astgrepResponse(results []astgrepResult, limit int, maxBytes int, outDir string, srcDir string) (*mcp.CallToolResult, error) {
	matches := results
	if matches == nil {
		matches = []astgrepResult{}
	}
	for i := range matches {
		matches[i].File = toContainerPath(matches[i].File, srcDir, outDir)
	}
	payload := map[string]any{
		"matches": matches,
		"count":   len(matches),
	}
	if limit > 0 && len(results) >= limit {
		payload["truncated"] = true
	}
	return toolResultJSON(payload, maxBytes, outDir)
}

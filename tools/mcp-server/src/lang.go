// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// outlineEntry is the structured result of ast_get_outline.
type outlineEntry struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Line int    `json:"line"`
}

// importEntry is the structured result of ast_get_imports.
type importEntry struct {
	Line int    `json:"line"`
	Text string `json:"text"`
}

// astgrepMatch is the subset of ast-grep --json output we care about.
type astgrepMatch struct {
	Text  string `json:"text"`
	File  string `json:"file"`
	Lines string `json:"lines,omitempty"`
	Range struct {
		Start struct {
			Line   int `json:"line"`
			Column int `json:"column"`
		} `json:"start"`
		End struct {
			Line   int `json:"line"`
			Column int `json:"column"`
		} `json:"end"`
	} `json:"range"`
	MetaVariables struct {
		Single map[string]struct {
			Text string `json:"text"`
		} `json:"single"`
	} `json:"metaVariables"`
}

// astgrepResult is the compact output returned to the agent.
type astgrepResult struct {
	File     string            `json:"file"`
	Line     int               `json:"line"`
	EndLine  int               `json:"end_line,omitempty"`
	Text     string            `json:"text"`
	MetaVars map[string]string `json:"meta_vars,omitempty"`
}

type outlinePattern struct {
	kind         string
	pattern      string // direct ast-grep pattern (empty when using yamlRule)
	yamlRule     string // YAML rule content (used for C/C++/TS)
	nameFromText bool   // extract name from matched text when $NAME metavar is absent
}

// definitionResult is a structured result for get_definition.
type definitionResult struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Kind string `json:"kind"`
	Text string `json:"text"`
}

// xrefResult is a structured result for get_xrefs.
type xrefResult struct {
	File    string `json:"file"`
	Line    int    `json:"line"`
	Text    string `json:"text"`
	Context string `json:"context,omitempty"`
}

// extractNameFromFirstLine extracts the function/symbol name from the first
// line of a C/C++ definition text.
// langRe matches a plain language identifier.
var langRe = regexp.MustCompile(`^[a-z][a-z0-9+]{0,15}$`)

func extractNameFromFirstLine(text string) string {
	firstLine, _, _ := strings.Cut(text, "\n")
	if idx := strings.Index(firstLine, "("); idx >= 0 {
		before := strings.TrimRight(firstLine[:idx], " \t*")
		parts := strings.FieldsFunc(before, func(r rune) bool {
			return r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9')
		})
		if len(parts) > 0 {
			return parts[len(parts)-1]
		}
	}
	return ""
}

// runAstGrep runs `ast-grep run --pattern ... --lang ... --json` against the
// given virtual path (e.g. "/src/foo.go").
func runAstGrep(pattern, lang, targetPath string, limit int, srcDir, outDir string) ([]astgrepResult, error) {
	key := toolCacheKey("runAstGrep", pattern, lang, targetPath, limit)
	return cachedJSON(key, func() ([]astgrepResult, error) {
		resolved := resolvePath(targetPath, srcDir, outDir)
		args := []string{"ast-grep", "run", "--pattern", pattern, "--lang", lang, "--json", resolved}
		return execAstGrep(args, limit, srcDir, outDir)
	})
}

// runAstGrepYAML writes the YAML rule to outDir and runs `ast-grep scan --rule <path>`.
func runAstGrepYAML(ruleContent, targetPath string, limit int, srcDir, outDir string) ([]astgrepResult, error) {
	if outDir == "" {
		return nil, fmt.Errorf("runAstGrepYAML: outDir is required (rule file lives in /tool_output)")
	}
	key := toolCacheKey("runAstGrepYAML", ruleContent, targetPath, limit)
	return cachedJSON(key, func() ([]astgrepResult, error) {
		name := "astgrep-" + randomHex(8) + ".yml"
		hostPath := filepath.Join(outDir, name)
		if err := os.WriteFile(hostPath, []byte(ruleContent), 0o644); err != nil {
			return nil, fmt.Errorf("writing temp rule: %w", err)
		}
		defer os.Remove(hostPath)

		resolved := resolvePath(targetPath, srcDir, outDir)
		args := []string{"ast-grep", "scan", "--rule", hostPath, "--json", resolved}
		return execAstGrep(args, limit, srcDir, outDir)
	})
}

func execAstGrep(args []string, limit int, srcDir, outDir string) ([]astgrepResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("ast-grep timeout")
		} else {
			return nil, fmt.Errorf("ast-grep: %w", runErr)
		}
	}
	// ast-grep exits 1 when no matches; that's not an error.
	if exitCode != 0 && exitCode != 1 && len(strings.TrimSpace(stdout.String())) == 0 {
		return nil, fmt.Errorf("ast-grep error (exit %d): %s", exitCode, strings.TrimSpace(stderr.String()))
	}
	out := []byte(strings.TrimSpace(stdout.String()))
	if len(out) == 0 {
		return nil, nil
	}

	var rawMatches []astgrepMatch
	if err := json.Unmarshal(out, &rawMatches); err != nil {
		return nil, fmt.Errorf("parsing ast-grep output: %w", err)
	}

	results := make([]astgrepResult, 0, len(rawMatches))
	for _, m := range rawMatches {
		r := astgrepResult{
			File:    m.File,
			Line:    m.Range.Start.Line + 1,
			EndLine: m.Range.End.Line + 1,
			Text:    m.Text,
		}
		if len(m.MetaVariables.Single) > 0 {
			r.MetaVars = make(map[string]string, len(m.MetaVariables.Single))
			for k, v := range m.MetaVariables.Single {
				r.MetaVars[k] = v.Text
			}
		}
		results = append(results, r)
		if limit > 0 && len(results) >= limit {
			break
		}
	}
	return results, nil
}

// callsUseCStyleAST returns true for languages where ast-grep's variadic
// pattern ($$$) is unreliable for call_expression nodes.
func callsUseCStyleAST(lang string) bool {
	switch lang {
	case "c", "cpp":
		return true
	}
	return false
}

func outlinePatternsForLang(lang string) []outlinePattern {
	switch lang {
	case "go":
		return []outlinePattern{
			{kind: "function", pattern: "func $NAME($$$) $$${ $$$ }"},
			{kind: "struct", pattern: "type $NAME struct { $$$ }"},
			{kind: "interface", pattern: "type $NAME interface { $$$ }"},
		}
	case "python":
		return []outlinePattern{
			{kind: "function", pattern: "def $NAME($$$): $$$"},
			{kind: "function", pattern: "async def $NAME($$$): $$$"},
			{kind: "class", pattern: "class $NAME($$$): $$$"},
			{kind: "class", pattern: "class $NAME: $$$"},
		}
	case "javascript":
		return []outlinePattern{
			{kind: "function", pattern: "function $NAME($$$) { $$$ }"},
			{kind: "function", pattern: "async function $NAME($$$) { $$$ }"},
			{kind: "class", pattern: "class $NAME { $$$ }"},
			{kind: "arrow", pattern: "const $NAME = ($$$) => $$$"},
			{kind: "arrow", pattern: "const $NAME = async ($$$) => $$$"},
		}
	case "typescript":
		return []outlinePattern{
			{kind: "function", pattern: "function $NAME($$$) { $$$ }"},
			{kind: "function", pattern: "function $NAME($$$): $$$ { $$$ }"},
			{kind: "function", pattern: "async function $NAME($$$) { $$$ }"},
			{kind: "function", pattern: "async function $NAME($$$): $$$ { $$$ }"},
			{kind: "class", pattern: "class $NAME { $$$ }"},
			{kind: "interface", pattern: "interface $NAME { $$$ }"},
			{kind: "enum", pattern: "enum $NAME { $$$ }"},
			{kind: "type", pattern: "type $NAME = $$$"},
			{kind: "arrow", pattern: "const $NAME = ($$$) => $$$"},
			{kind: "arrow", pattern: "const $NAME = async ($$$) => $$$"},
		}
	case "rust":
		return []outlinePattern{
			{kind: "function", pattern: "fn $NAME($$$) $$${ $$$ }"},
			{kind: "function", pattern: "async fn $NAME($$$) $$${ $$$ }"},
			{kind: "function", pattern: "pub fn $NAME($$$) $$${ $$$ }"},
			{kind: "function", pattern: "pub async fn $NAME($$$) $$${ $$$ }"},
			{kind: "struct", pattern: "struct $NAME { $$$ }"},
			{kind: "struct", pattern: "pub struct $NAME { $$$ }"},
			{kind: "impl", pattern: "impl $NAME { $$$ }"},
			{kind: "enum", pattern: "enum $NAME { $$$ }"},
			{kind: "enum", pattern: "pub enum $NAME { $$$ }"},
			{kind: "trait", pattern: "trait $NAME { $$$ }"},
			{kind: "trait", pattern: "pub trait $NAME { $$$ }"},
			{kind: "type", pattern: "type $NAME = $$$;"},
		}
	case "java":
		return []outlinePattern{
			{kind: "class", pattern: "class $NAME { $$$ }"},
			{kind: "interface", pattern: "interface $NAME { $$$ }"},
			{kind: "enum", pattern: "enum $NAME { $$$ }"},
		}
	case "c":
		return []outlinePattern{
			{kind: "function", nameFromText: true, yamlRule: "id: outline\nlanguage: c\nrule:\n  kind: function_definition\n"},
			{kind: "struct", yamlRule: "id: outline\nlanguage: c\nrule:\n  kind: struct_specifier\n  has:\n    kind: type_identifier\n    field: name\n    pattern: $NAME\n"},
			{kind: "enum", yamlRule: "id: outline\nlanguage: c\nrule:\n  kind: enum_specifier\n  has:\n    kind: type_identifier\n    field: name\n    pattern: $NAME\n"},
			{kind: "typedef", nameFromText: true, yamlRule: "id: outline\nlanguage: c\nrule:\n  kind: type_definition\n"},
		}
	case "cpp":
		return []outlinePattern{
			{kind: "function", nameFromText: true, yamlRule: "id: outline\nlanguage: cpp\nrule:\n  kind: function_definition\n"},
			{kind: "class", yamlRule: "id: outline\nlanguage: cpp\nrule:\n  kind: class_specifier\n  has:\n    kind: type_identifier\n    field: name\n    pattern: $NAME\n"},
			{kind: "struct", yamlRule: "id: outline\nlanguage: cpp\nrule:\n  kind: struct_specifier\n  has:\n    kind: type_identifier\n    field: name\n    pattern: $NAME\n"},
			{kind: "enum", yamlRule: "id: outline\nlanguage: cpp\nrule:\n  kind: enum_specifier\n  has:\n    kind: type_identifier\n    field: name\n    pattern: $NAME\n"},
			{kind: "namespace", yamlRule: "id: outline\nlanguage: cpp\nrule:\n  kind: namespace_definition\n  has:\n    kind: namespace_identifier\n    field: name\n    pattern: $NAME\n"},
		}
	default:
		return []outlinePattern{
			{kind: "function", pattern: "func $NAME($$$) { $$$ }"},
		}
	}
}

func importPatternsForLang(lang string) []string {
	switch lang {
	case "go":
		return []string{
			"import ($$$)",
			`import "$PKG"`,
		}
	case "python":
		return []string{
			"import $MOD",
			"from $MOD import $$$",
		}
	case "javascript":
		return []string{
			"import $$$",
			"require($$$)",
		}
	case "typescript":
		return []string{
			"import $$$",
			"require($$$)",
		}
	case "rust":
		return []string{
			"use $$$;",
			"extern crate $$$;",
		}
	case "java":
		return []string{
			"import $$$;",
		}
	case "c", "cpp":
		return []string{
			"#include $$$",
		}
	default:
		return []string{
			"import $$$",
		}
	}
}

func stringLiteralKind(lang string) string {
	switch lang {
	case "go":
		return "interpreted_string_literal"
	case "python":
		return "string"
	case "javascript", "typescript":
		return "string"
	case "rust":
		return "string_literal"
	case "java":
		return "string_literal"
	case "c", "cpp":
		return "string_literal"
	default:
		return "string_literal"
	}
}

// stringLiteralKinds returns all AST node kinds that represent string literals
// for the given language.
func stringLiteralKinds(lang string) []string {
	switch lang {
	case "go":
		return []string{"interpreted_string_literal", "raw_string_literal"}
	case "javascript":
		return []string{"string", "template_string"}
	case "typescript":
		return []string{"string", "template_string"}
	default:
		return []string{stringLiteralKind(lang)}
	}
}

// definitionPatternsForLang returns YAML rules and direct patterns to find
// definitions of a named symbol in the given language.
func definitionPatternsForLang(name, lang string) []struct {
	kind     string
	yamlRule string
	pattern  string
} {
	escaped := yamlRegexBody(name)
	type pat struct {
		kind     string
		yamlRule string
		pattern  string
	}
	switch lang {
	case "go":
		return []struct {
			kind     string
			yamlRule string
			pattern  string
		}{
			{kind: "function", pattern: fmt.Sprintf("func %s($$$) $$${ $$$ }", name)},
			{kind: "method", yamlRule: fmt.Sprintf("id: def-method\nlanguage: go\nrule:\n  pattern: \"func ($$$) %s($$$) $$${ $$$ }\"\n", name)},
			{kind: "type", pattern: fmt.Sprintf("type %s struct { $$$ }", name)},
			{kind: "type", pattern: fmt.Sprintf("type %s interface { $$$ }", name)},
			{kind: "type", pattern: fmt.Sprintf("type %s = $$$", name)},
			{kind: "type", pattern: fmt.Sprintf("type %s $$$", name)},
			{kind: "var", pattern: fmt.Sprintf("var %s $$$", name)},
			{kind: "const", pattern: fmt.Sprintf("const %s $$$", name)},
		}
	case "python":
		return []struct {
			kind     string
			yamlRule string
			pattern  string
		}{
			{kind: "function", pattern: fmt.Sprintf("def %s($$$): $$$", name)},
			{kind: "function", pattern: fmt.Sprintf("async def %s($$$): $$$", name)},
			{kind: "class", pattern: fmt.Sprintf("class %s($$$): $$$", name)},
			{kind: "class", pattern: fmt.Sprintf("class %s: $$$", name)},
			{kind: "var", yamlRule: fmt.Sprintf("id: def-var\nlanguage: python\nrule:\n  kind: assignment\n  regex: '^%s\\s*='\n", escaped)},
		}
	case "javascript":
		return []struct {
			kind     string
			yamlRule string
			pattern  string
		}{
			{kind: "function", pattern: fmt.Sprintf("function %s($$$) { $$$ }", name)},
			{kind: "function", pattern: fmt.Sprintf("async function %s($$$) { $$$ }", name)},
			{kind: "class", pattern: fmt.Sprintf("class %s { $$$ }", name)},
			{kind: "var", yamlRule: fmt.Sprintf("id: def-const\nlanguage: javascript\nrule:\n  kind: variable_declarator\n  has:\n    field: name\n    pattern: \"%s\"\n", name)},
		}
	case "typescript":
		return []struct {
			kind     string
			yamlRule string
			pattern  string
		}{
			{kind: "function", pattern: fmt.Sprintf("function %s($$$) { $$$ }", name)},
			{kind: "function", pattern: fmt.Sprintf("function %s($$$): $$$ { $$$ }", name)},
			{kind: "function", pattern: fmt.Sprintf("async function %s($$$) { $$$ }", name)},
			{kind: "function", pattern: fmt.Sprintf("async function %s($$$): $$$ { $$$ }", name)},
			{kind: "class", pattern: fmt.Sprintf("class %s { $$$ }", name)},
			{kind: "interface", pattern: fmt.Sprintf("interface %s { $$$ }", name)},
			{kind: "type", pattern: fmt.Sprintf("type %s = $$$", name)},
			{kind: "enum", pattern: fmt.Sprintf("enum %s { $$$ }", name)},
			{kind: "var", yamlRule: fmt.Sprintf("id: def-const\nlanguage: typescript\nrule:\n  kind: variable_declarator\n  has:\n    field: name\n    pattern: \"%s\"\n", name)},
		}
	case "rust":
		return []struct {
			kind     string
			yamlRule string
			pattern  string
		}{
			{kind: "function", pattern: fmt.Sprintf("fn %s($$$) $$${ $$$ }", name)},
			{kind: "function", pattern: fmt.Sprintf("async fn %s($$$) $$${ $$$ }", name)},
			{kind: "function", pattern: fmt.Sprintf("pub fn %s($$$) $$${ $$$ }", name)},
			{kind: "function", pattern: fmt.Sprintf("pub async fn %s($$$) $$${ $$$ }", name)},
			{kind: "struct", pattern: fmt.Sprintf("struct %s { $$$ }", name)},
			{kind: "struct", pattern: fmt.Sprintf("pub struct %s { $$$ }", name)},
			{kind: "enum", pattern: fmt.Sprintf("enum %s { $$$ }", name)},
			{kind: "enum", pattern: fmt.Sprintf("pub enum %s { $$$ }", name)},
			{kind: "trait", pattern: fmt.Sprintf("trait %s { $$$ }", name)},
			{kind: "trait", pattern: fmt.Sprintf("pub trait %s { $$$ }", name)},
			{kind: "type", pattern: fmt.Sprintf("type %s = $$$;", name)},
		}
	case "c", "cpp":
		return []struct {
			kind     string
			yamlRule string
			pattern  string
		}{
			{kind: "function", yamlRule: fmt.Sprintf("id: def-func\nlanguage: %s\nrule:\n  kind: function_definition\n  has:\n    field: declarator\n    regex: '\\b%s\\b'\n", lang, escaped)},
			{kind: "function", yamlRule: fmt.Sprintf("id: def-func-decl\nlanguage: %s\nrule:\n  kind: declaration\n  regex: '\\b%s\\b'\n  has:\n    kind: function_declarator\n", lang, escaped)},
			{kind: "struct", yamlRule: fmt.Sprintf("id: def-struct\nlanguage: %s\nrule:\n  kind: struct_specifier\n  regex: '\\b%s\\b'\n", lang, escaped)},
			{kind: "type", yamlRule: fmt.Sprintf("id: def-typedef\nlanguage: %s\nrule:\n  kind: type_definition\n  regex: '\\b%s\\b'\n", lang, escaped)},
			{kind: "enum", yamlRule: fmt.Sprintf("id: def-enum\nlanguage: %s\nrule:\n  kind: enum_specifier\n  regex: '\\b%s\\b'\n", lang, escaped)},
		}
	default:
		return []struct {
			kind     string
			yamlRule string
			pattern  string
		}{
			{kind: "function", pattern: fmt.Sprintf("func %s($$$) $$${ $$$ }", name)},
		}
	}
}

// findCalls executes the ast_find_calls logic: finds all call expressions for
// the given function name in dir (virtual path).
func findCalls(name, lang, dir string, limit int, srcDir, outDir string) ([]astgrepResult, error) {
	var results []astgrepResult
	if callsUseCStyleAST(lang) {
		escaped := yamlRegexBody(name)
		rule := fmt.Sprintf(
			"id: find-calls\nlanguage: %s\nrule:\n  kind: call_expression\n  regex: '^%s'\n",
			lang, escaped,
		)
		all, err := runAstGrepYAML(rule, dir, 0, srcDir, outDir)
		if err != nil {
			return nil, err
		}
		for _, r := range all {
			if strings.HasPrefix(strings.TrimSpace(r.Text), name) {
				results = append(results, r)
				if limit > 0 && len(results) >= limit {
					break
				}
			}
		}
	} else if strings.Contains(name, ".") {
		escaped := yamlRegexBody(name)
		rule := fmt.Sprintf(
			"id: find-calls\nlanguage: %s\nrule:\n  pattern: $FN($$$ARGS)\n  regex: '^%s'\n",
			lang, escaped,
		)
		all, err := runAstGrepYAML(rule, dir, 0, srcDir, outDir)
		if err != nil {
			return nil, err
		}
		for _, r := range all {
			if strings.HasPrefix(strings.TrimSpace(r.Text), name) {
				results = append(results, r)
				if limit > 0 && len(results) >= limit {
					break
				}
			}
		}
	} else {
		var err error
		results, err = runAstGrep(name+"($$$)", lang, dir, limit, srcDir, outDir)
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

// getOutline executes the ast_get_outline logic: returns all top-level
// definitions in file (virtual path) using the patterns for lang.
func getOutline(file, lang string, srcDir, outDir string) ([]outlineEntry, error) {
	patterns := outlinePatternsForLang(lang)
	var entries []outlineEntry
	for _, p := range patterns {
		var results []astgrepResult
		var err error
		if p.yamlRule != "" {
			results, err = runAstGrepYAML(p.yamlRule, file, 500, srcDir, outDir)
		} else {
			results, err = runAstGrep(p.pattern, lang, file, 500, srcDir, outDir)
		}
		if err != nil {
			continue
		}
		for _, r := range results {
			name := ""
			if n, ok := r.MetaVars["NAME"]; ok {
				name = n
			} else if p.nameFromText && r.Text != "" {
				name = extractNameFromFirstLine(r.Text)
			}
			entries = append(entries, outlineEntry{Kind: p.kind, Name: name, Line: r.Line})
		}
	}
	return entries, nil
}

// getImports executes the ast_get_imports logic: returns all import statements
// in file (virtual path) using the patterns for lang.
func getImports(file, lang string, srcDir, outDir string) ([]importEntry, error) {
	patterns := importPatternsForLang(lang)
	var allResults []astgrepResult
	for _, p := range patterns {
		results, err := runAstGrep(p, lang, file, 200, srcDir, outDir)
		if err != nil {
			continue
		}
		allResults = append(allResults, results...)
	}
	entries := make([]importEntry, len(allResults))
	for i, r := range allResults {
		entries[i] = importEntry{Line: r.Line, Text: r.Text}
	}
	return entries, nil
}

// findStrings executes the ast_find_strings logic: finds string literals
// matching pattern (regex) in dir (virtual path) for the given language.
func findStrings(pattern, lang, dir string, limit int, srcDir, outDir string) ([]astgrepResult, error) {
	quoted := yamlSingleQuote(pattern)
	kinds := stringLiteralKinds(lang)
	var rule string
	if len(kinds) == 1 {
		rule = fmt.Sprintf(
			"id: find-strings\nlanguage: %s\nrule:\n  kind: %s\n  regex: %s\n",
			lang, kinds[0], quoted,
		)
	} else {
		anyItems := ""
		for _, k := range kinds {
			anyItems += fmt.Sprintf("    - kind: %s\n      regex: %s\n", k, quoted)
		}
		rule = fmt.Sprintf("id: find-strings\nlanguage: %s\nrule:\n  any:\n%s", lang, anyItems)
	}
	return runAstGrepYAML(rule, dir, limit, srcDir, outDir)
}

// yamlSingleQuote renders s as a YAML single-quoted scalar: single quotes are
// doubled and newlines/control characters are stripped.
func yamlSingleQuote(s string) string {
	return "'" + yamlSingleQuoteBody(s) + "'"
}

// yamlSingleQuoteBody escapes s for embedding INSIDE an existing single-quoted
// YAML scalar (no wrapping quotes): single quotes are doubled and
// newlines/control characters are stripped.
func yamlSingleQuoteBody(s string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || (r < 0x20 && r != '\t') {
			return -1
		}
		return r
	}, s)
	return strings.ReplaceAll(cleaned, "'", "''")
}

// yamlRegexBody regex-quotes an agent-supplied symbol name and makes it safe to
// embed inside a single-quoted YAML `regex:` scalar.
func yamlRegexBody(name string) string {
	return yamlSingleQuoteBody(regexp.QuoteMeta(name))
}

func validLang(lang string) bool { return langRe.MatchString(lang) }

// validSymbolName rejects characters a real symbol name never contains
// (quotes, backtick, backslash, control chars).
func validSymbolName(name string) bool {
	if name == "" || len(name) > 256 {
		return false
	}
	for _, r := range name {
		if r < 0x20 || r == '"' || r == '\'' || r == '`' || r == '\\' {
			return false
		}
	}
	return true
}

// getDefinition finds definition sites for a symbol name in the given directory.
func getDefinition(name, lang, dir string, srcDir, outDir string) ([]definitionResult, error) {
	pats := definitionPatternsForLang(name, lang)
	var defs []definitionResult
	seen := map[string]bool{}

	for _, p := range pats {
		var results []astgrepResult
		var err error
		if p.yamlRule != "" {
			results, err = runAstGrepYAML(p.yamlRule, dir, 50, srcDir, outDir)
		} else {
			results, err = runAstGrep(p.pattern, lang, dir, 50, srcDir, outDir)
		}
		if err != nil {
			continue
		}
		for _, r := range results {
			key := fmt.Sprintf("%s:%d", r.File, r.Line)
			if seen[key] {
				continue
			}
			seen[key] = true
			defs = append(defs, definitionResult{
				File: r.File,
				Line: r.Line,
				Kind: p.kind,
				Text: r.Text,
			})
		}
	}
	return defs, nil
}

// getXrefs finds all references to a symbol name in the given directory.
func getXrefs(name, lang, dir string, limit int, srcDir, outDir string) ([]xrefResult, error) {
	escaped := yamlRegexBody(name)

	var rule string
	switch lang {
	case "c", "cpp":
		rule = fmt.Sprintf(
			"id: xrefs\nlanguage: %s\nrule:\n  kind: identifier\n  regex: '^%s$'\n",
			lang, escaped,
		)
	case "go", "typescript":
		// Both Go and TypeScript use 'type_identifier' for type names alongside 'identifier'.
		rule = fmt.Sprintf(
			"id: xrefs\nlanguage: %s\nrule:\n  any:\n    - kind: identifier\n      regex: '^%s$'\n    - kind: type_identifier\n      regex: '^%s$'\n",
			lang, escaped, escaped,
		)
	case "python":
		// Python uses 'identifier' for all names.
		rule = fmt.Sprintf(
			"id: xrefs\nlanguage: python\nrule:\n  kind: identifier\n  regex: '^%s$'\n",
			escaped,
		)
	case "javascript":
		// JavaScript uses 'identifier' and 'property_identifier' for method names.
		rule = fmt.Sprintf(
			"id: xrefs\nlanguage: javascript\nrule:\n  any:\n    - kind: identifier\n      regex: '^%s$'\n    - kind: property_identifier\n      regex: '^%s$'\n",
			escaped, escaped,
		)
	case "rust":
		rule = fmt.Sprintf(
			"id: xrefs\nlanguage: rust\nrule:\n  any:\n    - kind: identifier\n      regex: '^%s$'\n    - kind: type_identifier\n      regex: '^%s$'\n",
			escaped, escaped,
		)
	default:
		rule = fmt.Sprintf(
			"id: xrefs\nlanguage: %s\nrule:\n  kind: identifier\n  regex: '^%s$'\n",
			lang, escaped,
		)
	}

	results, err := runAstGrepYAML(rule, dir, limit, srcDir, outDir)
	if err != nil {
		return nil, err
	}

	xrefs := make([]xrefResult, len(results))
	for i, r := range results {
		xrefs[i] = xrefResult{
			File: r.File,
			Line: r.Line,
			Text: r.Text,
		}
	}
	return xrefs, nil
}

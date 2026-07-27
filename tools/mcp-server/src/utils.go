// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

func getStringArg(req mcp.CallToolRequest, key string) (string, error) {
	val := mcp.ParseArgument(req, key, "")
	s, ok := val.(string)
	if !ok || s == "" {
		return "", fmt.Errorf("'%s' parameter is required", key)
	}
	return s, nil
}

func getOptionalStringArg(req mcp.CallToolRequest, key string) string {
	val := mcp.ParseArgument(req, key, "")
	s, _ := val.(string)
	return s
}

func getIntArg(req mcp.CallToolRequest, key string, defaultVal int) int {
	val := mcp.ParseArgument(req, key, float64(defaultVal))
	switch v := val.(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return defaultVal
}

// toContainerPath converts an absolute host path to its virtual path equivalent.
// srcDir maps to /src; outDir maps to /tool_output.
// Paths that don't start with either prefix are returned unchanged.
func toContainerPath(path, srcDir, outDir string) string {
	if srcDir != "" {
		base := strings.TrimRight(srcDir, "/")
		if path == base {
			return containerSrcDir
		}
		if strings.HasPrefix(path, base+"/") {
			return containerSrcDir + "/" + path[len(base)+1:]
		}
	}
	if outDir != "" {
		base := strings.TrimRight(outDir, "/")
		if path == base {
			return containerOutDir
		}
		if strings.HasPrefix(path, base+"/") {
			return containerOutDir + "/" + path[len(base)+1:]
		}
	}
	return path
}

// randomHex returns a random lowercase hex string of n bytes (2n chars).
func randomHex(n int) string {
	buf := make([]byte, n)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

// toolResultRawOrFile returns pre-marshaled JSON as a tool result.
// When data exceeds maxBytes, it writes to a temp file in outDir and returns
// the path as JSON.
func toolResultRawOrFile(data []byte, maxBytes int, outDir string) (*mcp.CallToolResult, error) {
	if maxBytes > 0 && len(data) > maxBytes {
		dir := outDir
		if dir == "" {
			dir = os.TempDir()
		}
		path := filepath.Join(dir, "result-"+randomHex(8)+".json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("writing large result: %v", err)), nil
		}
		lines := bytes.Count(data, []byte("\n"))
		ref, _ := json.Marshal(map[string]any{
			"file":  containerOutDir + "/" + filepath.Base(path),
			"bytes": len(data),
			"lines": lines,
			"note":  "result too large for inline response — read it with read_local_file, or pass the file path to grep to match just the parts you need",
		})
		return mcp.NewToolResultText(string(ref)), nil
	}
	return mcp.NewToolResultText(string(data)), nil
}

// toolResultJSON marshals v to indented JSON and delegates to toolResultRaw.
func toolResultJSON(v any, maxBytes int, outDir string) (*mcp.CallToolResult, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("marshaling result: %v", err)), nil
	}
	return toolResultRawOrFile(data, maxBytes, outDir)
}

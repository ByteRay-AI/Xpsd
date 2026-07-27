// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// fetch_url returns a web page as readable markdown.

// webFetchTimeout bounds a single render request to the service.
const webFetchTimeout = 150 * time.Second

func registerWebTools(s *server.MCPServer, webFetcherURL string, maxBytes int, outDir string) {
	base := strings.TrimRight(webFetcherURL, "/")
	client := &http.Client{Timeout: webFetchTimeout}

	s.AddTool(
		mcp.NewTool("fetch_url",
			mcp.WithDescription(
				"Fetch a web page and return its readable text as markdown. The page is "+
					"fully rendered with a headless browser (JavaScript is executed), then "+
					"converted to clean markdown — headings, paragraphs, lists, code blocks, "+
					"tables, and links preserved; navigation, scripts, styles, and images "+
					"stripped. Use it to read CVE references: advisories, bug trackers, "+
					"mailing-list posts, vendor bulletins, commit pages.",
			),
			mcp.WithString("url",
				mcp.Required(),
				mcp.Description("Absolute http:// or https:// URL"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			raw, err := getStringArg(req, "url")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			target := strings.TrimSpace(raw)
			if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
				return mcp.NewToolResultError("url must start with http:// or https://"), nil
			}
			md, err := renderViaService(ctx, client, base, target)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return toolResultRawOrFile([]byte(md), maxBytes, outDir)
		},
	)
}

// renderViaService POSTs the URL to the web-fetcher service and returns the
// markdown it renders.
func renderViaService(ctx context.Context, client *http.Client, base, target string) (string, error) {
	body, _ := json.Marshal(map[string]string{"url": target})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/render", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("building render request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("web-fetcher unreachable: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return "", fmt.Errorf("reading render response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("web-fetcher error (%d): %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if strings.TrimSpace(string(data)) == "" {
		return "", fmt.Errorf("web-fetcher returned no text for %s", target)
	}
	return string(data), nil
}

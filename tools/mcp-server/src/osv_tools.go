// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// osvBaseURL is the OSV.dev REST API base.
const osvBaseURL = "https://api.osv.dev"

// osvHTTPClient talks to the fixed api.osv.dev host and refuses redirects to
// non-public addresses.
var osvHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return checkURLAllowed(req.URL.String())
	},
}

// registerOSVTools adds osv_get_vuln, which fetches the full OSV.dev advisory
// for a known vulnerability id.
func registerOSVTools(s *server.MCPServer, maxBytes int, outDir string) {
	s.AddTool(
		mcp.NewTool("osv_get_vuln",
			mcp.WithDescription(
				"Fetch the full OSV.dev record for a known vulnerability id (e.g. a CVE, "+
					"GHSA, GO, PYSEC, or RUSTSEC id). Returns the structured advisory: summary, "+
					"details, affected packages with version ranges, severity, and references. "+
					"Use this to learn exactly which component/versions a CVE affects before "+
					"deciding whether the code is present in the target.",
			),
			mcp.WithString("id",
				mcp.Required(),
				mcp.Description("Vulnerability id, e.g. CVE-2021-44228, GHSA-jfh8-c2jp-5v3q"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			id, err := getStringArg(req, "id")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			id = strings.TrimSpace(id)
			if id == "" {
				return mcp.NewToolResultError("'id' must not be empty"), nil
			}
			body, err := osvGet(ctx, osvBaseURL+"/v1/vulns/"+url.PathEscape(id))
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			return toolResultJSON(body, maxBytes, outDir)
		},
	)
}

// osvGet issues a GET to the OSV API and returns the decoded JSON body.
func osvGet(ctx context.Context, endpoint string) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("building OSV request: %w", err)
	}
	resp, err := osvHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV request failed: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20)) // cap at 8 MB
	if err != nil {
		return nil, fmt.Errorf("reading OSV response: %w", err)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("OSV: not found (404)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var out any
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parsing OSV response: %w", err)
	}
	return out, nil
}

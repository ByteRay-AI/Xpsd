// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MCPRPCRequest is a JSON-RPC 2.0 request to an MCP server.
type MCPRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *int        `json:"id,omitempty"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// MCPRPCError is the error object inside a JSON-RPC 2.0 response.
type MCPRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCPRPCResponse is a JSON-RPC 2.0 response from an MCP server.
type MCPRPCResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *MCPRPCError    `json:"error"`
}

// MCPToolDef is one tool advertised by the MCP server.
type MCPToolDef struct {
	Name        string
	Description string
	InputSchema map[string]any
}

// MCPClient holds an initialized MCP session and calls tools over it.
type MCPClient struct {
	url       string
	sessionID string
	http      *http.Client

	mu     sync.Mutex
	nextID int
}

// ExcludedTools is the standard set of built-in tools excluded from sessions.
var ExcludedTools = []string{
	"view", "edit", "create", "glob", "grep", "rg",
	"bash", "shell", "run_command",
	"edit_file", "create_file", "write_file", "read_file",
	"report_intent", "ask_user", "task",
}

// DoMCPRPC sends a single JSON-RPC request to the MCP server and returns the
// response together with the (potentially updated) session ID.
func DoMCPRPC(ctx context.Context, client *http.Client, mcpURL string, payload MCPRPCRequest, sessionID string) (*MCPRPCResponse, string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshal MCP request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mcpURL, strings.NewReader(string(body)))
	if err != nil {
		return nil, "", fmt.Errorf("create MCP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("MCP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return nil, "", fmt.Errorf("MCP request returned status %d", resp.StatusCode)
	}

	newSessionID := sessionID
	if hdr := resp.Header.Get("Mcp-Session-Id"); hdr != "" {
		newSessionID = hdr
	}

	var rpcResp MCPRPCResponse
	if resp.StatusCode == http.StatusAccepted {
		return &rpcResp, newSessionID, nil
	}
	if err := json.NewDecoder(resp.Body).Decode(&rpcResp); err != nil {
		return nil, "", fmt.Errorf("decode MCP response: %w", err)
	}
	return &rpcResp, newSessionID, nil
}

// FetchMCPTools connects to the MCP server, performs the initialize handshake,
// and returns the list of available tool names.
func FetchMCPTools(ctx context.Context, mcpURL string) ([]string, error) {
	client := &http.Client{Timeout: 5 * time.Second}

	initID := 1
	initReq := MCPRPCRequest{
		JSONRPC: "2.0",
		ID:      &initID,
		Method:  "initialize",
		Params: map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo": map[string]string{
				"name":    "mcp-cli",
				"version": "1.0",
			},
		},
	}
	initResp, sessionID, err := DoMCPRPC(ctx, client, mcpURL, initReq, "")
	if err != nil {
		return nil, err
	}
	if initResp.Error != nil {
		return nil, fmt.Errorf("initialize failed: %s", initResp.Error.Message)
	}

	if _, _, err := DoMCPRPC(ctx, client, mcpURL, MCPRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
		Params:  map[string]any{},
	}, sessionID); err != nil {
		return nil, err
	}

	listID := 2
	listResp, _, err := DoMCPRPC(ctx, client, mcpURL, MCPRPCRequest{
		JSONRPC: "2.0",
		ID:      &listID,
		Method:  "tools/list",
		Params:  map[string]any{},
	}, sessionID)
	if err != nil {
		return nil, err
	}
	if listResp.Error != nil {
		return nil, fmt.Errorf("tools/list failed: %s", listResp.Error.Message)
	}

	var parsed struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(listResp.Result, &parsed); err != nil {
		return nil, fmt.Errorf("parsing tools/list response: %w", err)
	}

	tools := make([]string, 0, len(parsed.Tools))
	for _, t := range parsed.Tools {
		if t.Name == "" {
			continue
		}
		tools = append(tools, t.Name)
	}
	if len(tools) == 0 {
		return nil, fmt.Errorf("tools/list returned no tools")
	}
	return tools, nil
}

// NewMCPClient performs the initialize handshake and returns a client ready to
// list and call tools.
func NewMCPClient(ctx context.Context, mcpURL string, timeout time.Duration) (*MCPClient, error) {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	c := &MCPClient{url: mcpURL, http: &http.Client{Timeout: timeout}, nextID: 1}

	id := c.id()
	initResp, sessionID, err := DoMCPRPC(ctx, c.http, mcpURL, MCPRPCRequest{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "initialize",
		Params: map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]string{"name": "xpsd", "version": "1.0"},
		},
	}, "")
	if err != nil {
		return nil, err
	}
	if initResp.Error != nil {
		return nil, fmt.Errorf("initialize failed: %s", initResp.Error.Message)
	}
	c.sessionID = sessionID

	if _, _, err := DoMCPRPC(ctx, c.http, mcpURL, MCPRPCRequest{
		JSONRPC: "2.0",
		Method:  "notifications/initialized",
		Params:  map[string]any{},
	}, c.sessionID); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *MCPClient) id() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	return c.nextID
}

// ListTools returns every tool the server advertises, with its input schema.
func (c *MCPClient) ListTools(ctx context.Context) ([]MCPToolDef, error) {
	id := c.id()
	resp, _, err := DoMCPRPC(ctx, c.http, c.url, MCPRPCRequest{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "tools/list",
		Params:  map[string]any{},
	}, c.sessionID)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("tools/list failed: %s", resp.Error.Message)
	}

	var parsed struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &parsed); err != nil {
		return nil, fmt.Errorf("parsing tools/list response: %w", err)
	}

	defs := make([]MCPToolDef, 0, len(parsed.Tools))
	for _, t := range parsed.Tools {
		if t.Name == "" {
			continue
		}
		schema := t.InputSchema
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		defs = append(defs, MCPToolDef{Name: t.Name, Description: t.Description, InputSchema: schema})
	}
	if len(defs) == 0 {
		return nil, fmt.Errorf("tools/list returned no tools")
	}
	return defs, nil
}

// CallTool invokes one tool and returns its text content.
func (c *MCPClient) CallTool(ctx context.Context, name string, args any) (string, error) {
	if args == nil {
		args = map[string]any{}
	}
	id := c.id()
	resp, _, err := DoMCPRPC(ctx, c.http, c.url, MCPRPCRequest{
		JSONRPC: "2.0",
		ID:      &id,
		Method:  "tools/call",
		Params:  map[string]any{"name": name, "arguments": args},
	}, c.sessionID)
	if err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", fmt.Errorf("%s", resp.Error.Message)
	}

	var out struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(resp.Result, &out); err != nil {
		return string(resp.Result), nil
	}
	var sb strings.Builder
	for _, part := range out.Content {
		if part.Text != "" {
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(part.Text)
		}
	}
	if out.IsError {
		return "", fmt.Errorf("%s", sb.String())
	}
	return sb.String(), nil
}

// CheckMCP sends an MCP initialize request to verify the server is reachable.
func CheckMCP(mcpURL string) error {
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-healthcheck","version":"1.0"}}}`
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(mcpURL, "application/json", strings.NewReader(body))
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}

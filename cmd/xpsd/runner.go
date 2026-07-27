// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"fmt"
	"log"
	"time"

	copilot "github.com/github/copilot-sdk/go"
)

// SessionOpts configures a single-run LLM session.
type SessionOpts struct {
	MCPURL          string
	TargetPath      string
	Model           string
	ReasoningEffort string
	ProviderType    string
	BaseURL         string
	APIKey          string
	Timeout         time.Duration
	MaxCycles       int
	MaxResultKB     int
	Verbose         bool
	StrictReact     bool
	NoReact         bool
	// Budgets passed to the ReactEnforcer (0 = unlimited).
	MaxTokens int // deny tool calls when context tokens >= MaxTokens
	// ToolTimeout is the per-tool-call MCP timeout passed to the session config.
	ToolTimeout int
	// UsageOut is optionally filled with session usage statistics after the
	// session completes.
	UsageOut *SessionUsage
	// Logger captures structured per-event session data (tool calls, assistant
	// messages, ReAct violations). When nil, RunSession falls back to a basic
	// stderr-only event printer.
	Logger Logger
}

// RunSession creates a Copilot session with the given system prompt and user
// message, registers the MCP server's tools on it, and runs a single
// send-and-wait. Returns the assistant's text reply.
//
// The session is fitted with a ReactEnforcer: cycle-budget cap (opts.MaxCycles),
// per-tool result truncation (opts.MaxResultKB), duplicate-call detection, and
// Thought-before-Action nudges.
func RunSession(ctx context.Context, client *copilot.Client, opts SessionOpts, systemPrompt, userMessage string) (string, error) {
	// Tools are proxied in-process, exposed under the exact names below.
	mcpClient, err := NewMCPClient(ctx, opts.MCPURL, time.Duration(opts.ToolTimeout)*time.Millisecond)
	if err != nil {
		return "", fmt.Errorf("connecting to MCP server: %w", err)
	}
	defs, err := mcpClient.ListTools(ctx)
	if err != nil {
		return "", fmt.Errorf("listing MCP tools: %w", err)
	}
	vlog("discovered %d MCP tools from %s:", len(defs), opts.MCPURL)

	tools := make([]copilot.Tool, 0, len(defs))
	toolNamesAllowed := make([]string, 0, len(defs))
	for _, d := range defs {
		vlog("  • %s", d.Name)
		name := d.Name
		tools = append(tools, copilot.Tool{
			Name:                 name,
			Description:          d.Description,
			Parameters:           d.InputSchema,
			SkipPermission:       true,
			OverridesBuiltInTool: true,
			Handler: func(inv copilot.ToolInvocation) (copilot.ToolResult, error) {
				out, cerr := mcpClient.CallTool(ctx, name, inv.Arguments)
				if cerr != nil {
					return copilot.ToolResult{Error: cerr.Error(), ResultType: "error"}, nil
				}
				return copilot.ToolResult{TextResultForLLM: out, ResultType: "text"}, nil
			},
		})
		toolNamesAllowed = append(toolNamesAllowed, name)
	}
	SetAnalysisTools(toolNamesAllowed)

	var react *ReactEnforcer
	if !opts.NoReact {
		react = NewReactEnforcer(opts.Logger, ReactEnforcerOpts{
			Strict:         opts.StrictReact,
			MaxCycles:      opts.MaxCycles,
			MaxResultBytes: opts.MaxResultKB * 1024,
			MaxTokens:      opts.MaxTokens,
		})
	}

	sessionCfg := &copilot.SessionConfig{
		Model:               opts.Model,
		ReasoningEffort:     opts.ReasoningEffort,
		OnPermissionRequest: copilot.PermissionHandler.ApproveAll,
		SystemMessage: &copilot.SystemMessageConfig{
			Mode:    "replace",
			Content: systemPrompt,
		},
		Tools:          tools,
		AvailableTools: toolNamesAllowed,
	}

	if react != nil {
		sessionCfg.Hooks = react.Hooks()
	}

	if opts.ProviderType != "" {
		key := ResolveAPIKey(opts.ProviderType, opts.APIKey)
		sessionCfg.Provider = &copilot.ProviderConfig{
			Type:    opts.ProviderType,
			BaseURL: opts.BaseURL,
			APIKey:  key,
		}
		if sessionCfg.Model == "" {
			sessionCfg.Model = DefaultModel(opts.ProviderType)
		}
	}

	session, err := client.CreateSession(ctx, sessionCfg)
	if err != nil {
		return "", fmt.Errorf("creating session: %w", err)
	}
	defer session.Disconnect()

	if react != nil {
		session.On(react.EventHandler())
	}

	if opts.Logger != nil {
		session.On(opts.Logger.Hook())
	} else {
		toolNames := map[string]string{}
		modelLogged := false
		session.On(func(event copilot.SessionEvent) {
			switch d := event.Data.(type) {
			case *copilot.AssistantIntentData:
				vlog("  💭 %s", d.Intent)
			case *copilot.SessionMCPServersLoadedData:
				for _, s := range d.Servers {
					msg := ""
					if s.Error != nil {
						msg = ": " + *s.Error
					}
					vlog("  🔌 MCP server %q: %s%s", s.Name, s.Status, msg)
				}
			case *copilot.SessionMCPServerStatusChangedData:
				msg := ""
				if d.Error != nil {
					msg = ": " + *d.Error
				}
				vlog("  🔌 MCP server %q -> %s%s", d.ServerName, d.Status, msg)
			case *copilot.ToolExecutionStartData:
				toolNames[d.ToolCallID] = d.ToolName
				if d.Model != nil && !modelLogged {
					modelLogged = true
					vlog("  session model: %s", *d.Model)
				}
				vlog("  🔧 %s%s%s", d.ToolName, mcpTag(d.ToolName), argsSummary(d.Arguments))
			case *copilot.ToolExecutionCompleteData:
				name := toolNames[d.ToolCallID]
				delete(toolNames, d.ToolCallID)
				if !d.Success {
					if name != "" {
						log.Printf("  ❌ tool call %s (%s) failed", name, d.ToolCallID)
					} else {
						log.Printf("  ❌ tool call %s failed", d.ToolCallID)
					}
				}
			case *copilot.SessionErrorData:
				log.Printf("  ❌ session error: %s", d.Message)
			}
		})
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	vlog("sending prompt (%d bytes)…", len(userMessage))
	reply, err := session.SendAndWait(timeoutCtx, copilot.MessageOptions{Prompt: userMessage})
	if err != nil {
		return "", fmt.Errorf("LLM call: %w", err)
	}

	var content string
	if reply != nil {
		if d, ok := reply.Data.(*copilot.AssistantMessageData); ok {
			content = d.Content
		}
	}

	if react != nil && opts.UsageOut != nil {
		usage := react.Usage()
		*opts.UsageOut = usage
	}

	if content == "" {
		return "", fmt.Errorf("empty response from agent")
	}
	return content, nil
}

// RunText runs a single tool-less LLM turn: no MCP server, no tools, no ReAct
// enforcement, the model can only produce text. Used for the markdown
// rendering pass that turns the verdict JSON into a report.
func RunText(ctx context.Context, client *copilot.Client, opts SessionOpts, systemPrompt, userMessage string) (string, error) {
	sessionCfg := &copilot.SessionConfig{
		Model:               opts.Model,
		ReasoningEffort:     opts.ReasoningEffort,
		OnPermissionRequest: copilot.PermissionHandler.ApproveAll,
		AvailableTools:      []string{},
		SystemMessage: &copilot.SystemMessageConfig{
			Mode:    "replace",
			Content: systemPrompt,
		},
	}
	if opts.ProviderType != "" {
		key := ResolveAPIKey(opts.ProviderType, opts.APIKey)
		sessionCfg.Provider = &copilot.ProviderConfig{
			Type:    opts.ProviderType,
			BaseURL: opts.BaseURL,
			APIKey:  key,
		}
		if sessionCfg.Model == "" {
			sessionCfg.Model = DefaultModel(opts.ProviderType)
		}
	}

	session, err := client.CreateSession(ctx, sessionCfg)
	if err != nil {
		return "", fmt.Errorf("creating render session: %w", err)
	}
	defer session.Disconnect()
	if opts.Logger != nil {
		session.On(opts.Logger.Hook())
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	timeoutCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	reply, err := session.SendAndWait(timeoutCtx, copilot.MessageOptions{Prompt: userMessage})
	if err != nil {
		return "", fmt.Errorf("render LLM call: %w", err)
	}
	var content string
	if reply != nil {
		if d, ok := reply.Data.(*copilot.AssistantMessageData); ok {
			content = d.Content
		}
	}
	if content == "" {
		return "", fmt.Errorf("empty response from render agent")
	}
	return content, nil
}

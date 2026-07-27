// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"strings"
	"time"
)

// orientationTools are the calls every analysis opens with. They return the
// same bytes for every finding in a run, so paying a model turn for each one,
// for each finding, buys nothing.
var orientationTools = []string{"source_languages", "source_dirs"}

// maxOrientationBytes caps the injected block. Orientation is a shortcut, not a
// second copy of the tree; anything larger and the model should go look itself.
const maxOrientationBytes = 4000

// GatherOrientation calls the orientation tools once and renders their results
// as text to inject into the analysis prompt. Every finding in a run then starts
// already knowing the project layout instead of spending a turn per tool to
// rediscover it.
//
// Returns "" when the MCP server cannot be reached or every call fails, in which
// case the prompt falls back to telling the model to gather it itself.
func GatherOrientation(ctx context.Context, mcpURL string, toolTimeout time.Duration) string {
	client, err := NewMCPClient(ctx, mcpURL, toolTimeout)
	if err != nil {
		vlog("orientation: MCP unavailable, the agent will gather it itself: %v", err)
		return ""
	}

	var sb strings.Builder
	for _, tool := range orientationTools {
		out, err := client.CallTool(ctx, tool, map[string]any{})
		if err != nil {
			vlog("orientation: %s failed: %v", tool, err)
			continue
		}
		out = strings.TrimSpace(out)
		if out == "" {
			continue
		}
		sb.WriteString("### " + tool + "\n\n")
		sb.WriteString(out)
		sb.WriteString("\n\n")
	}

	block := strings.TrimSpace(sb.String())
	if block == "" {
		return ""
	}
	if len(block) > maxOrientationBytes {
		block = block[:maxOrientationBytes] + "\n… (truncated; call the tool yourself for the rest)"
	}
	vlog("orientation: gathered %d bytes from %s, injected into every prompt this run",
		len(block), strings.Join(orientationTools, " and "))
	return block
}

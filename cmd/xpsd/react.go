// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"unicode/utf8"

	copilot "github.com/github/copilot-sdk/go"
)

const (
	defaultMaxResultBytes = 32 * 1024 // 32 KB per tool result
	truncateTolerance     = 0.05      // skip truncation if result is within 5% of limit
	wrapUpBuffer          = 5         // cycles before max to start nudging wrap-up
)

// SessionUsage holds usage statistics for a completed agent session.
type SessionUsage struct {
	Tokens   float64 // context-window tokens consumed (last reported value)
	Requests int     // number of LLM turns (AssistantTurnEnd events)
}

// ReactEnforcerOpts configures the ReactEnforcer.
type ReactEnforcerOpts struct {
	Strict         bool
	MaxCycles      int // 0 = unlimited
	MaxResultBytes int // 0 = use defaultMaxResultBytes
	MaxTokens      int // 0 = unlimited; deny tool calls when context tokens >= MaxTokens
}

// ReactPhase tracks where we are in the Thought→Action→Observation cycle.
type ReactPhase int

const (
	PhaseThought     ReactPhase = iota // expecting a Thought before next Action
	PhaseAction                        // Thought seen, expecting tool call
	PhaseObservation                   // tool done, expecting Observation summary
)

// ReactEnforcer ensures the agent follows the ReAct cycle, manages the
// per-session context budget, truncates oversized tool results, and detects
// duplicate tool calls.
type ReactEnforcer struct {
	mu             sync.Mutex
	cycle          int
	phase          ReactPhase
	sawThought     bool
	nudges         int
	denials        int
	truncations    int
	dedupSkips     int
	strict         bool
	maxCycles      int
	maxResultBytes int
	seenCalls      map[string]int // "toolName:argsJSON" → cycle when first seen
	logger         Logger

	// Real token counts from session.usage_info events.
	currentTokens float64
	tokenLimit    float64

	// LLM turn counter, incremented on AssistantTurnEndData.
	requests int

	// Per-stage budgets (0 = unlimited).
	maxTokensPerStage int
}

func NewReactEnforcer(logger Logger, opts ReactEnforcerOpts) *ReactEnforcer {
	maxResultBytes := opts.MaxResultBytes
	if maxResultBytes <= 0 {
		maxResultBytes = defaultMaxResultBytes
	}
	return &ReactEnforcer{
		cycle:             0,
		phase:             PhaseThought,
		strict:            opts.Strict,
		maxCycles:         opts.MaxCycles,
		maxResultBytes:    maxResultBytes,
		seenCalls:         make(map[string]int),
		logger:            logger,
		maxTokensPerStage: opts.MaxTokens,
	}
}

// Hooks returns the SessionHooks that enforce the ReAct cycle.
func (r *ReactEnforcer) Hooks() *copilot.SessionHooks {
	return &copilot.SessionHooks{
		OnUserPromptSubmitted: r.onUserPrompt,
		OnPreToolUse:          r.onPreToolUse,
		OnPostToolUse:         r.onPostToolUse,
	}
}

// EventHandler returns a session event handler for tracking model output.
// Wire this into session.On() alongside the logger hook.
func (r *ReactEnforcer) EventHandler() copilot.SessionEventHandler {
	return func(event copilot.SessionEvent) {
		r.mu.Lock()
		defer r.mu.Unlock()

		switch d := event.Data.(type) {
		case *copilot.AssistantIntentData:
			r.sawThought = true
			r.logger.Log("react_thought", map[string]any{
				"cycle":  r.cycle,
				"source": "intent",
				"intent": d.Intent,
			})

		case *copilot.AssistantReasoningData:
			r.sawThought = true
			r.logger.Log("react_thought", map[string]any{
				"cycle":  r.cycle,
				"source": "reasoning",
			})

		case *copilot.AssistantMessageData:
			r.detectCycleMarkers(d.Content)

		case *copilot.AssistantTurnEndData:
			r.phase = PhaseThought
			r.sawThought = false
			r.requests++

		case *copilot.SessionUsageInfoData:
			r.currentTokens = float64(d.CurrentTokens)
			r.tokenLimit = float64(d.TokenLimit)
		}
	}
}

// detectCycleMarkers scans assistant text for explicit ReAct markers.
func (r *ReactEnforcer) detectCycleMarkers(content string) {
	if ContainsAny(content, "**Thought:**", "Thought:", "[Cycle") {
		r.sawThought = true
	}
	if ContainsAny(content, "**Observation:**", "Observation:") {
		r.phase = PhaseThought
	}
}

// onUserPrompt injects the ReAct framework reminder and cycle budget info.
func (r *ReactEnforcer) onUserPrompt(
	input copilot.UserPromptSubmittedHookInput,
	inv copilot.HookInvocation,
) (*copilot.UserPromptSubmittedHookOutput, error) {
	r.mu.Lock()
	r.cycle = 1
	r.phase = PhaseThought
	r.sawThought = false
	r.seenCalls = make(map[string]int)
	r.mu.Unlock()

	r.logger.Log("react_cycle_start", map[string]any{"cycle": 1})

	ctx := "IMPORTANT: Follow the Thought→Action→Observation cycle. " +
		"Before calling any tool, state your **Thought** (what you want to learn and why). " +
		"After each tool result, state your **Observation** (what you learned). " +
		"Number each cycle: [Cycle 1], [Cycle 2], etc."

	if r.maxCycles > 0 {
		ctx += fmt.Sprintf(
			" You have a budget of %d tool-call cycles. Be surgical: gather just enough "+
				"evidence rather than aiming for exhaustive coverage, and produce your final "+
				"answer as soon as you have it.",
			r.maxCycles,
		)
	}

	return &copilot.UserPromptSubmittedHookOutput{AdditionalContext: ctx}, nil
}

// onPreToolUse fires before each tool execution.
// Enforces the cycle limit, detects duplicate calls, and checks for Thought.
func (r *ReactEnforcer) onPreToolUse(
	input copilot.PreToolUseHookInput,
	inv copilot.HookInvocation,
) (*copilot.PreToolUseHookOutput, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := &copilot.PreToolUseHookOutput{}

	if r.maxCycles > 0 && r.cycle > r.maxCycles {
		r.denials++
		r.logger.Log("react_cycle_limit", map[string]any{
			"cycle": r.cycle, "max": r.maxCycles, "tool_name": input.ToolName,
		})
		vlog("  %s🛑 ReAct: cycle limit reached (%d/%d), denying %s",
			r.logger.Prefix(), r.cycle, r.maxCycles, input.ToolName)
		out.PermissionDecision = "deny"
		out.PermissionDecisionReason = fmt.Sprintf(
			"Cycle limit reached (%d/%d). Produce your final answer now based on the "+
				"evidence gathered so far. Do not make further tool calls.",
			r.cycle, r.maxCycles,
		)
		return out, nil
	}

	if r.maxTokensPerStage > 0 && r.currentTokens >= float64(r.maxTokensPerStage) {
		r.denials++
		r.logger.Log("react_token_limit", map[string]any{
			"tokens": r.currentTokens, "max_tokens": r.maxTokensPerStage, "tool_name": input.ToolName,
		})
		vlog("  %s🛑 Token limit reached (%.0f/%d tokens used), denying %s",
			r.logger.Prefix(), r.currentTokens, r.maxTokensPerStage, input.ToolName)
		out.PermissionDecision = "deny"
		out.PermissionDecisionReason = fmt.Sprintf(
			"Token budget reached (%.0f/%d tokens used). Produce your final answer now "+
				"based on the evidence gathered so far. Do not make further tool calls.",
			r.currentTokens, r.maxTokensPerStage,
		)
		return out, nil
	}

	callKey := callCacheKey(input.ToolName, input.ToolArgs)
	if prevCycle, seen := r.seenCalls[callKey]; seen {
		r.dedupSkips++
		r.logger.Log("react_dedup", map[string]any{
			"cycle": r.cycle, "prev_cycle": prevCycle, "tool_name": input.ToolName,
		})
		vlog("  %s🔁 ReAct: duplicate call to %s (already called in cycle %d)",
			r.logger.Prefix(), input.ToolName, prevCycle)
		if r.strict {
			r.denials++
			out.PermissionDecision = "deny"
			out.PermissionDecisionReason = fmt.Sprintf(
				"You already called %q with the same arguments in cycle %d. "+
					"Reuse that result — do not re-fetch the same data.",
				input.ToolName, prevCycle,
			)
			return out, nil
		}
		out.AdditionalContext = fmt.Sprintf(
			"[ReAct Enforcer] You already called %q with identical arguments in cycle %d. "+
				"Reuse that result instead of making the same call again.",
			input.ToolName, prevCycle,
		)
	} else {
		r.seenCalls[callKey] = r.cycle
	}

	if !r.sawThought {
		r.nudges++
		r.logger.Log("react_violation", map[string]any{
			"cycle": r.cycle, "tool_name": input.ToolName,
			"violation": "missing_thought", "strict": r.strict, "nudge": r.nudges,
		})
		vlog("  %s⚠️ ReAct: no Thought before %s (cycle %d)",
			r.logger.Prefix(), input.ToolName, r.cycle)
		if r.strict {
			r.denials++
			out.PermissionDecision = "deny"
			out.PermissionDecisionReason = fmt.Sprintf(
				"Tool call denied: state your **Thought:** reasoning before calling %q. "+
					"Explain what you want to learn and why, then retry the tool call.",
				input.ToolName,
			)
		} else {
			out.AdditionalContext = fmt.Sprintf(
				"[ReAct Enforcer] You are calling tool %q without stating a Thought first. "+
					"In your next response, please start with **Thought:** explaining your reasoning "+
					"before the next tool call. Current cycle: %d.",
				input.ToolName, r.cycle,
			)
		}
	} else {
		r.logger.Log("react_action", map[string]any{
			"cycle": r.cycle, "tool_name": input.ToolName,
		})
	}

	r.phase = PhaseAction
	return out, nil
}

// onPostToolUse fires after each tool execution.
// Truncates oversized results and injects the Observation prompt plus any
// cycle-budget warnings.
func (r *ReactEnforcer) onPostToolUse(
	input copilot.PostToolUseHookInput,
	inv copilot.HookInvocation,
) (*copilot.PostToolUseHookOutput, error) {
	r.mu.Lock()
	r.phase = PhaseObservation
	r.sawThought = false
	cycle := r.cycle // the call that just completed
	r.cycle++
	remaining := 0
	if r.maxCycles > 0 {
		remaining = r.maxCycles - cycle
	}
	// Snapshot token state under the lock; the SDK event goroutine updates these concurrently.
	curTokens := r.currentTokens
	tokLimit := r.tokenLimit
	r.mu.Unlock()

	out := &copilot.PostToolUseHookOutput{}

	if modified, origBytes, wasTruncated := TruncateMCPResult(input.ToolResult, r.maxResultBytes); wasTruncated {
		r.mu.Lock()
		r.truncations++
		r.mu.Unlock()
		r.logger.Log("react_result_truncated", map[string]any{
			"cycle": cycle, "tool_name": input.ToolName,
			"orig_bytes": origBytes, "max_bytes": r.maxResultBytes,
		})
		vlog("  %s✂️ ReAct: truncated %s result (%d → %d bytes)",
			r.logger.Prefix(), input.ToolName, origBytes, r.maxResultBytes)
		out.ModifiedResult = modified
	}

	if cycle > 0 && cycle%3 == 0 {
		var progressLine string
		if tokLimit > 0 {
			pct := curTokens / tokLimit * 100
			remaining := tokLimit - curTokens
			progressLine = fmt.Sprintf(
				"📊 Context: %.0f/%.0f tokens used (%.1f%%), ~%.0f tokens remaining | Cycle %d/%d",
				curTokens, tokLimit, pct, remaining, cycle, r.maxCycles,
			)
		} else if r.maxCycles > 0 {
			pct := float64(cycle) / float64(r.maxCycles) * 100
			progressLine = fmt.Sprintf(
				"📊 Context: cycle %d/%d (%.0f%%) — token data pending",
				cycle, r.maxCycles, pct,
			)
		}

		if progressLine != "" {
			vlog("  %s%s", r.logger.Prefix(), progressLine)
			r.logger.Log("context_progress", map[string]any{
				"cycle":          cycle,
				"current_tokens": curTokens,
				"token_limit":    tokLimit,
				"max_cycles":     r.maxCycles,
			})
		}
	}

	var sb strings.Builder
	fmt.Fprintf(&sb,
		"[Cycle %d complete] Now write your **Observation** summarizing what this "+
			"tool result revealed. Then state your next **Thought** with your hypothesis "+
			"for the next step, or a **Conclusion** if you have enough evidence.",
		cycle,
	)

	if r.maxCycles > 0 {
		switch {
		case remaining <= 0:
			sb.WriteString(
				"\n\n🛑 CONTEXT BUDGET EXHAUSTED: Produce your final answer NOW " +
					"based on evidence gathered so far. Do not make further tool calls.",
			)
		case remaining <= wrapUpBuffer:
			fmt.Fprintf(&sb,
				"\n\n⚠️ CONTEXT BUDGET: Only %d tool call(s) remaining (%d/%d used). "+
					"Start wrapping up — consolidate and produce your final answer "+
					"within the next cycle or two.",
				remaining, cycle, r.maxCycles,
			)
		}
	}

	if r.maxTokensPerStage > 0 {
		tokenPct := curTokens / float64(r.maxTokensPerStage) * 100
		if tokenPct >= 90 {
			tokRemaining := float64(r.maxTokensPerStage) - curTokens
			fmt.Fprintf(&sb,
				"\n\n⚠️ TOKEN BUDGET: %.0f%% used (%.0f/%d tokens, ~%.0f remaining). "+
					"Start consolidating and produce your final answer soon.",
				tokenPct, curTokens, r.maxTokensPerStage, tokRemaining,
			)
		}
	}

	out.AdditionalContext = sb.String()

	r.logger.Log("react_observation_prompt", map[string]any{
		"cycle": cycle, "tool_name": input.ToolName,
	})

	return out, nil
}

// Usage returns the token and request usage for the completed session.
func (r *ReactEnforcer) Usage() SessionUsage {
	r.mu.Lock()
	defer r.mu.Unlock()
	return SessionUsage{Tokens: r.currentTokens, Requests: r.requests}
}

// TruncateMCPResult truncates an oversized tool result to maxBytes.
// Returns (modifiedResult, originalBytes, wasTruncated).
func TruncateMCPResult(result any, maxBytes int) (any, int, bool) {
	if result == nil {
		return result, 0, false
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return result, 0, false
	}

	// Extract only the text the LLM sees; the SDK ToolResult carries duplicate copies in multiple fields.
	var r struct {
		TextResultForLLM string `json:"textResultForLlm"`
		Contents         []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"contents"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	primaryText := ""
	if json.Unmarshal(resultJSON, &r) == nil {
		primaryText = r.TextResultForLLM
		if primaryText == "" {
			for _, c := range r.Contents {
				if c.Type == "text" {
					primaryText += c.Text
				}
			}
		}
		if primaryText == "" {
			for _, c := range r.Content {
				if c.Type == "text" {
					primaryText += c.Text
				}
			}
		}
	}

	if primaryText == "" {
		origLen := len(resultJSON)
		tolerance := int(float64(maxBytes) * truncateTolerance)
		if origLen <= maxBytes+tolerance {
			return result, origLen, false
		}
		tail := fmt.Sprintf(
			"...[TRUNCATED: showing %d of %d bytes. Use more specific queries for focused results.]",
			maxBytes, origLen,
		)
		return string(resultJSON[:maxBytes]) + tail, origLen, true
	}

	origLen := len(primaryText)
	tolerance := int(float64(maxBytes) * truncateTolerance)
	if origLen <= maxBytes+tolerance {
		return result, origLen, false
	}

	budget := maxBytes
	if budget < 256 {
		budget = 256
	}
	head := truncateUTF8(primaryText, budget)
	truncated := head + fmt.Sprintf(
		"\n\n[TRUNCATED: showing %d of %d bytes. "+
			"Use a more specific symbol name or narrower query to get focused results.]",
		len(head), origLen,
	)

	if r.TextResultForLLM != "" {
		return map[string]any{
			"textResultForLlm": truncated,
			"resultType":       "success",
		}, origLen, true
	}
	return map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": truncated},
		},
	}, origLen, true
}

// callCacheKey builds a deduplication key from tool name and arguments.
func callCacheKey(toolName string, args any) string {
	argsJSON, _ := json.Marshal(args)
	return toolName + ":" + string(argsJSON)
}

// truncateUTF8 cuts s to at most max bytes without splitting a multi-byte
// rune. Strings under the limit are returned unchanged; truncated strings
// carry no marker (callers add their own).
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// ContainsAny reports whether s contains any of the given substrings.
func ContainsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

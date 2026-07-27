// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	copilot "github.com/github/copilot-sdk/go"
)

// verboseEnabled gates progress logging. Set once at startup, before any
// session goroutine reads it. Errors, warnings, and the final verdict are
// printed regardless.
var verboseEnabled bool

// analysisTools holds the tool names Xpsd exposes for the current session, so
// the log can distinguish them from the runtime's own tools.
var (
	analysisToolsMu sync.RWMutex
	analysisTools   map[string]bool
)

// Logger is the interface satisfied by both SessionLogger (file-backed) and
// any alternative implementation (e.g. a database-backed logger).
type Logger interface {
	Log(event string, data any)
	Close()
	Hook() func(copilot.SessionEvent)
	Prefix() string
}

// SessionLogger writes structured JSON-lines logs for each session.
//
// Stage is optional: when set, the human-readable log lines emitted via Hook()
// are prefixed with `[STAGE]`.
type SessionLogger struct {
	file  *os.File
	enc   *json.Encoder
	Stage string // optional label for the session, e.g. "xpsd"
}

// LogEntry is a single line in the session log.
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
	Data      any    `json:"data,omitempty"`
}

// SetVerbose enables progress logging.
func SetVerbose(v bool) { verboseEnabled = v }

// vlog prints a progress line only in verbose mode.
func vlog(format string, args ...any) {
	if verboseEnabled {
		log.Printf(format, args...)
	}
}

// argsSummary renders tool-call arguments as compact JSON, truncated.
func argsSummary(args any) string {
	if args == nil {
		return ""
	}
	b, err := json.Marshal(args)
	if err != nil || len(b) == 0 || string(b) == "null" {
		return ""
	}
	s := string(b)
	if len(s) > 100 {
		s = truncateUTF8(s, 100) + "…"
	}
	return " " + s
}

// SetAnalysisTools records the tool names Xpsd registered for this session.
func SetAnalysisTools(names []string) {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	analysisToolsMu.Lock()
	analysisTools = set
	analysisToolsMu.Unlock()
}

// mcpTag marks tools that are not the ones Xpsd registered.
func mcpTag(name string) string {
	analysisToolsMu.RLock()
	known := analysisTools[name]
	analysisToolsMu.RUnlock()
	if known {
		return ""
	}
	return " [builtin]"
}

// Prefix returns "[STAGE] " for log lines, or "" when Stage is not set.
func (sl *SessionLogger) Prefix() string {
	if sl == nil || sl.Stage == "" {
		return ""
	}
	return "[" + sl.Stage + "] "
}

// NewNamedSessionLogger creates a JSONL log file in dir. The optional name is
// used as a filename prefix; when empty the filename is timestamp-only.
func NewNamedSessionLogger(dir, name string) (*SessionLogger, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("creating log dir: %v", err)
	}

	ts := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("session_%s.jsonl", ts)
	if name != "" {
		filename = fmt.Sprintf("%s_%s.jsonl", name, ts)
	}
	path := filepath.Join(dir, filename)

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("creating log file: %v", err)
	}

	sl := &SessionLogger{
		file: f,
		enc:  json.NewEncoder(f),
	}
	sl.Log("session_start", map[string]string{"log_file": path})

	vlog("  📁 Session log: %s", path)
	return sl, nil
}

// Log writes a single entry.
func (sl *SessionLogger) Log(event string, data any) {
	if sl == nil {
		return
	}
	sl.enc.Encode(LogEntry{
		Timestamp: time.Now().Format(time.RFC3339Nano),
		Event:     event,
		Data:      data,
	})
}

// Close flushes and closes the log file.
func (sl *SessionLogger) Close() {
	if sl == nil {
		return
	}
	sl.Log("session_end", nil)
	sl.file.Close()
}

// Hook returns a session event handler that logs all events.
func (sl *SessionLogger) Hook() func(copilot.SessionEvent) {
	// ToolExecutionCompleteData doesn't carry the tool name; remembered from the matching StartData.
	toolNames := map[string]string{}
	modelLogged := false
	return func(event copilot.SessionEvent) {
		switch d := event.Data.(type) {

		case *copilot.AssistantTurnStartData:
			sl.Log("turn_start", map[string]string{
				"turn_id": d.TurnID,
			})

		case *copilot.AssistantIntentData:
			sl.Log("intent", map[string]string{
				"intent": d.Intent,
			})
			vlog("  %s💭 %s", sl.Prefix(), d.Intent)

		case *copilot.AssistantReasoningData:
			sl.Log("reasoning", map[string]string{
				"reasoning_id": d.ReasoningID,
				"content":      d.Content,
			})

		case *copilot.SessionMCPServersLoadedData:
			for _, s := range d.Servers {
				msg := ""
				if s.Error != nil {
					msg = ": " + *s.Error
				}
				transport := ""
				if s.Transport != nil {
					transport = string(*s.Transport)
				}
				sl.Log("mcp_server_loaded", map[string]any{
					"name": s.Name, "status": string(s.Status),
					"transport": transport, "error": msg,
				})
				vlog("  %s🔌 MCP server %q: %s %s%s", sl.Prefix(), s.Name, s.Status, transport, msg)
			}

		case *copilot.SessionMCPServerStatusChangedData:
			msg := ""
			if d.Error != nil {
				msg = ": " + *d.Error
			}
			sl.Log("mcp_server_status", map[string]any{
				"name": d.ServerName, "status": string(d.Status), "error": msg,
			})
			vlog("  %s🔌 MCP server %q -> %s%s", sl.Prefix(), d.ServerName, d.Status, msg)

		case *copilot.ToolExecutionStartData:
			toolNames[d.ToolCallID] = d.ToolName
			if d.Model != nil && !modelLogged {
				modelLogged = true
				vlog("  %ssession model: %s", sl.Prefix(), *d.Model)
			}
			entry := map[string]any{
				"tool_call_id": d.ToolCallID,
				"tool_name":    d.ToolName,
				"arguments":    d.Arguments,
			}
			if d.Model != nil {
				entry["model"] = *d.Model
			}
			sl.Log("tool_start", entry)
			vlog("  %s🔧 %s%s%s", sl.Prefix(), d.ToolName, mcpTag(d.ToolName), argsSummary(d.Arguments))

		case *copilot.ToolExecutionCompleteData:
			name := toolNames[d.ToolCallID]
			delete(toolNames, d.ToolCallID)
			entry := map[string]any{
				"tool_call_id": d.ToolCallID,
				"tool_name":    name,
				"success":      d.Success,
			}
			if d.Result != nil {
				entry["result_content"] = d.Result.Content
			}
			if d.Error != nil {
				entry["error_message"] = d.Error.Message
			}
			sl.Log("tool_complete", entry)
			if !d.Success {
				if name != "" {
					log.Printf("  %s❌ tool call %s (%s) failed", sl.Prefix(), name, d.ToolCallID)
				} else {
					log.Printf("  %s❌ tool call %s failed", sl.Prefix(), d.ToolCallID)
				}
			}

		case *copilot.AssistantMessageData:
			sl.Log("assistant_message", map[string]string{
				"message_id": d.MessageID,
				"content":    d.Content,
			})

		case *copilot.AssistantTurnEndData:
			sl.Log("turn_end", map[string]string{
				"turn_id": d.TurnID,
			})

		case *copilot.SessionErrorData:
			sl.Log("session_error", map[string]string{
				"message": d.Message,
			})
			log.Printf("  %s❌ session error: %s", sl.Prefix(), d.Message)

		default:
			sl.Log(string(event.Type()), event.Data)
		}
	}
}

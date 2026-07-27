// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// pythonSandbox is the command prefix that runs the interpreter in a network-
// isolated namespace, or nil when that is unavailable on this host.
var pythonSandbox = detectPythonSandbox()

// cappedBuilder is an io.Writer that keeps at most cap bytes and discards the
// rest, recording that truncation happened.
type cappedBuilder struct {
	sb        strings.Builder
	remaining int
	truncated bool
}

// runPythonEnabled gates the run_python tool. Default off; enable with
// XPSD_ENABLE_RUN_PYTHON=1.
func runPythonEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("XPSD_ENABLE_RUN_PYTHON"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

func detectPythonSandbox() []string {
	if _, err := exec.LookPath("unshare"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Probe: a no-op child in a new user+net namespace.
	if err := exec.CommandContext(ctx, "unshare", "-r", "-n", "true").Run(); err != nil {
		return nil
	}
	return []string{"unshare", "-r", "-n"}
}

func registerPythonTools(s *server.MCPServer, srcDir string, maxBytes int, outDir string) {
	if _, err := exec.LookPath("python3"); err != nil {
		return
	}
	if !runPythonEnabled() {
		return
	}
	if pythonSandbox == nil {
		log.Printf("warning: run_python is ENABLED without network isolation " +
			"(unshare/userns unavailable); agent-supplied Python can reach the network. " +
			"Restrict the container's egress or run where unprivileged userns is available.")
	}

	s.AddTool(
		mcp.NewTool("run_python",
			mcp.WithDescription(
				"Run Python 3 code locally. "+
					"The project source tree root is in os.environ['SRC_DIR']. "+
					"Files written by other tools (large results) are in os.environ['TOOL_OUTPUT_DIR']. "+
					"Use this to filter, transform, or analyse tool output that is "+
					"too large to process inline.",
			),
			mcp.WithString("code",
				mcp.Required(),
				mcp.Description(
					"Python code to execute. "+
						"Access source via os.environ['SRC_DIR'] and tool output via os.environ['TOOL_OUTPUT_DIR']. "+
						"Write output to stdout; it will be returned as the tool result.",
				),
			),
			mcp.WithNumber("timeout",
				mcp.Description("Execution timeout in seconds (default: 30, max: 120)"),
			),
		),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			code, err := getStringArg(req, "code")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			timeout := getIntArg(req, "timeout", 30)
			if timeout <= 0 || timeout > 120 {
				timeout = 30
			}

			result, err := runPython(code, srcDir, outDir, timeout)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			data, _ := json.MarshalIndent(result, "", "  ")
			return toolResultRawOrFile(data, maxBytes, outDir)
		},
	)
}

// runPython executes Python code locally with SRC_DIR and TOOL_OUTPUT_DIR set
// as environment variables.
func runPython(code, srcDir, outDir string, timeoutSec int) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSec)*time.Second)
	defer cancel()

	argv := append(append([]string{}, pythonSandbox...), "python3", "-I", "-c", code)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = append(os.Environ(),
		"SRC_DIR="+srcDir,
		"TOOL_OUTPUT_DIR="+outDir,
		"PYTHONDONTWRITEBYTECODE=1",
	)
	// Cap collected output; the tail is dropped.
	stdout := newCappedBuilder(8 * 1024 * 1024)
	stderr := newCappedBuilder(1 * 1024 * 1024)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	runErr := cmd.Run()
	exitCode := 0
	timedOut := ctx.Err() == context.DeadlineExceeded
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if timedOut {
			exitCode = -1
		} else {
			return nil, fmt.Errorf("python: %w", runErr)
		}
	}

	result := map[string]any{
		"stdout": stdout.String(),
	}
	if stdout.truncated {
		result["stdout_truncated"] = true
	}
	if s := strings.TrimSpace(stderr.String()); s != "" {
		result["stderr"] = s
	}
	result["exit_code"] = exitCode
	if timedOut {
		result["timeout"] = true
	}
	return result, nil
}

func newCappedBuilder(capBytes int) *cappedBuilder {
	return &cappedBuilder{remaining: capBytes}
}

func (c *cappedBuilder) Write(p []byte) (int, error) {
	n := len(p)
	if c.remaining <= 0 {
		c.truncated = true
		return n, nil
	}
	if n > c.remaining {
		c.sb.Write(p[:c.remaining])
		c.remaining = 0
		c.truncated = true
		return n, nil
	}
	c.sb.Write(p)
	c.remaining -= n
	return n, nil
}

func (c *cappedBuilder) String() string { return c.sb.String() }

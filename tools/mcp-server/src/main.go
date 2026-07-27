// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/mark3labs/mcp-go/server"
)

// verboseEnabled gates progress logging; warnings and fatals always print.
var verboseEnabled bool

// The MCP server exposes file tools and ast-grep structural-search tools that
// run against the project source, mounted at /src in the agent's virtual paths.

func main() {
	outDir := flag.String("out", "out", "parent output directory; server artifacts go under <out>/server/")
	addr := flag.String("addr", ":8080", "HTTP listen address (use 'stdio' for stdin/stdout mode)")
	maxToolOutputKB := flag.Int("max-tool-output-kb", 24, "max inline response size in KB; larger results are written to a tmp file (default: 24 KB)")
	srcDir := flag.String("source", "",
		"path to the project source directory used by the file and ast-grep tools. "+
			"Required: when unset the tools return an error.")
	verbose := flag.Bool("v", false, "verbose logging")
	webFetcherURL := flag.String("web-fetcher-url", "",
		"base URL of the web-fetcher service (e.g. http://127.0.0.1:port). "+
			"When set, the fetch_url tool is registered and proxies to it.")
	flag.Parse()
	verboseEnabled = *verbose

	serverDir := filepath.Join(*outDir, "server")
	logDir := filepath.Join(serverDir, "logs")
	for _, d := range []string{serverDir, logDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			log.Fatalf("creating dir %s: %v", d, err)
		}
	}

	// Set up file logging alongside stderr.
	logF, err := os.OpenFile(filepath.Join(logDir, "mcp.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("opening log file: %v", err)
	}
	defer logF.Close()
	log.SetOutput(io.MultiWriter(os.Stderr, logF))

	sourcePath := strings.TrimSpace(*srcDir)
	if sourcePath != "" {
		if info, err := os.Stat(sourcePath); err != nil || !info.IsDir() {
			log.Fatalf("invalid -source %q: must be an existing directory (err=%v)", sourcePath, err)
		}
		vlog("source dir: %s", sourcePath)
		logSourceTree(sourcePath)
	} else {
		log.Printf("warning: no -source set; file and ast-grep tools will return an error")
	}

	toolOutDir, err := os.MkdirTemp("", "mcp-tools-*")
	if err != nil {
		log.Fatalf("creating tool output dir: %v", err)
	}
	if err := os.Chmod(toolOutDir, 0o755); err != nil {
		log.Fatalf("chmod tool output dir: %v", err)
	}
	vlog("tool output dir: %s", toolOutDir)

	maxBytes := *maxToolOutputKB * 1024

	// Single SSRF enforcement point for outbound fetches; git and archive
	// downloads route through it.
	safeProxyURL = startSafeProxy()
	if safeProxyURL != "" {
		vlog("SSRF-validating proxy: %s", safeProxyURL)
	} else {
		log.Printf("warning: SSRF-validating proxy unavailable; dependency fetches are disabled for safety")
	}

	s := server.NewMCPServer(
		"analysis",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	registerCommonTools(s, sourcePath, maxBytes, toolOutDir)
	registerAstGrepTools(s, sourcePath, maxBytes, toolOutDir)
	registerPythonTools(s, sourcePath, maxBytes, toolOutDir)
	registerOSVTools(s, maxBytes, toolOutDir)
	registerDepTools(s, maxBytes, toolOutDir)
	toolset := "common + ast-grep + python + osv + dep"
	if u := strings.TrimSpace(*webFetcherURL); u != "" {
		registerWebTools(s, u, maxBytes, toolOutDir)
		toolset += " + web"
		vlog("web-fetcher service: %s", u)
	}
	vlog("registered MCP tools (%s)", toolset)

	if *addr == "stdio" {
		log.Println("starting MCP server on stdio")
		if err := server.ServeStdio(s); err != nil {
			log.Fatalf("server error: %v", err)
		}
	} else {
		httpServer := server.NewStreamableHTTPServer(s, server.WithEndpointPath("/mcp"))
		mux := http.NewServeMux()
		mux.Handle("/mcp", httpServer)
		mux.Handle("/mcp/", httpServer)
		ln, actualAddr := listenWithRotation(*addr, 10)
		vlog("starting MCP server on %s/mcp", actualAddr)
		if err := http.Serve(ln, mux); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}
}

// vlog prints a progress line only in verbose mode.
func vlog(format string, args ...any) {
	if verboseEnabled {
		log.Printf(format, args...)
	}
}

// logSourceTree logs a shallow tree of the source dir.
func logSourceTree(root string) {
	const maxDepth = 2
	const maxEntries = 100
	count := 0
	truncated := false
	vlog("source tree (depth<=%d):", maxDepth)
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil || rel == "." {
			return nil
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "vendor") {
			return filepath.SkipDir
		}
		depth := strings.Count(rel, string(filepath.Separator))
		if depth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if count >= maxEntries {
			truncated = true
			return filepath.SkipAll
		}
		count++
		name := d.Name()
		if d.IsDir() {
			name += "/"
		}
		vlog("  %s%s", strings.Repeat("  ", depth), name)
		return nil
	})
	if count == 0 {
		vlog("  (empty)")
	} else if truncated {
		vlog("  … (more than %d entries)", maxEntries)
	}
}

func listenWithRotation(addr string, maxRetries int) (net.Listener, string) {
	ln, err := net.Listen("tcp", addr)
	if err == nil {
		return ln, addr
	}

	host, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		if strings.HasPrefix(addr, ":") {
			host = ""
			portStr = addr[1:]
		} else {
			log.Fatalf("listen on %s: %v", addr, err)
		}
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		log.Fatalf("listen on %s: %v", addr, err)
	}

	for i := 1; i <= maxRetries; i++ {
		nextPort := port + i
		nextAddr := fmt.Sprintf("%s:%d", host, nextPort)
		vlog("port %d in use, trying %d", port+i-1, nextPort)
		ln, err = net.Listen("tcp", nextAddr)
		if err == nil {
			return ln, nextAddr
		}
	}
	log.Fatalf("could not find free port after %d retries (starting from %s)", maxRetries, addr)
	return nil, ""
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"time"
)

// webFetcherScript is the in-image path for the bundled web-fetcher service.
const webFetcherScript = "/opt/web-fetcher/server.py"

// startWebFetcher starts the web-fetcher as a local subprocess and returns its
// base URL plus a stop function. Best-effort: if python3 or the script is
// missing, the run continues without the fetch_url tool.
func startWebFetcher(ctx context.Context) (url string, stop func()) {
	noop := func() {}

	if _, err := exec.LookPath("python3"); err != nil {
		log.Printf("web-fetcher: python3 not found; fetch_url disabled")
		return "", noop
	}
	if _, err := os.Stat(webFetcherScript); err != nil {
		log.Printf("web-fetcher: %s not found; fetch_url disabled", webFetcherScript)
		return "", noop
	}

	port, err := freePort()
	if err != nil {
		log.Printf("web-fetcher: no free port: %v; fetch_url disabled", err)
		return "", noop
	}

	cmd := exec.CommandContext(ctx, "python3", webFetcherScript)
	cmd.Env = append(os.Environ(),
		"PORT="+strconv.Itoa(port),
		"HOME=/tmp",
		"PLAYWRIGHT_BROWSERS_PATH=/ms-playwright",
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		log.Printf("web-fetcher: failed to start: %v; fetch_url disabled", err)
		return "", noop
	}

	stop = func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	}

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	if err := waitForWebFetcher(ctx, base, 90*time.Second); err != nil {
		log.Printf("web-fetcher: did not become ready: %v; fetch_url disabled", err)
		stop()
		return "", noop
	}
	vlog("web-fetcher ready at %s", base)
	return base, stop
}

// waitForWebFetcher polls the service /healthz endpoint until it responds 200
// or the deadline elapses.
func waitForWebFetcher(ctx context.Context, base string, within time.Duration) error {
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(within)
	var last error
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/healthz", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			last = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			last = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	return last
}

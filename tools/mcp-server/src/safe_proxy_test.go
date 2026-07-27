// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain starts the SSRF-validating proxy for the whole package.
func TestMain(m *testing.M) {
	safeProxyURL = startSafeProxy()
	os.Exit(m.Run())
}

func TestDialPublicRejectsInternal(t *testing.T) {
	ctx := context.Background()
	for _, addr := range []string{
		"127.0.0.1:80",       // loopback
		"10.0.0.1:80",        // RFC1918
		"192.168.1.1:443",    // RFC1918
		"169.254.169.254:80", // link-local / cloud metadata
		"[::1]:80",           // IPv6 loopback
	} {
		if _, err := dialPublic(ctx, addr); err == nil {
			t.Errorf("dialPublic(%q) allowed an internal address", addr)
		}
	}
}

// TestSafeProxyBlocksInternalHTTP proves a client configured to use the proxy
// cannot reach a loopback service through it.
func TestSafeProxyBlocksInternalHTTP(t *testing.T) {
	// A stand-in "internal service" on loopback.
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "SECRET")
	}))
	defer internal.Close()

	proxyURL := startSafeProxy()
	if proxyURL == "" {
		t.Fatal("proxy did not start")
	}
	pu, _ := url.Parse(proxyURL)
	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
	}

	resp, err := client.Get(internal.URL) // internal.URL is http://127.0.0.1:PORT
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK && strings.Contains(string(body), "SECRET") {
		t.Fatalf("proxy leaked an internal service: status %d body %q", resp.StatusCode, body)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 from proxy, got %d", resp.StatusCode)
	}
}

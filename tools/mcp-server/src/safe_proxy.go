// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// safeProxyURL is the address of the loopback validating proxy, set once at
// startup by startSafeProxy. Empty until the proxy is running.
var safeProxyURL string

// proxyHTTPTransport dials every upstream through dialPublic (resolve-once-pin).
var proxyHTTPTransport = &http.Transport{
	DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
		return dialPublic(ctx, addr)
	},
	MaxIdleConns:          10,
	IdleConnTimeout:       30 * time.Second,
	TLSHandshakeTimeout:   15 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
}

var hopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// startSafeProxy launches a loopback HTTP proxy that only ever connects to
// public addresses. Returns the proxy URL, or "" if it could not start.
func startSafeProxy() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Printf("warning: SSRF-validating proxy failed to start: %v", err)
		return ""
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(safeProxyHandler),
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			vlog("SSRF-validating proxy stopped: %v", err)
		}
	}()
	return "http://" + ln.Addr().String()
}

func safeProxyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		proxyConnect(w, r)
		return
	}
	proxyHTTP(w, r)
}

// dialPublic resolves addr's host once, requires every resolved address to be
// public, and dials the first one.
func dialPublic(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("bad target %q: %w", addr, err)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	for _, ip := range ips {
		if !isGlobalIP(ip) {
			return nil, fmt.Errorf("%s resolves to non-public address %s; refusing", host, ip)
		}
	}
	d := &net.Dialer{Timeout: 30 * time.Second}
	return d.DialContext(ctx, "tcp", net.JoinHostPort(ips[0].String(), port))
}

// proxyConnect handles CONNECT (used for https): it opens a validated tunnel to
// the target and pipes raw bytes.
func proxyConnect(w http.ResponseWriter, r *http.Request) {
	dst, err := dialPublic(r.Context(), r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	defer dst.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy: no hijack support", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	done := make(chan struct{}, 2)
	go func() { io.Copy(dst, client); done <- struct{}{} }()
	go func() { io.Copy(client, dst); done <- struct{}{} }()
	<-done
}

// proxyHTTP handles absolute-form requests (used for plain http): it re-issues
// the request through a dialer that only reaches public addresses.
func proxyHTTP(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() || r.URL.Host == "" {
		http.Error(w, "proxy: expected absolute-form request", http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "http" {
		http.Error(w, "proxy: unsupported scheme", http.StatusBadRequest)
		return
	}
	// Reject internal targets up front with a 403.
	if err := checkURLAllowed(r.URL.String()); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	removeHopHeaders(outReq.Header)

	resp, err := proxyHTTPTransport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "proxy: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHopHeaders(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func removeHopHeaders(h http.Header) {
	for _, k := range hopHeaders {
		h.Del(k)
	}
}

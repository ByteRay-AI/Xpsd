// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// toolCacheTTL bounds how long a tool's raw output is reused.
const toolCacheTTL = 12 * time.Hour

type toolCacheEntry struct {
	data      []byte
	expiresAt time.Time
}

var toolCache struct {
	mu      sync.RWMutex
	entries map[string]toolCacheEntry
}

func init() {
	toolCache.entries = make(map[string]toolCacheEntry)
}

// toolCacheKey produces a stable hash from the tool name and its parameter
// values. Each part is formatted with %#v.
func toolCacheKey(tool string, parts ...any) string {
	h := sha256.New()
	h.Write([]byte(tool))
	for _, p := range parts {
		h.Write([]byte{0})
		fmt.Fprintf(h, "%#v", p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func toolCacheGet(key string) ([]byte, bool) {
	toolCache.mu.RLock()
	defer toolCache.mu.RUnlock()
	e, ok := toolCache.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	out := make([]byte, len(e.data))
	copy(out, e.data)
	return out, true
}

func toolCachePut(key string, data []byte) {
	cp := make([]byte, len(data))
	copy(cp, data)
	toolCache.mu.Lock()
	defer toolCache.mu.Unlock()
	toolCache.entries[key] = toolCacheEntry{data: cp, expiresAt: time.Now().Add(toolCacheTTL)}
}

// cachedJSON caches values that marshal cleanly to JSON. The cached payload
// is the JSON encoding of v; on hit it is unmarshaled back into a fresh *T.
func cachedJSON[T any](key string, fn func() (T, error)) (T, error) {
	var zero T
	if hit, ok := toolCacheGet(key); ok {
		var v T
		if err := json.Unmarshal(hit, &v); err == nil {
			return v, nil
		}
	}
	v, err := fn()
	if err != nil {
		return zero, err
	}
	if data, mErr := json.Marshal(v); mErr == nil {
		toolCachePut(key, data)
	}
	return v, nil
}

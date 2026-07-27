// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	copilot "github.com/github/copilot-sdk/go"
)

// ListModelsOpts controls model listing behavior for interactive selection.
type ListModelsOpts struct {
	ProviderType string
	BaseURL      string
	APIKey       string
	Verbose      bool
}

// ResolveAPIKey returns explicit when non-empty, otherwise reads the
// well-known env var for the given BYOK provider type.
func ResolveAPIKey(providerType, explicit string) string {
	if explicit != "" {
		return explicit
	}
	switch providerType {
	case "openai":
		return os.Getenv("OPENAI_API_KEY")
	case "anthropic":
		return os.Getenv("ANTHROPIC_API_KEY")
	case "azure":
		return os.Getenv("AZURE_OPENAI_KEY")
	}
	return ""
}

// DefaultModel returns a sensible default model id for the given BYOK provider.
func DefaultModel(providerType string) string {
	switch providerType {
	case "openai":
		return "gpt-4o"
	case "anthropic":
		return "claude-sonnet-4-20250514"
	case "azure":
		return "gpt-4o"
	}
	return "gpt-4o"
}

// PrintModels prints models in a tab-separated 5-column format
func PrintModels(models []copilot.ModelInfo) {
	for _, m := range models {
		ctxWin := "-"
		if m.Capabilities.Limits.MaxContextWindowTokens != nil && *m.Capabilities.Limits.MaxContextWindowTokens > 0 {
			ctxWin = fmt.Sprintf("%d", *m.Capabilities.Limits.MaxContextWindowTokens)
		}
		prompt := "-"
		if m.Capabilities.Limits.MaxPromptTokens != nil {
			prompt = fmt.Sprintf("%d", *m.Capabilities.Limits.MaxPromptTokens)
		}
		if len(m.SupportedReasoningEfforts) == 0 {
			fmt.Printf("%s\t-\t%s\t%s\t%s\n", m.ID, ctxWin, prompt, m.Name)
			continue
		}
		for _, e := range m.SupportedReasoningEfforts {
			def := ""
			if e == m.DefaultReasoningEffort {
				def = "*"
			}
			fmt.Printf("%s\t%s%s\t%s\t%s\t%s\n", m.ID, e, def, ctxWin, prompt, m.Name)
		}
	}
}

// ListModels returns available models for either the default Copilot runtime
// or a BYOK provider endpoint when provider options are supplied.
func ListModels(ctx context.Context, opts ListModelsOpts) ([]copilot.ModelInfo, error) {
	if opts.ProviderType != "" || opts.BaseURL != "" || opts.APIKey != "" {
		return listProviderModels(ctx, opts.ProviderType, opts.BaseURL, opts.APIKey)
	}
	client := copilot.NewClient(&copilot.ClientOptions{LogLevel: LogLevel(opts.Verbose)})
	if err := client.Start(ctx); err != nil {
		return nil, fmt.Errorf("starting copilot client: %w", err)
	}
	defer client.Stop()
	return client.ListModels(ctx)
}

func listProviderModels(ctx context.Context, providerType, baseURL, apiKey string) ([]copilot.ModelInfo, error) {
	if strings.TrimSpace(baseURL) == "" {
		return nil, errors.New("-base-url is required when listing models with provider settings")
	}
	if strings.TrimSpace(providerType) == "" {
		providerType = "openai"
	}
	resolvedKey := ResolveAPIKey(providerType, apiKey)

	var errs []string
	for _, endpoint := range providerModelListEndpoints(baseURL) {
		models, err := fetchProviderModels(ctx, providerType, endpoint, resolvedKey)
		if err == nil {
			return models, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", endpoint, err))
	}
	return nil, fmt.Errorf("listing models from provider failed (%s)", strings.Join(errs, "; "))
}

func providerModelListEndpoints(baseURL string) []string {
	base := strings.TrimRight(baseURL, "/")
	candidates := []string{base + "/models"}
	if !strings.Contains(base, "/v1/") && !strings.HasSuffix(base, "/v1") {
		candidates = append(candidates, base+"/v1/models")
	}
	seen := make(map[string]struct{}, len(candidates))
	var out []string
	for _, endpoint := range candidates {
		if _, ok := seen[endpoint]; ok {
			continue
		}
		seen[endpoint] = struct{}{}
		out = append(out, endpoint)
	}
	return out
}

func fetchProviderModels(ctx context.Context, providerType, endpoint, apiKey string) ([]copilot.ModelInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	switch providerType {
	case "anthropic":
		if apiKey != "" {
			req.Header.Set("x-api-key", apiKey)
		}
		req.Header.Set("anthropic-version", "2023-06-01")
	case "azure":
		if apiKey != "" {
			req.Header.Set("api-key", apiKey)
		}
	default:
		if apiKey != "" {
			req.Header.Set("Authorization", "Bearer "+apiKey)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("HTTP %s (%s)", resp.Status, msg)
	}

	models, err := decodeProviderModels(body)
	if err != nil {
		return nil, err
	}
	if len(models) == 0 {
		return nil, errors.New("provider returned an empty model list")
	}
	return models, nil
}

func decodeProviderModels(body []byte) ([]copilot.ModelInfo, error) {
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("decoding provider model-list response: %w", err)
	}

	var rows []any
	for _, key := range []string{"data", "models"} {
		if arr, ok := payload[key].([]any); ok {
			rows = arr
			break
		}
	}
	if len(rows) == 0 {
		return nil, errors.New("model-list response missing data/models array")
	}

	seen := map[string]struct{}{}
	out := make([]copilot.ModelInfo, 0, len(rows))
	for _, row := range rows {
		obj, ok := row.(map[string]any)
		if !ok {
			continue
		}
		id := firstNonEmptyString(obj, "id", "model")
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		name := firstNonEmptyString(obj, "name", "display_name")
		if name == "" {
			name = id
		}
		out = append(out, copilot.ModelInfo{ID: id, Name: name})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func firstNonEmptyString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if raw, ok := values[key]; ok {
			if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
				return s
			}
		}
	}
	return ""
}

// LogLevel maps a verbose bool to the copilot SDK's log-level string.
func LogLevel(verbose bool) string {
	if verbose {
		return "debug"
	}
	return "error"
}

// ExtractJSON strips markdown code fences from an LLM response and pretty-prints
// the result if it parses as JSON. If the content is not valid JSON, the
// fence-stripped string is returned as-is.
func ExtractJSON(s string) string {
	s = strings.TrimSpace(s)

	// Strip ```json ... ``` (or any ``` ... ```) wrapper.
	if strings.HasPrefix(s, "```") {
		lines := strings.SplitN(s, "\n", 2)
		if len(lines) == 2 {
			s = lines[1]
		}
		if idx := strings.LastIndex(s, "```"); idx >= 0 {
			s = s[:idx]
		}
	}
	s = strings.TrimSpace(s)

	var js json.RawMessage
	if json.Unmarshal([]byte(s), &js) == nil {
		var buf strings.Builder
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if enc.Encode(js) == nil {
			return strings.TrimSpace(buf.String())
		}
	}
	return s
}

// ExtractJSONBlock extracts the first JSON object from text that may contain
// prose, code fences, or other surrounding content. Unlike ExtractJSON it does
// not pretty-print and is tolerant of leading/trailing prose; callers that
// expect a clean LLM response should use ExtractJSON instead.
func ExtractJSONBlock(text string) string {
	text = strings.TrimSpace(text)

	// Already clean JSON.
	if strings.HasPrefix(text, "{") {
		return text
	}

	// ```json ... ``` fence.
	if idx := strings.Index(text, "```json"); idx >= 0 {
		start := idx + 7
		if end := strings.Index(text[start:], "```"); end >= 0 {
			return strings.TrimSpace(text[start : start+end])
		}
	}

	// ``` ... ``` fence with JSON inside.
	if idx := strings.Index(text, "```"); idx >= 0 {
		start := idx + 3
		if nl := strings.Index(text[start:], "\n"); nl >= 0 {
			start = start + nl + 1
		}
		if end := strings.Index(text[start:], "```"); end >= 0 {
			candidate := strings.TrimSpace(text[start : start+end])
			if strings.HasPrefix(candidate, "{") {
				return candidate
			}
		}
	}

	// Bare { ... } block.
	first := strings.Index(text, "{")
	last := strings.LastIndex(text, "}")
	if first >= 0 && last > first {
		return strings.TrimSpace(text[first : last+1])
	}

	return ""
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"strings"
	"testing"
)

// 1 AIU is one cent, and the runtime reports nano-AIU, so 1e11 nano-AIU is $1.
func TestFormatCostFromReportedAIU(t *testing.T) {
	got := formatCost(
		SessionUsage{NanoAIU: 4_473_525_000, HasCost: true},
		SessionUsage{NanoAIU: 1_526_475_000, HasCost: true},
	)
	if !strings.Contains(got, "$0.0600") {
		t.Errorf("6e9 nano-AIU should be $0.06, got %q", got)
	}
	if !strings.Contains(got, "reported by Copilot") {
		t.Errorf("cost should be labelled as reported, not estimated: %q", got)
	}
}

// No report means unknown. Inventing a figure would be worse than saying so.
func TestNoCostDataSaysSo(t *testing.T) {
	got := formatCost(SessionUsage{Requests: 20, ToolCalls: 45}, SessionUsage{})
	if !strings.Contains(got, "not available") {
		t.Errorf("missing an explicit unavailable message: %q", got)
	}
	if strings.Contains(got, "$") {
		t.Errorf("quoted a price with no billing data: %q", got)
	}
}

// One stage reporting is enough to price what was reported.
func TestPartialCostStillReported(t *testing.T) {
	got := formatCost(
		SessionUsage{NanoAIU: 1e11, HasCost: true},
		SessionUsage{Requests: 3},
	)
	if !strings.Contains(got, "$1.0000") {
		t.Errorf("1e11 nano-AIU should be $1.00, got %q", got)
	}
}

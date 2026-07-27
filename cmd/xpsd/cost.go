// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import "fmt"

// nanoAIUPerDollar converts Copilot's billing unit to dollars. Cost is reported
// in nano-AI-units: 1e9 nano-AIU is one AI unit, and one AI unit is one cent.
const nanoAIUPerDollar = 100_000_000_000

// formatCost renders the run's billed cost from what Copilot reported.
//
// The number is Copilot's own, not an estimate derived from turn counts, so it
// is only available when the runtime reports it. A bring-your-own-key provider
// bills at the user's own account and reports nothing here, and so does any
// endpoint that omits the field. In those cases the cost is unknown, and saying
// so beats inventing a figure.
func formatCost(analysis, review SessionUsage) string {
	if !analysis.HasCost && !review.HasCost {
		return "cost: data not available, cannot estimate"
	}
	total := analysis.NanoAIU + review.NanoAIU
	return fmt.Sprintf("cost: $%.4f  (%.0f nano-AIU reported by Copilot)", total/nanoAIUPerDollar, total)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import (
	"math"
	"strings"
)

// CVSS3BaseScore computes the base score from a CVSS v3.0 / v3.1 vector
// string like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".
// Returns (score, true) on success, (0, false) for anything it cannot parse
// (including CVSS v2 and v4 vectors).
func CVSS3BaseScore(vector string) (float64, bool) {
	vector = strings.TrimSpace(vector)
	v31 := strings.HasPrefix(vector, "CVSS:3.1/")
	if !strings.HasPrefix(vector, "CVSS:3.0/") && !v31 {
		return 0, false
	}

	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/")[1:] {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			return 0, false
		}
		metrics[kv[0]] = kv[1]
	}

	scopeChanged := false
	switch metrics["S"] {
	case "C":
		scopeChanged = true
	case "U":
	default:
		return 0, false
	}

	av, ok := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[metrics["AV"]]
	if !ok {
		return 0, false
	}
	ac, ok := map[string]float64{"L": 0.77, "H": 0.44}[metrics["AC"]]
	if !ok {
		return 0, false
	}
	prTable := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	if scopeChanged {
		prTable = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	}
	pr, ok := prTable[metrics["PR"]]
	if !ok {
		return 0, false
	}
	ui, ok := map[string]float64{"N": 0.85, "R": 0.62}[metrics["UI"]]
	if !ok {
		return 0, false
	}
	cia := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}
	c, okC := cia[metrics["C"]]
	i, okI := cia[metrics["I"]]
	a, okA := cia[metrics["A"]]
	if !okC || !okI || !okA {
		return 0, false
	}

	iss := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		// The changed-scope impact sub-score differs between v3.0 and v3.1.
		if v31 {
			impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss*0.9731-0.02, 13)
		} else {
			impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
		}
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, true
	}

	exploitability := 8.22 * av * ac * pr * ui
	var score float64
	if scopeChanged {
		score = math.Min(1.08*(impact+exploitability), 10)
	} else {
		score = math.Min(impact+exploitability, 10)
	}
	return cvssRoundUp(score), true
}

// cvssRoundUp implements the CVSS v3.1 Roundup function: the smallest number
// with one decimal place that is >= the input (per the v3.1 specification,
// appendix A).
func cvssRoundUp(x float64) float64 {
	intInput := math.Round(x * 100000)
	if math.Mod(intInput, 10000) == 0 {
		return intInput / 100000
	}
	return (math.Floor(intInput/10000) + 1) / 10
}

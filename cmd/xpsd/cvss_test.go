// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ByteRay Ltd.

package main

import "testing"

func TestCVSS3BaseScore(t *testing.T) {
	cases := []struct {
		vector string
		want   float64
	}{
		// Reference scores from NVD / the CVSS v3.1 calculator.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9},
		{"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		{"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H", 9.1},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6},
	}
	for _, c := range cases {
		got, ok := CVSS3BaseScore(c.vector)
		if !ok {
			t.Errorf("CVSS3BaseScore(%q): not parsed", c.vector)
			continue
		}
		if got != c.want {
			t.Errorf("CVSS3BaseScore(%q) = %.1f, want %.1f", c.vector, got, c.want)
		}
	}
}

func TestCVSS3BaseScoreRejects(t *testing.T) {
	for _, vector := range []string{
		"",
		"garbage",
		"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // no prefix
		"CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", // v2
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N",   // v4
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",     // missing A
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // bad AV value
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:Q/C:H/I:H/A:H", // bad scope
		"CVSS:3.1/AV/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   // malformed pair
	} {
		if got, ok := CVSS3BaseScore(vector); ok {
			t.Errorf("CVSS3BaseScore(%q) = %.1f, want rejection", vector, got)
		}
	}
}

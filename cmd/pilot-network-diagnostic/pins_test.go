// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import "testing"

func TestParsePopulationFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name, events string
		empty, valid bool
	}{
		{"empty", "populated 0\nfrozen 0\n", true, true},
		{"active", "populated 1\nfrozen 0\n", false, true},
		{"missing", "frozen 0\n", false, false},
		{"ambiguous", "populated 00\n", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			empty, err := parsePopulation([]byte(test.events))
			if empty != test.empty || (err == nil) != test.valid {
				t.Fatalf("empty=%v error=%v", empty, err)
			}
		})
	}
}

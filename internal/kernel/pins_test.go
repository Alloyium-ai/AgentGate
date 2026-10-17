// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package kernel

import "testing"

func TestMapPinsPreserveLegacyNamesAndEncodeGlobalData(t *testing.T) {
	names, err := mapPinNames([]string{"policies", "stats", "events", "file_cookies", ".rodata"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"policies", "stats", "events", "file_cookies"} {
		if names[name] != name {
			t.Fatal("a legacy pin name changed")
		}
	}
	if names[".rodata"] != "map-2e726f64617461" {
		t.Fatal("the global-data pin name is not deterministic")
	}
	for _, input := range [][]string{{""}, {"unsafe/name"}, {".rodata", "map-2e726f64617461"}, {"policies", "policies"}} {
		if _, err = mapPinNames(input); err == nil {
			t.Fatal("an invalid or colliding pin name passed")
		}
	}
}

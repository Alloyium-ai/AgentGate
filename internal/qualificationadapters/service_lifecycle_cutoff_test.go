// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"testing"

	"alloyium.local/kernel-poc/internal/jobaudit"
)

func TestServiceLifecycleCutoffRejectsAllowedBoundary(t *testing.T) {
	for _, test := range []struct {
		name    string
		at      uint64
		allowed bool
		valid   bool
	}{
		{"before observer", 9, false, false},
		{"allowed before cutoff", 19, true, true},
		{"allowed at cutoff", 20, true, false},
		{"allowed after cutoff", 21, true, false},
		{"denied at cutoff", 20, false, true},
		{"denied after cutoff", 21, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			allowed := test.allowed
			bundle := jobaudit.Bundle{Events: []jobaudit.Event{{Stream: "files", Kind: "resource", Observation: jobaudit.Observation{TimestampNS: test.at, Decision: &allowed}}}}
			err := verifyServiceLifecycleCutoffEvents(bundle, 20, 10)
			if (err == nil) != test.valid {
				t.Fatal("the cutoff boundary result differs", err)
			}
		})
	}
}

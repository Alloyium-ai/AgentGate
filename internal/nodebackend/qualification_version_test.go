// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"context"
	"testing"

	"alloyium.local/kernel-poc/internal/lifecycle"
)

func TestVersionBackendRejectsAnAbsentOrDifferentOpaquePurpose(t *testing.T) {
	for _, permit := range []*lifecycle.QualificationFixturePermit{nil, {}} {
		if _, err := NewQualificationVersionBackend(context.Background(), Config{}, permit); err == nil {
			t.Fatal("an absent or fixed-worker permit entered the version backend")
		}
	}
}

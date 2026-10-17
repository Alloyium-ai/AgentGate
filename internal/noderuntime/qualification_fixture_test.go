// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"testing"
)

func TestQualificationNodeHasNoNormalAdmissionServer(t *testing.T) {
	node := &Node{fixture: &lifecycle.QualificationFixturePermit{}}
	if node.Serve(context.Background()) == nil {
		t.Fatal("a fixture exposed the normal admission server")
	}
}

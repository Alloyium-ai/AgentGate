// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodecontrol

import (
	"alloyium.local/kernel-poc/internal/childwire"
	"strings"
	"testing"
)

func TestChildFrameChunksRejectInvalidKindsAndBounds(t *testing.T) {
	p := ChildFrameChunk{Kind: "filters", Offset: 0, Total: 4097, Digest: strings.Repeat("a", 64), Bytes: make([]byte, 4096)}
	if p.Validate() != nil {
		t.Fatal("bounded chunk rejected")
	}
	for _, change := range []func(*ChildFrameChunk){func(v *ChildFrameChunk) { v.Kind = "unknown" }, func(v *ChildFrameChunk) { v.Offset = 4097 }, func(v *ChildFrameChunk) { v.Total = childwire.MaxFrame + 1 }, func(v *ChildFrameChunk) { v.Bytes = make([]byte, 4097) }, func(v *ChildFrameChunk) { v.Digest = "invalid" }} {
		bad := p
		change(&bad)
		if bad.Validate() == nil {
			t.Fatal("invalid frame chunk accepted")
		}
	}
}

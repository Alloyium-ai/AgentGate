// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"encoding/base64"
	"strings"
	"testing"
)

func pinBinding() lifecycle.Binding {
	return lifecycle.Binding{AgentID: "agent", AgentKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), JobDigest: strings.Repeat("1", 64), GrantID: "grant", RunID: "run", NodeID: "node", BootID: "boot", PolicyDigest: strings.Repeat("2", 64), SchemaDigest: strings.Repeat("3", 64), CompilerDigest: strings.Repeat("4", 64), ArtifactDigests: map[string]string{"node": strings.Repeat("5", 64)}, CgroupID: 42, Generation: 1, DeadlineNS: 100}
}
func TestPinnedCounterNamespaceRejectsForeignAndUnallocatedQueries(t *testing.T) {
	p := &PinReader{node: "node", proof: domainstore.RootProof{BootID: "boot", OwnedPrefix: "alloyium-poc-job-1234567890abcdef-"}}
	b := pinBinding()
	name, err := p.name(b, true)
	if err != nil {
		t.Fatal(err)
	}
	unallocated := b
	unallocated.CgroupID = 0
	same, err := p.name(unallocated, false)
	if err != nil || same != name {
		t.Fatal("resolved identity changed its immutable namespace")
	}
	if _, err = p.name(unallocated, true); err == nil {
		t.Fatal("an unallocated binding read kernel counters")
	}
	for _, change := range []func(*lifecycle.Binding){func(b *lifecycle.Binding) { b.NodeID = "foreign" }, func(b *lifecycle.Binding) { b.BootID = "old-boot" }, func(b *lifecycle.Binding) { b.Generation = 0 }, func(b *lifecycle.Binding) { b.RunID = "../other" }} {
		bad := b
		change(&bad)
		if _, err = p.name(bad, true); err == nil {
			t.Fatal("a foreign or invalid binding selected pins")
		}
	}
	next := b
	next.RunID = "next"
	different, err := p.name(next, true)
	if err != nil || different == name {
		t.Fatal("different runs share a pin namespace")
	}
}

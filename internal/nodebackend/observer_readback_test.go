// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"github.com/cilium/ebpf"
	"testing"
)

func TestObserverReadbackRefusesUnavailableMaps(t *testing.T) {
	b := &Backend{}
	for _, runtime := range []*kernel.Runtime{nil, {}, {Domain: "owned-domain", ID: 100, Collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}} {
		proof, err := b.observerReadback(&run{observation: runtime})
		if err == nil || proof.ManagedMapID != 0 || proof.BindingMapID != 0 || len(proof.Managed) != 0 || len(proof.Binding) != 0 {
			t.Fatal("unavailable maps acquired a readback", proof, err)
		}
	}
}

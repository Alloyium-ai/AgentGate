// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodecontrol

import (
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

func TestObserverControlRetainsExactMapBytes(t *testing.T) {
	b, g := boundFixture()
	b.ArtifactDigests["syscalls"] = strings.Repeat("f", 64)
	p := ObserverBinding{Domain: b.CgroupID, ManagedMapID: 51, BindingMapID: 52, Managed: make([]byte, 4), Binding: make([]byte, 16), ObservedMonoNS: 300}
	binary.LittleEndian.PutUint32(p.Managed, 1)
	binary.LittleEndian.PutUint64(p.Binding, b.Generation)
	binary.LittleEndian.PutUint64(p.Binding[8:], g.KernelDeadlineNS)
	raw, err := Encode(b, "observer_binding_readback", p)
	if err != nil {
		t.Fatal(err)
	}
	o, err := Decoder(b)(raw)
	if err != nil || o.Decision != nil || o.ControlPhase != "observer_binding_readback" || o.CgroupID != b.CgroupID || o.Generation != b.Generation {
		t.Fatal(o, err)
	}
	state, err := p.State()
	if err != nil || state.Generation != b.Generation || state.ExpiresNS != g.KernelDeadlineNS {
		t.Fatal(state, err)
	}
	for _, mutate := range []func(*ObserverBinding){func(v *ObserverBinding) { v.Domain++ }, func(v *ObserverBinding) { v.ManagedMapID = 0 }, func(v *ObserverBinding) { v.BindingMapID = v.ManagedMapID }, func(v *ObserverBinding) { v.Managed = v.Managed[:3] }, func(v *ObserverBinding) { v.Managed[0] = 0 }, func(v *ObserverBinding) { v.Binding = v.Binding[:15] }, func(v *ObserverBinding) { v.Binding[0]++ }, func(v *ObserverBinding) { binary.LittleEndian.PutUint64(v.Binding[8:], b.DeadlineNS+1) }, func(v *ObserverBinding) { v.ObservedMonoNS = g.KernelDeadlineNS }} {
		bad := p
		bad.Managed = append([]byte{}, p.Managed...)
		bad.Binding = append([]byte{}, p.Binding...)
		mutate(&bad)
		if reflect.DeepEqual(bad, p) {
			t.Fatal("negative did not change")
		}
		if _, err = Encode(b, "observer_binding_readback", bad); err == nil {
			t.Fatal("invalid observer readback passed", bad)
		}
	}
	for _, wire := range []string{strings.Replace(string(raw), `"domain":"100"`, `"domain":"100","domain":"101"`, 1), strings.Replace(string(raw), `"managed_map_id"`, `"Managed_Map_ID"`, 1), strings.Replace(string(raw), `"managed_map_id":51`, `"managed_map_id":51,"extra":1`, 1)} {
		if _, err = Decoder(b)([]byte(wire)); err == nil {
			t.Fatal("ambiguous observer fields passed")
		}
	}
}

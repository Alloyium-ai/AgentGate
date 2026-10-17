// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"errors"
	"github.com/cilium/ebpf"
)

func observerMapID(m *ebpf.Map, bytes uint32) (uint32, error) {
	if m == nil {
		return 0, errors.New("the observer map is absent")
	}
	info, err := m.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok || id == 0 || info.Type != ebpf.Hash || info.KeySize != 8 || info.ValueSize != bytes || info.MaxEntries != 64 {
		return 0, errors.New("the observer map identity or ABI differs")
	}
	return uint32(id), nil
}
func (b *Backend) observerReadback(r *run) (p nodecontrol.ObserverBinding, err error) {
	if r.observation == nil {
		return p, errors.New("the observer runtime is absent")
	}
	err = r.observation.WithPolicyUpdate(func() error {
		managed := r.observation.Collection.Maps["audit_managed"]
		binding := r.observation.Collection.Maps["audit_bindings"]
		if p.ManagedMapID, err = observerMapID(managed, 4); err != nil {
			return err
		}
		if p.BindingMapID, err = observerMapID(binding, 16); err != nil {
			return err
		}
		var marker [4]byte
		var state [16]byte
		if err = managed.Lookup(r.binding.CgroupID, &marker); err != nil {
			return err
		}
		if err = binding.Lookup(r.binding.CgroupID, &state); err != nil {
			return err
		}
		p.Domain = r.binding.CgroupID
		p.Managed = append([]byte{}, marker[:]...)
		p.Binding = append([]byte{}, state[:]...)
		p.ObservedMonoNS, err = b.config.Clock.NowNS()
		if err != nil {
			return err
		}
		if err = p.Validate(r.binding); err != nil {
			return err
		}
		actual, err := p.State()
		if err != nil {
			return err
		}
		if actual.ExpiresNS != r.deadline() {
			return errors.New("the observer readback misses the effective cutoff")
		}
		return nil
	})
	return p, err
}

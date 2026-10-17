// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodecontrol

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"encoding/binary"
	"errors"
)

// ObserverBinding retains exact bytes from the owned observer maps. It grants no permission.
type ObserverBinding struct {
	Domain         uint64 `json:"domain,string"`
	ManagedMapID   uint32 `json:"managed_map_id"`
	BindingMapID   uint32 `json:"binding_map_id"`
	Managed        []byte `json:"managed"`
	Binding        []byte `json:"binding"`
	ObservedMonoNS uint64 `json:"observed_mono_ns,string"`
}

func (p ObserverBinding) State() (syscallrules.Binding, error) {
	if len(p.Binding) != 16 {
		return syscallrules.Binding{}, errors.New("the observer binding byte count differs")
	}
	return syscallrules.Binding{Generation: binary.LittleEndian.Uint64(p.Binding), ExpiresNS: binary.LittleEndian.Uint64(p.Binding[8:])}, nil
}
func (p ObserverBinding) Validate(expected lifecycle.Binding) error {
	state, err := p.State()
	if err != nil || expected.Validate(false) != nil || expected.ArtifactDigests["syscalls"] == "" || p.Domain != expected.CgroupID || p.ManagedMapID == 0 || p.BindingMapID == 0 || p.ManagedMapID == p.BindingMapID || len(p.Managed) != 4 || binary.LittleEndian.Uint32(p.Managed) != 1 || state.Generation != expected.Generation || state.ExpiresNS == 0 || state.ExpiresNS > expected.DeadlineNS || p.ObservedMonoNS == 0 || p.ObservedMonoNS >= state.ExpiresNS {
		return errors.New("the observer map readback differs from the exact job")
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package openrules

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"errors"
	"github.com/cilium/ebpf"
)

// NewRuntime is restricted by kernel.Preflight to the disposable QEMU target.
// This component does not supply full policy admission or descriptor confinement.
func NewRuntime(object, domain string) (*kernel.Runtime, error) {
	return kernel.NewProfile(object, domain, kernel.Profile{
		ProgramOptions: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats, LogSizeStart: 4 << 20},
		Initialize: func(r *kernel.Runtime) error {
			if r.Collection.Maps["owned"] == nil || r.Collection.Maps["policies"] == nil {
				return errors.New("file-open object lacks its required maps")
			}
			if err := r.Collection.Maps["owned"].Update(r.ID, uint32(1), ebpf.UpdateNoExist); err != nil {
				return err
			}
			return r.Collection.Maps["policies"].Update(r.ID, State{}, ebpf.UpdateNoExist)
		},
		LSMPrograms:    []string{"file_open_rules"},
		CgroupPrograms: []kernel.CgroupProgram{{Name: "file_component_connect4", Attach: ebpf.AttachCGroupInet4Connect}, {Name: "file_component_connect6", Attach: ebpf.AttachCGroupInet6Connect}},
	})
}

// Install stages every node before the active generation changes.
func Install(r *kernel.Runtime, plan Plan) error {
	return r.WithPolicyUpdate(func() error { return install(r, plan) })
}

func validateInstall(plan Plan, domain, now, generation uint64) error {
	if plan.domain != domain || plan.state.Generation == 0 || plan.digest == "" || plan.digest != planDigest(plan) {
		return errors.New("file-open component binding differs")
	}
	if plan.state.Generation <= generation {
		return errors.New("file-open component generation must increase")
	}
	if plan.state.ExpiresNS <= now {
		return errors.New("file-open component expired before installation")
	}
	return nil
}

func install(r *kernel.Runtime, plan Plan) error {
	policies := r.Collection.Maps["policies"]
	if policies == nil {
		return errors.New("file-open policy map is unavailable")
	}
	var current State
	if err := policies.Lookup(r.ID, &current); err != nil {
		return err
	}
	now, err := kernel.MonotonicNS()
	if err != nil {
		return err
	}
	if err = validateInstall(plan, r.ID, now, current.Generation); err != nil {
		return err
	}
	nodes := r.Collection.Maps["nodes"]
	if nodes == nil {
		return errors.New("file-open node map is unavailable")
	}
	inserted := []Key{}
	rollback := func() {
		for _, key := range inserted {
			_ = nodes.Delete(key)
		}
	}
	for _, entry := range plan.entries {
		if err = nodes.Update(entry.Key, entry.Node, ebpf.UpdateNoExist); err != nil {
			rollback()
			return err
		}
		inserted = append(inserted, entry.Key)
	}
	if err = policies.Update(r.ID, plan.state, ebpf.UpdateExist); err != nil {
		rollback()
		return err
	}
	return nil
}

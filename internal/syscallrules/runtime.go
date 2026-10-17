// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package syscallrules

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
)

// RuntimeProfile uses the common pinned loader. The initial binding grants no
// operation; the observer only records the actual syscall and task outcomes.
func RuntimeProfile() kernel.Profile {
	hooks := []kernel.TracepointProgram{}
	for _, p := range Programs() {
		hooks = append(hooks, kernel.TracepointProgram{Name: p.Program, Group: p.Group, Event: p.Name})
	}
	return kernel.Profile{Initialize: func(r *kernel.Runtime) error {
		if r.ID == 0 {
			return errors.New("the syscall observer requires an owned root")
		}
		for _, name := range []string{"audit_managed", "audit_bindings", "audit_events", "audit_stats", "audit_origin"} {
			if r.Collection.Maps[name] == nil {
				return fmt.Errorf("the syscall observer lacks map %s", name)
			}
		}
		if err := r.Collection.Maps["audit_managed"].Update(r.ID, uint32(1), ebpf.UpdateNoExist); err != nil {
			return err
		}
		return r.Collection.Maps["audit_bindings"].Update(r.ID, Binding{}, ebpf.UpdateNoExist)
	}, TracepointPrograms: hooks, EventsMap: "audit_events", CountersMap: "audit_stats", ProgramOptions: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats, LogSizeStart: 4 << 20}}
}

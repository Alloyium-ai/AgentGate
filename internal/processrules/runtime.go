// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package processrules

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
)

func Programs() []string { return []string{"process_signal", "process_ptrace", "process_traceme"} }

func Profile() kernel.Profile {
	return kernel.Profile{Initialize: func(r *kernel.Runtime) error {
		for _, name := range []string{"proc_managed", "proc_policies", "proc_stats", "proc_events"} {
			if r.Collection.Maps[name] == nil {
				return fmt.Errorf("process object lacks map %s", name)
			}
		}
		if r.ID == 0 {
			return errors.New("process ownership requires a nonzero domain")
		}
		if err := r.Collection.Maps["proc_managed"].Update(r.ID, uint32(1), ebpf.UpdateNoExist); err != nil {
			return err
		}
		return r.Collection.Maps["proc_policies"].Update(r.ID, State{}, ebpf.UpdateNoExist)
	}, LSMPrograms: Programs(), EventsMap: "proc_events", CountersMap: "proc_stats", ProgramOptions: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats, LogSizeStart: 4 << 20}}
}
func validateInstall(plan Plan, domain, now, current uint64) error {
	if domain == 0 || plan.domain != domain || plan.state.Generation <= current || plan.state.ExpiresNS <= now || plan.digest == "" || plan.digest != planDigest(plan) {
		return errors.New("process binding, generation, deadline or digest differs")
	}
	return nil
}

// Install requires a trusted proof of an empty or fully held domain before and
// after the atomic update. The callback must inspect the complete owned domain.
func Install(r *kernel.Runtime, plan Plan, quiescent func() error) error {
	if r == nil || quiescent == nil {
		return errors.New("process installation requires a trusted quiescence verifier")
	}
	return r.WithPolicyUpdate(func() error {
		policies, managed := r.Collection.Maps["proc_policies"], r.Collection.Maps["proc_managed"]
		if policies == nil || managed == nil {
			return errors.New("process policy maps are unavailable")
		}
		var marker uint32
		if managed.Lookup(r.ID, &marker) != nil || marker != 1 {
			return errors.New("the process ownership marker differs")
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
		if err = quiescent(); err != nil {
			return err
		}
		fail := func(cause error) error {
			_ = policies.Update(r.ID, State{Generation: plan.state.Generation}, ebpf.UpdateExist)
			return cause
		}
		if err = policies.Update(r.ID, plan.state, ebpf.UpdateExist); err != nil {
			return err
		}
		var installed State
		if err = policies.Lookup(r.ID, &installed); err != nil {
			return fail(err)
		}
		if installed != plan.state {
			return fail(errors.New("the process policy readback differs"))
		}
		if err = quiescent(); err != nil {
			return fail(err)
		}
		return nil
	})
}

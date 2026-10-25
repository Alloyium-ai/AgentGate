// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"testing"

	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

func TestPipeUseWitnessRequiresOwnedAllowedLiveDecision(t *testing.T) {
	receipt := candidateReceipt{DomainID: 900, Generation: 2, Active: processSnapshot{PID: 42, MonoNS: 10}, DeadlineNS: 100}
	event := kernel.Event{Cgroup: 900, Generation: 2, PID: 42, UID: 65534, Hook: 16, Allowed: 1, MonoNS: 11}
	if !observedPipeUse([]kernel.Event{event}, receipt, 16) {
		t.Fatal("the owned live pipe read was not observed")
	}
	for name, change := range map[string]func(*kernel.Event){
		"wrong direction": func(e *kernel.Event) { e.Hook = 17 },
		"denied":          func(e *kernel.Event) { e.Allowed = 0 },
		"foreign domain":  func(e *kernel.Event) { e.Cgroup++ },
		"old generation":  func(e *kernel.Event) { e.Generation-- },
		"foreign actor":   func(e *kernel.Event) { e.PID++ },
		"wrong uid":       func(e *kernel.Event) { e.UID = 0 },
		"expired":         func(e *kernel.Event) { e.MonoNS = 100 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := event
			change(&changed)
			if observedPipeUse([]kernel.Event{changed}, receipt, 16) {
				t.Fatal("a foreign or denied pipe event supplied a positive case")
			}
		})
	}
}

func TestNoCreateFactsRejectMissingDenialAndExtraProcess(t *testing.T) {
	receipt := candidateReceipt{Active: processSnapshot{PID: 42, MonoNS: 1}, DeadlineNS: 100, ActiveMembers: "42\n", FinalMembers: "42\n"}
	calls := []syscallrules.Event{}
	for _, number := range []int64{unix.SYS_CLONE, unix.SYS_FORK, unix.SYS_VFORK, unix.SYS_CLONE3} {
		result := -int64(unix.EPERM)
		if number == unix.SYS_CLONE3 {
			result = -int64(unix.ENOSYS)
		}
		calls = append(calls, syscallrules.Event{Type: syscallrules.Result, SyscallID: number, Result: result, MonoNS: 10})
	}
	if err := noCreateFacts(receipt, calls); err != nil {
		t.Fatal(err)
	}
	if noCreateFacts(receipt, calls[:3]) == nil {
		t.Fatal("a missing actual clone3 denial passed")
	}
	calls[0].Result = 43
	if noCreateFacts(receipt, calls) == nil {
		t.Fatal("a successful process creation passed")
	}
	calls[0].Result = -int64(unix.EPERM)
	receipt.FinalMembers = "42\n43\n"
	if noCreateFacts(receipt, calls) == nil {
		t.Fatal("a second process passed")
	}
}

func TestPositiveCloneRequiresReapedSameDomainChild(t *testing.T) {
	receipt := candidateReceipt{Active: processSnapshot{PID: 42, MonoNS: 1}, DomainID: 900, DeadlineNS: 100, ActiveMembers: "42\n", FinalMembers: "42\n"}
	records := map[uint32]scalarRecord{50: {ID: 50, Result: 43}, 53: {ID: 53, Result: 43}, 54: {ID: 54, Result: 90 << 8}}
	calls := []syscallrules.Event{
		{Type: syscallrules.Result, SyscallID: unix.SYS_CLONE, Result: 43, MonoNS: 10},
		{Type: syscallrules.Result, SyscallID: unix.SYS_WAIT4, Result: 43, MonoNS: 11},
		{Type: syscallrules.Result, SyscallID: unix.SYS_FORK, Result: -int64(unix.EPERM), MonoNS: 12},
		{Type: syscallrules.Result, SyscallID: unix.SYS_VFORK, Result: -int64(unix.EPERM), MonoNS: 13},
		{Type: syscallrules.Result, SyscallID: unix.SYS_CLONE3, Result: -int64(unix.ENOSYS), MonoNS: 14},
		{Type: syscallrules.Result, SyscallID: unix.SYS_CLONE, Result: 0, TGID: 43, TID: 43, ParentTGID: 42, Cgroup: 900, MonoNS: 15},
		{Type: syscallrules.TaskExit, TGID: 43, ParentTGID: 42, ExitCode: 90 << 8, Cgroup: 900, MonoNS: 16},
	}
	if err := positiveCloneFacts(receipt, calls, records); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*candidateReceipt, []syscallrules.Event, map[uint32]scalarRecord){
		"unreaped": func(_ *candidateReceipt, calls []syscallrules.Event, _ map[uint32]scalarRecord) {
			calls[1].Result = -int64(unix.EPERM)
		},
		"foreign parent": func(_ *candidateReceipt, calls []syscallrules.Event, _ map[uint32]scalarRecord) {
			calls[6].ParentTGID++
		},
		"foreign domain": func(_ *candidateReceipt, calls []syscallrules.Event, _ map[uint32]scalarRecord) { calls[6].Cgroup++ },
		"missing exit":   func(_ *candidateReceipt, calls []syscallrules.Event, _ map[uint32]scalarRecord) { calls[6].TGID++ },
		"missing clone return": func(_ *candidateReceipt, calls []syscallrules.Event, _ map[uint32]scalarRecord) {
			calls[5].Result = -int64(unix.EPERM)
		},
		"foreign clone return": func(_ *candidateReceipt, calls []syscallrules.Event, _ map[uint32]scalarRecord) {
			calls[5].Cgroup++
		},
		"retained child": func(r *candidateReceipt, _ []syscallrules.Event, _ map[uint32]scalarRecord) { r.FinalMembers += "43\n" },
		"changed wait": func(_ *candidateReceipt, _ []syscallrules.Event, records map[uint32]scalarRecord) {
			records[53] = scalarRecord{ID: 53, Result: 44}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := receipt
			got := append([]syscallrules.Event{}, calls...)
			copyRecords := map[uint32]scalarRecord{}
			for id, record := range records {
				copyRecords[id] = record
			}
			change(&r, got, copyRecords)
			if positiveCloneFacts(r, got, copyRecords) == nil {
				t.Fatal("changed clone evidence passed")
			}
		})
	}
}

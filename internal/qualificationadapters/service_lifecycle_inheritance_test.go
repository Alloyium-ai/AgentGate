// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"encoding/binary"
	"testing"

	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

func lifecycleInheritanceFixture(t *testing.T) (qualification.Request, serviceLifecycleScene, []syscallrules.Event) {
	t.Helper()
	request := adapterRequest(t)
	request.Document.Runtime.Seccomp.AllowSyscalls = []string{"gettid"}
	scene := serviceLifecycleScene{Wire: lifecycleWireFixture()}
	for offset := 28; offset < len(scene.Wire); offset += 32 {
		binary.LittleEndian.PutUint32(scene.Wire[offset:], ^uint32(0))
	}
	scene.NodeSnapshot.Status = "Seccomp:\t0\nSeccomp_filters:\t0\n"
	scene.Active.Record.Binding.CgroupID = 456
	scene.Active.Record.Binding.Generation = 1
	actors, err := DecodeLifecycleRecords(scene.Wire)
	if err != nil {
		t.Fatal(err)
	}
	events := []syscallrules.Event{}
	for index, actor := range actors {
		ticks := uint64(1000 + index)
		scene.Actors = append(scene.Actors, processSnapshot{PID: int(actor.PID), StartTimeTicks: ticks, MonoNS: 50000000000, Status: "Seccomp:\t2\nSeccomp_filters:\t2\n"})
		events = append(events, syscallrules.Event{Sequence: uint64(index + 1), Domain: 456, Cgroup: 456, Generation: 1, MonoNS: uint64(20000000000 + index), TaskStartBootNS: ticks * 10000000, SyscallID: unix.SYS_GETTID, Result: -int64(unix.EPERM), TGID: actor.PID, TID: actor.PID, UID: 65534, Type: syscallrules.Result, BindingState: syscallrules.Live, ParentTGID: actor.ParentPID, OriginalID: unix.SYS_GETTID, Version: 2, OriginFlags: syscallrules.TraceOrigin})
	}
	return request, scene, events
}
func lifecycleInheritanceRaw(t *testing.T, events []syscallrules.Event) []byte {
	t.Helper()
	bundle := jobaudit.Bundle{}
	for _, event := range events {
		var raw bytes.Buffer
		if err := binary.Write(&raw, binary.LittleEndian, event); err != nil {
			t.Fatal(err)
		}
		bundle.Events = append(bundle.Events, jobaudit.Event{Stream: "syscalls", Raw: raw.Bytes()})
	}
	return serviceJSON(bundle)
}
func TestInheritanceOutcomeRequiresOriginalSyscallAndExactActor(t *testing.T) {
	request, scene, events := lifecycleInheritanceFixture(t)
	scene.Audit = lifecycleInheritanceRaw(t, events)
	if err := verifyServiceLifecycleInheritanceOutcomes(request, scene); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing-grandchild", "unknown-id", "wrong-start", "wrong-domain", "allowed-result", "different-filter-count", "parent-filter", "future-entry", "ambiguous-origin"} {
		t.Run(name, func(t *testing.T) {
			request, scene, events := lifecycleInheritanceFixture(t)
			switch name {
			case "missing-grandchild":
				events = events[:2]
			case "unknown-id":
				events[2].SyscallID = -1
				events[2].Flags = syscallrules.UnknownSyscallID
			case "wrong-start":
				events[1].TaskStartBootNS++
				events[1].TaskStartBootNS += 10000000
			case "wrong-domain":
				events[1].Cgroup++
			case "allowed-result":
				events[1].Result = int64(events[1].TID)
			case "different-filter-count":
				scene.Actors[1].Status = "Seccomp:\t2\nSeccomp_filters:\t1\n"
			case "parent-filter":
				scene.NodeSnapshot.Status = "Seccomp:\t2\nSeccomp_filters:\t1\n"
			case "future-entry":
				events[1].SyscallID = -1
				events[1].Flags = syscallrules.UnknownSyscallID
				events[1].OriginFlags = syscallrules.EntryOrigin
				events[1].EntryMonoNS = events[1].MonoNS + 1
			case "ambiguous-origin":
				events[1].OriginFlags = syscallrules.TraceOrigin | syscallrules.EntryOrigin
			}
			scene.Audit = lifecycleInheritanceRaw(t, events)
			if verifyServiceLifecycleInheritanceOutcomes(request, scene) == nil {
				t.Fatal("an unbound or inferred inheritance outcome passed")
			}
		})
	}
}

func TestInheritanceUsesValidatedEntryOriginWithoutChangingTheRawNumber(t *testing.T) {
	request, scene, events := lifecycleInheritanceFixture(t)
	for index := range events {
		event := &events[index]
		event.SyscallID = -1
		event.Flags = syscallrules.UnknownSyscallID
		event.OriginFlags = syscallrules.EntryOrigin
		event.EntryMonoNS = event.MonoNS - 1
	}
	scene.Audit = lifecycleInheritanceRaw(t, events)
	if err := verifyServiceLifecycleInheritanceOutcomes(request, scene); err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.SyscallID != -1 {
			t.Fatal("the inherited outcome changed a raw syscall number")
		}
	}
}

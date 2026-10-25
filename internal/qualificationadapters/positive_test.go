//go:build agentgate_native_evidence

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

func TestManagedReadbackRejectsChangedProcessOrPolicy(t *testing.T) {
	request, _, receipt := actualFixture(t)
	receipt.FinalActive = receipt.Active
	if !managedUnprivilegedReadback(request, receipt) {
		t.Fatal("the measured fixed actor lost its managed profile readback")
	}
	for name, change := range map[string]func(){
		"policy uid":     func() { request.Document.Runtime.UID = 0 },
		"foreign domain": func() { receipt.FinalActive.Cgroup = "0::/foreign" },
		"effective capability": func() {
			receipt.Active.Status = strings.Replace(receipt.Active.Status, "CapEff:\t0000000000000000", "CapEff:\t0000000000000001", 1)
		},
		"no new privileges": func() {
			receipt.FinalActive.Status = strings.Replace(receipt.FinalActive.Status, "NoNewPrivs:\t1", "NoNewPrivs:\t0", 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			request, _, receipt = actualFixture(t)
			receipt.FinalActive = receipt.Active
			change()
			if managedUnprivilegedReadback(request, receipt) {
				t.Fatal("changed policy or process status supplied managed readback credit")
			}
		})
	}
}

func TestActualPositiveSubtreeNeedsBoundFileAndResult(t *testing.T) {
	request, _, receipt := actualFixture(t)
	calls, files, err := verifyCandidateStreams(receipt)
	if err != nil {
		t.Fatal(err)
	}
	request.Document.Files.Rules = request.Document.Files.Rules[:1]
	rule := &request.Document.Files.Rules[0]
	rule.Selector.Kind = "subtree"
	rule.Selector.Path = filepath.Dir(rule.Selector.Path)
	rule.Operations = []string{"read", "write"}
	want := "explicit-allow:" + digestJSON(*rule)
	proved := positiveCases(request, receipt, calls, files)
	if !slices.Contains(proved["fs.read.v1"], want) || !slices.Contains(proved["fs.write.v1"], want) ||
		len(proved["fs.rules.v1"]) != 0 {
		t.Fatal("the measured subtree did not supply its two file cases", proved)
	}
	overlap := *rule
	overlap.ID = "more-specific"
	overlap.Selector.Kind = "exact"
	overlap.Selector.Path += "/input"
	overlap.Operations = []string{"read"}
	request.Document.Files.Rules = append(request.Document.Files.Rules, overlap)
	proved = positiveCases(request, receipt, calls, files)
	if slices.Contains(proved["fs.read.v1"], want) || !slices.Contains(proved["fs.write.v1"], want) {
		t.Fatal("overlapping file rules supplied ambiguous read credit", proved)
	}
	request.Document.Files.Rules = request.Document.Files.Rules[:1]
	for i := range files {
		copy(files[i].Path[:], []byte(rule.Selector.Path+"-foreign/input"))
	}
	proved = positiveCases(request, receipt, calls, files)
	if slices.Contains(proved["fs.read.v1"], want) || slices.Contains(proved["fs.write.v1"], want) {
		t.Fatal("a sibling prefix supplied a subtree case", proved)
	}
}

func TestFileUseRejectsForeignOrUnrelatedResult(t *testing.T) {
	receipt := candidateReceipt{DomainID: 42, Generation: 2, Active: processSnapshot{PID: 101, MonoNS: 100}, DeadlineNS: 2_000_000}
	event := kernel.Event{Generation: 2, Cgroup: 42, MonoNS: 120, PID: 101, UID: 65534, Hook: 0, Allowed: 1}
	copy(event.Path[:], "/owned/input")
	call := syscallrules.Event{Sequence: 3, Domain: 42, Cgroup: 42, Generation: 2, MonoNS: 130,
		SyscallID: unix.SYS_READ, OriginalID: unix.SYS_READ, Result: 1, TGID: 101, TID: 101,
		UID: 65534, Type: syscallrules.Result, BindingState: syscallrules.Live,
		Version: 2, OriginFlags: syscallrules.TraceOrigin}
	witness := func(c syscallrules.Event, e kernel.Event) bool {
		return observedFileUse([]syscallrules.Event{c}, []kernel.Event{e}, receipt, 2, 0, unix.SYS_READ, 1, "subtree", "/owned")
	}
	if !witness(call, event) {
		t.Fatal("the owned file and syscall result lost their join")
	}
	for name, mutate := range map[string]func(*syscallrules.Event, *kernel.Event){
		"foreign domain":   func(_ *syscallrules.Event, e *kernel.Event) { e.Cgroup++ },
		"foreign actor":    func(_ *syscallrules.Event, e *kernel.Event) { e.PID++ },
		"foreign result":   func(c *syscallrules.Event, _ *kernel.Event) { c.TGID++ },
		"wrong generation": func(_ *syscallrules.Event, e *kernel.Event) { e.Generation++ },
		"denied file":      func(_ *syscallrules.Event, e *kernel.Event) { e.Allowed = 0 },
		"failed syscall":   func(c *syscallrules.Event, _ *kernel.Event) { c.Result = -int64(unix.EPERM) },
		"early result":     func(c *syscallrules.Event, _ *kernel.Event) { c.Sequence = 2 },
		"unrelated result": func(c *syscallrules.Event, _ *kernel.Event) { c.MonoNS = 1_000_121 },
		"sibling path": func(_ *syscallrules.Event, e *kernel.Event) {
			e.Path = [160]byte{}
			copy(e.Path[:], "/owned-other/input")
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, e := call, event
			mutate(&c, &e)
			if witness(c, e) {
				t.Fatal("a changed file or result supplied a subtree case")
			}
		})
	}
}

func TestAnonymousMemoryCreditNeedsLiveOwnedLSMAndSyscallPair(t *testing.T) {
	receipt := candidateReceipt{DomainID: 42, Generation: 2, Active: processSnapshot{PID: 101, MonoNS: 100}, DeadlineNS: 2_000_000}
	event := kernel.Event{Generation: 2, Cgroup: 42, MonoNS: 120, PID: 101, UID: 65534, Hook: 14, Allowed: 1}
	call := syscallrules.Event{Sequence: 3, Domain: 42, Cgroup: 42, Generation: 2, MonoNS: 130,
		SyscallID: -1, OriginalID: unix.SYS_MMAP, Result: 0x1000, TGID: 101, TID: 101,
		UID: 65534, Type: syscallrules.Result, BindingState: syscallrules.Live,
		Flags: syscallrules.UnknownSyscallID, Version: 2, OriginFlags: syscallrules.EntryOrigin, EntryMonoNS: 110}
	witness := func(c syscallrules.Event, e kernel.Event) bool {
		return observedAnonymousMemory([]syscallrules.Event{c}, []kernel.Event{e}, receipt, 2, 14, unix.SYS_MMAP)
	}
	if !witness(call, event) {
		t.Fatal("the owned anonymous mapping lost its LSM/result join")
	}
	for name, mutate := range map[string]func(*syscallrules.Event, *kernel.Event){
		"foreign domain":      func(_ *syscallrules.Event, e *kernel.Event) { e.Cgroup++ },
		"foreign result root": func(c *syscallrules.Event, _ *kernel.Event) { c.Domain++ },
		"foreign actor":       func(_ *syscallrules.Event, e *kernel.Event) { e.PID++ },
		"wrong generation":    func(_ *syscallrules.Event, e *kernel.Event) { e.Generation++ },
		"denied mapping":      func(_ *syscallrules.Event, e *kernel.Event) { e.Allowed = 0 },
		"wrong hook":          func(_ *syscallrules.Event, e *kernel.Event) { e.Hook = 15 },
		"failed syscall":      func(c *syscallrules.Event, _ *kernel.Event) { c.Result = -int64(unix.EPERM) },
		"before filter":       func(c *syscallrules.Event, _ *kernel.Event) { c.Sequence = 2 },
		"late result":         func(c *syscallrules.Event, _ *kernel.Event) { c.MonoNS = 1_000_121 },
		"unrelated original":  func(c *syscallrules.Event, _ *kernel.Event) { c.OriginalID = unix.SYS_MPROTECT },
		"foreign entry":       func(c *syscallrules.Event, _ *kernel.Event) { c.EntryMonoNS = 121 },
	} {
		t.Run(name, func(t *testing.T) {
			c, e := call, event
			mutate(&c, &e)
			if witness(c, e) {
				t.Fatal("an unrelated memory event supplied policy credit")
			}
		})
	}
	event.Hook, call.OriginalID, call.Result = 15, unix.SYS_MPROTECT, 0
	if !observedAnonymousMemory([]syscallrules.Event{call}, []kernel.Event{event}, receipt, 2, 15, unix.SYS_MPROTECT) {
		t.Fatal("the owned successful protection change lost its join")
	}
}

func TestActualPositiveCasesNeedSuccessfulCallsAndExactFilePaths(t *testing.T) {
	request, _, receipt := actualFixture(t)
	calls, files, err := verifyCandidateStreams(receipt)
	if err != nil {
		t.Fatal(err)
	}
	proved := positiveCases(request, receipt, calls, files)
	if len(proved["runtime.explicit-syscalls.v2"]) != 6 || len(proved["fs.read.v1"]) != 1 || len(proved["fs.write.v1"]) != 1 || !slices.Equal(proved["fs.rules.v1"], []string{"exact-path-match"}) {
		t.Fatal("the actual positive facts differ", proved)
	}
	for i := range files {
		files[i].Path = [160]byte{}
	}
	proved = positiveCases(request, receipt, calls, files)
	if len(proved["fs.read.v1"]) != 0 || len(proved["fs.write.v1"]) != 0 {
		t.Fatal("a changed path supplied a rule witness")
	}
	for i := range calls {
		if calls[i].SyscallID == unix.SYS_READ {
			calls[i].Result = -int64(unix.EPERM)
		}
	}
	proved = positiveCases(request, receipt, calls, files)
	if slices.Contains(proved["runtime.explicit-syscalls.v2"], "explicit-allow:"+digestJSON("read")) {
		t.Fatal("a failed read supplied a positive witness")
	}
	for i := range calls {
		if calls[i].SyscallID == unix.SYS_SECCOMP {
			calls[i].Result = -int64(unix.EPERM)
		}
	}
	if len(positiveCases(request, receipt, calls, files)) != 0 {
		t.Fatal("a failed filter install supplied a positive witness")
	}
}

func TestPositiveSyscallWitnessUsesCompilerNumberAndActiveWindow(t *testing.T) {
	request, _, receipt := actualFixture(t)
	calls, files, err := verifyCandidateStreams(receipt)
	if err != nil {
		t.Fatal(err)
	}
	request.Document.Runtime.Seccomp.AllowSyscalls = append(request.Document.Runtime.Seccomp.AllowSyscalls, "gettid")
	var witness syscallrules.Event
	for _, call := range calls {
		if call.Type == syscallrules.Result && call.SyscallID == unix.SYS_READ && call.Result >= 0 {
			witness = call
			break
		}
	}
	if witness.Sequence == 0 {
		t.Fatal("the actual fixture lacks a successful kernel call")
	}
	witness.Sequence++
	for _, call := range calls {
		if call.Sequence >= witness.Sequence {
			witness.Sequence = call.Sequence + 1
		}
	}
	witness.SyscallID = unix.SYS_GETTID
	witness.OriginalID = unix.SYS_GETTID
	witness.Version = 2
	witness.OriginFlags = syscallrules.TraceOrigin
	witness.EntryMonoNS = 0
	witness.Flags = 0
	witness.Result = 1
	witness.MonoNS = receipt.Active.MonoNS + 1
	calls = append(calls, witness)
	caseName := "explicit-allow:" + digestJSON("gettid")
	if !slices.Contains(positiveCases(request, receipt, calls, files)["runtime.explicit-syscalls.v2"], caseName) {
		t.Fatal("an observed supported call gained no case")
	}
	calls[len(calls)-1].Sequence = 1
	if slices.Contains(positiveCases(request, receipt, calls, files)["runtime.explicit-syscalls.v2"], caseName) {
		t.Fatal("a call before filter installation gained a case")
	}
	calls[len(calls)-1].Sequence = witness.Sequence
	calls[len(calls)-1].MonoNS = receipt.DeadlineNS
	if slices.Contains(positiveCases(request, receipt, calls, files)["runtime.explicit-syscalls.v2"], caseName) {
		t.Fatal("a call at the cutoff gained a case")
	}
	calls[len(calls)-1].MonoNS = receipt.Active.MonoNS + 1
	calls[len(calls)-1].Result = -int64(unix.EPERM)
	if slices.Contains(positiveCases(request, receipt, calls, files)["runtime.explicit-syscalls.v2"], caseName) {
		t.Fatal("a denied call gained a positive case")
	}
}

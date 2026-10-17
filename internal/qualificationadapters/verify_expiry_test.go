// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"encoding/json"
	"testing"

	"alloyium.local/kernel-poc/internal/execbroker"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

func TestExpiryEventsRejectAllocationSuccessAndOtherOperations(t *testing.T) {
	receipt := candidateReceipt{DeadlineNS: 100, Expiry: &expiryReceipt{ResumedMonoNS: 110}}
	event := syscallrules.Event{Type: syscallrules.Result, SyscallID: unix.SYS_BRK, Result: -int64(unix.EPERM), MonoNS: 120, BindingState: syscallrules.Expired}
	if err := verifyExpiryEvent(receipt, event); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*syscallrules.Event){
		"allocation succeeds":         func(e *syscallrules.Event) { e.Result = 4096 },
		"wrong call":                  func(e *syscallrules.Event) { e.SyscallID = unix.SYS_MMAP },
		"before actual resume":        func(e *syscallrules.Event) { e.MonoNS = 105 },
		"live assertion after cutoff": func(e *syscallrules.Event) { e.BindingState = syscallrules.Live },
	} {
		t.Run(name, func(t *testing.T) {
			changed := event
			change(&changed)
			if verifyExpiryEvent(receipt, changed) == nil {
				t.Fatal("an unsupported expiry witness passed")
			}
		})
	}
}

func TestHeapCoverageRequiresBrokerAndKernelCutoffAgreement(t *testing.T) {
	request := adapterRequest(t)
	request.Document.Runtime.Memory = &policy.MemoryPolicy{Heap: "allow"}
	request.Document.Runtime.Seccomp.AllowSyscalls = append(request.Document.Runtime.Seccomp.AllowSyscalls, "brk")
	receipt := candidateReceipt{DomainID: 5, Generation: 1, DeadlineNS: 100, Active: processSnapshot{PID: 42, MonoNS: 1}, Expiry: &expiryReceipt{ResumedMonoNS: 110}}
	records := map[uint32]scalarRecord{24: {Result: 4096}, 25: {Result: 8192}, 26: {Result: 4096}}
	calls := []syscallrules.Event{}
	decisions := []execbroker.Decision{}
	for i, result := range []int64{4096, 8192, 4096, -int64(unix.EPERM)} {
		mono := uint64(10 + i*10)
		reason := "continue-live-heap"
		continued := true
		if i == 3 {
			mono = 120
			reason = "expired-binding"
			continued = false
		}
		calls = append(calls, syscallrules.Event{Type: syscallrules.Result, SyscallID: unix.SYS_BRK, Result: result, MonoNS: mono + 1})
		decisions = append(decisions, execbroker.Decision{Protocol: "agentgate.exec-decision.v1", Domain: 5, Generation: 1, NotificationID: uint64(i + 1), MonotonicNS: mono, PID: 42, Syscall: unix.SYS_BRK, Continued: continued, Reason: reason})
	}
	encode := func() {
		receipt.Broker.Audit = nil
		for _, d := range decisions {
			raw, _ := json.Marshal(d)
			receipt.Broker.Audit = append(receipt.Broker.Audit, append(raw, '\n')...)
		}
	}
	encode()
	if err := verifyLiveHeapDecisions(request, receipt, calls, records); err != nil {
		t.Fatal(err)
	}
	decisions[3].Continued = true
	encode()
	if verifyLiveHeapDecisions(request, receipt, calls, records) == nil {
		t.Fatal("an expired continuation passed")
	}
	decisions[3].Continued = false
	encode()
	calls[3].Result = 8192
	if verifyLiveHeapDecisions(request, receipt, calls, records) == nil {
		t.Fatal("an actual successful expired allocation passed")
	}
}

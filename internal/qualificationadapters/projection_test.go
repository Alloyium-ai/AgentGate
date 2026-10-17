// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"testing"

	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

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

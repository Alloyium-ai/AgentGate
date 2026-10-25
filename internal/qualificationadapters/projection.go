// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

func noCreateFacts(receipt candidateReceipt, calls []syscallrules.Event) error {
	wanted := strconv.Itoa(receipt.Active.PID)
	for _, members := range []string{receipt.ActiveMembers, receipt.FinalMembers} {
		if strings.Join(strings.Fields(members), " ") != wanted {
			return errors.New("the candidate domain did not retain one exact process")
		}
	}
	for _, number := range []int64{unix.SYS_CLONE, unix.SYS_FORK, unix.SYS_VFORK} {
		if !observedCall(calls, receipt, number, -int64(unix.EPERM)) {
			return errors.New("the candidate lacks an actual legacy process creation denial")
		}
	}
	if !observedCall(calls, receipt, unix.SYS_CLONE3, -int64(unix.ENOSYS)) {
		return errors.New("the candidate lacks its clone3 denial")
	}
	return nil
}

func verifyProcessProjection(request qualification.Request, receipt candidateReceipt, calls []syscallrules.Event, records map[uint32]scalarRecord) error {
	if slices.Contains(request.Document.Runtime.Seccomp.AllowSyscalls, "clone") {
		if err := positiveCloneFacts(receipt, calls, records); err != nil {
			return err
		}
	} else if err := noCreateFacts(receipt, calls); err != nil {
		return err
	}
	final := receipt.FinalActive
	if err := validateProcess(final, false, "2"); err != nil {
		return err
	}
	projection := receipt
	projection.Active = final
	if err := verifyActorDescriptors(request, projection); err != nil {
		return err
	}
	if final.PID != receipt.Active.PID || final.StartTimeTicks != receipt.Active.StartTimeTicks || final.Executable != receipt.Active.Executable || final.ExecutableSHA256 != receipt.Active.ExecutableSHA256 || final.MonoNS <= receipt.Active.MonoNS || final.MonoNS >= receipt.DeadlineNS || !memberSnapshot(final, receipt.Domain) {
		return errors.New("the process creation denial projection changed its actor")
	}
	// The clone branch proves one child exited in the measured root. It does
	// not prove a grandchild, inherited file rules, or an admitted workload.
	return nil
}

func positiveCloneFacts(receipt candidateReceipt, calls []syscallrules.Event, records map[uint32]scalarRecord) error {
	child := records[50].Result
	if child <= 0 || records[53].Result != child || records[54].Result != 90<<8 ||
		!observedCall(calls, receipt, unix.SYS_CLONE, child) || !observedCall(calls, receipt, unix.SYS_WAIT4, child) {
		return errors.New("the candidate lacks a successful and reaped clone witness")
	}
	if strings.Join(strings.Fields(receipt.ActiveMembers), " ") != strconv.Itoa(receipt.Active.PID) ||
		strings.Join(strings.Fields(receipt.FinalMembers), " ") != strconv.Itoa(receipt.Active.PID) {
		return errors.New("the candidate retained a second process")
	}
	for _, denial := range []struct{ number, result int64 }{{unix.SYS_FORK, -int64(unix.EPERM)}, {unix.SYS_VFORK, -int64(unix.EPERM)}, {unix.SYS_CLONE3, -int64(unix.ENOSYS)}} {
		if !observedCall(calls, receipt, denial.number, denial.result) {
			return errors.New("the candidate lacks the remaining process denials")
		}
	}
	count, childReturns := 0, 0
	for _, call := range calls {
		if call.Type == syscallrules.Result && call.TGID == uint32(child) && call.TID == uint32(child) && call.SyscallID == unix.SYS_CLONE && call.Result == 0 && call.ParentTGID == uint32(receipt.Active.PID) && call.Cgroup == receipt.DomainID && call.MonoNS >= receipt.Active.MonoNS && call.MonoNS < receipt.DeadlineNS {
			childReturns++
		}
		if call.Type == syscallrules.TaskExit && call.TGID == uint32(child) {
			if call.ParentTGID != uint32(receipt.Active.PID) || call.ExitCode != 90<<8 || call.Cgroup != receipt.DomainID ||
				call.MonoNS < receipt.Active.MonoNS || call.MonoNS >= receipt.DeadlineNS {
				return errors.New("the child's same-domain exit differs")
			}
			count++
		}
	}
	if count != 1 || childReturns != 1 {
		return errors.New("the child lacks one same-domain clone return and exit")
	}
	return nil
}

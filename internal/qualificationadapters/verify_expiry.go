// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"errors"
	"reflect"

	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

func verifyExpiryEvent(receipt candidateReceipt, event syscallrules.Event) error {
	if event.MonoNS < receipt.DeadlineNS {
		if event.BindingState != syscallrules.Live {
			return errors.New("the live candidate audit binding differs")
		}
		return nil
	}
	if receipt.Expiry == nil || event.BindingState != syscallrules.Expired || event.MonoNS < receipt.Expiry.ResumedMonoNS {
		return errors.New("the expired candidate audit binding differs")
	}
	if event.Type == syscallrules.TaskExit && event.ExitCode == 0 {
		return nil
	}
	if event.Type != syscallrules.Result {
		return errors.New("the expiry phase contains an unexpected event")
	}
	if event.SyscallID == unix.SYS_BRK && event.Result == -int64(unix.EPERM) {
		return nil
	}
	return errors.New("the expiry phase contains an unproved syscall or allocation")
}

func verifyExpiryBinding(request qualification.Request, result qualification.Result, receipt candidateReceipt, calls []syscallrules.Event) error {
	if !candidateHeap(request) {
		if receipt.Expiry != nil {
			return errors.New("the candidate lacks the heap grant used by the expiry phase")
		}
		return nil
	}
	if receipt.Expiry == nil {
		return errors.New("the heap grant lacks its fixed allocation expiry witness")
	}
	phase := receipt.Expiry
	held := phase.Held
	if err := validateProcess(held, true, "2"); err != nil {
		return err
	}
	projection := receipt
	projection.Active = held
	if err := verifyActorDescriptors(request, projection); err != nil {
		return err
	}
	if held.PID != receipt.Active.PID || held.StartTimeTicks != receipt.Active.StartTimeTicks || held.Executable != receipt.Active.Executable || held.ExecutableSHA256 != receipt.Active.ExecutableSHA256 || !memberSnapshot(held, receipt.Domain) || held.MonoNS <= receipt.Active.MonoNS || held.MonoNS >= receipt.DeadlineNS || phase.MapsMonoNS < held.MonoNS || phase.MapsMonoNS >= receipt.DeadlineNS || !reflect.DeepEqual(phase.Maps, receipt.Before) {
		return errors.New("the expiry hold identity or candidate maps differ")
	}
	if phase.ResumedMonoNS < receipt.DeadlineNS || phase.ResumedMonoNS-receipt.DeadlineNS > 1_000_000_000 || result.FinishedMonoNS <= phase.ResumedMonoNS || result.FinishedMonoNS-phase.ResumedMonoNS > 5_000_000_000 {
		return errors.New("the expiry release or completion clock differs")
	}
	counts := map[int64]int{}
	exits := 0
	for _, call := range calls {
		if call.MonoNS < receipt.DeadlineNS {
			continue
		}
		if err := verifyExpiryEvent(receipt, call); err != nil {
			return err
		}
		if call.Type == syscallrules.TaskExit {
			exits++
		} else {
			counts[call.SyscallID]++
		}
	}
	if exits != 1 || counts[unix.SYS_BRK] != 1 || len(counts) != 1 {
		return errors.New("the expiry phase lacks its exact denied allocation or task exit")
	}
	return nil
}

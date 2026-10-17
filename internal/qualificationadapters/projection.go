// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"errors"
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

func verifyNoCreateProjection(request qualification.Request, receipt candidateReceipt, calls []syscallrules.Event) error {
	if err := noCreateFacts(receipt, calls); err != nil {
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
	// These exact denials do not prove inheritance in a child or grandchild.
	return nil
}

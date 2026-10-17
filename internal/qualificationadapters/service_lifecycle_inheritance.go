// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"errors"
	"slices"
	"strconv"

	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

// This checks only actual descendant outcomes. The caller must also verify the
// measured helper's install acknowledgement and exact sealed filter frames.
// It supplies no coverage by itself and cannot replace the candidate denial.
func verifyServiceLifecycleInheritanceOutcomes(request qualification.Request, scene serviceLifecycleScene) error {
	if request.Document.Runtime == nil || !slices.Contains(request.Document.Runtime.Seccomp.AllowSyscalls, "gettid") || slices.Contains(request.Document.Runtime.Seccomp.AllowSyscalls, "getppid") {
		return errors.New("the fixed inheritance implication differs from the candidate selectors")
	}
	return verifyServiceLifecycleActorOutcomes(scene)
}

// Every successful fixture scene joins each observed PID/start time to its
// signed original syscall outcome, including scenes with no inheritance claim.
func verifyServiceLifecycleActorOutcomes(scene serviceLifecycleScene) error {
	actors, err := DecodeLifecycleRecords(scene.Wire)
	if err != nil || len(scene.Actors) != 3 {
		return errors.New("the actual inheritance actor records are incomplete")
	}
	parent := processFields(scene.NodeSnapshot.Status)
	if parent["Seccomp"] != "0" || parent["Seccomp_filters"] != "0" {
		return errors.New("the fixture node already carries an unmeasured filter")
	}
	bundle, err := jobauthority.DecodeAuditBundle(scene.Audit)
	if err != nil {
		return err
	}
	for index, actor := range actors {
		snapshot := scene.Actors[index]
		fields := processFields(snapshot.Status)
		count, err := strconv.ParseUint(fields["Seccomp_filters"], 10, 32)
		if err != nil || fields["Seccomp"] != "2" || count != 2 || snapshot.PID != int(actor.PID) || actor.GettidResult != -int32(unix.EPERM) {
			return errors.New("the actual inherited filter count or worker outcome differs")
		}
		found := 0
		for _, raw := range bundle.Events {
			if raw.Stream != "syscalls" {
				continue
			}
			event, err := syscallrules.Decode(raw.Raw)
			if err != nil {
				return err
			}
			number, known := event.OriginalNumber()
			if event.TGID != actor.PID || event.Type != syscallrules.Result || !known || number != unix.SYS_GETTID {
				continue
			}
			binding := scene.Active.Record.Binding
			if event.Result != -int64(unix.EPERM) || event.BindingState != syscallrules.Live || event.Domain != binding.CgroupID || event.Cgroup != binding.CgroupID || event.Generation != binding.Generation || event.TID != actor.PID || event.UID != 65534 || event.ParentTGID != actor.ParentPID || event.TaskStartBootNS/10000000 != snapshot.StartTimeTicks || event.MonoNS >= snapshot.MonoNS {
				return errors.New("the original descendant syscall outcome or identity differs")
			}
			found++
		}
		if found != 1 {
			return errors.New("the original descendant gettid outcome is absent or repeated")
		}
	}
	return nil
}

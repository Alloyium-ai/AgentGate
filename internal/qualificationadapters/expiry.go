// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"errors"
	"slices"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/qualification"
)

func candidateHeap(request qualification.Request) bool {
	return request.Document.Runtime.Memory != nil && request.Document.Runtime.Memory.Heap == "allow" && slices.Contains(request.Document.Runtime.Seccomp.AllowSyscalls, "brk")
}

func (a *candidateDenial) expireHeap(ctx context.Context, request qualification.Request, actor *actorProcess, io *ownedIO, group *enforcement.Group, plan enforcement.Plan, receipt *candidateReceipt) error {
	if err := actor.waitRecord(io.output, 100); err != nil {
		return err
	}
	if err := actor.cmd.Process.Signal(syscall.SIGSTOP); err != nil {
		return err
	}
	until := time.Now().Add(3 * time.Second)
	var held processSnapshot
	for {
		var err error
		held, err = inspectProcess(actor.cmd.Process.Pid, receipt.Active.Executable, receipt.Active.ExecutableSHA256)
		if err != nil {
			return err
		}
		if validateProcess(held, true, "2") == nil {
			break
		}
		if time.Now().After(until) {
			return errors.New("the expiry worker did not enter its measured hold")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
	projection := *receipt
	projection.Active = held
	if err := verifyActorDescriptors(request, projection); err != nil {
		return err
	}
	if !memberSnapshot(held, receipt.Domain) || held.StartTimeTicks != receipt.Active.StartTimeTicks || held.MonoNS >= receipt.DeadlineNS {
		return errors.New("the expiry worker changed or reached cutoff before its hold")
	}
	maps, err := snapshotMaps(group, plan, request)
	if err != nil {
		return err
	}
	receipt.Expiry = &expiryReceipt{Held: held, Maps: maps}
	now, err := kernel.MonotonicNS()
	if err != nil {
		return err
	}
	receipt.Expiry.MapsMonoNS = now
	if now >= receipt.DeadlineNS {
		return errors.New("the candidate cutoff preceded its complete expiry readback")
	}
	delay := time.Duration(receipt.DeadlineNS-now) + 10*time.Millisecond
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(delay):
	}
	receipt.Expiry.ResumedMonoNS, err = kernel.MonotonicNS()
	if err != nil {
		return err
	}
	if receipt.Expiry.ResumedMonoNS < receipt.DeadlineNS {
		return errors.New("the expiry release preceded the exact candidate cutoff")
	}
	return actor.resume()
}

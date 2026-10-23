// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"errors"
	"path/filepath"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/lifecycle"
)

const serviceLifecycleLossProtocol = "agentgate.fixed-watchdog-loss.v2"

type serviceLifecycleExit struct {
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks,string"`
	ObservedNS uint64 `json:"observed_mono_ns,string"`
	ExitCode   int    `json:"exit_code"`
	Signal     int    `json:"signal"`
	Error      string `json:"error"`
}

type serviceLifecycleLoss struct {
	Protocol         string                          `json:"protocol"`
	Watchdog         processSnapshot                 `json:"watchdog"`
	Signal           int                             `json:"signal"`
	SignalStartedNS  uint64                          `json:"signal_started_mono_ns,string"`
	SignalFinishedNS uint64                          `json:"signal_finished_mono_ns,string"`
	SignalError      string                          `json:"signal_error"`
	WatchdogExit     serviceLifecycleExit            `json:"watchdog_exit"`
	NodeExit         serviceLifecycleExit            `json:"node_exit"`
	NodeAfterFault   *processSnapshot                `json:"node_after_fault,omitempty"`
	Journal          serviceLifecycleJournalReadback `json:"journal"`
	TerminalFile     serviceLifecycleAuditFile       `json:"terminal_file"`
}

type serviceLifecycleStopRecord struct {
	Protocol string             `json:"protocol"`
	Evidence lifecycle.Evidence `json:"evidence"`
	Terminal lifecycle.Terminal `json:"terminal"`
}

// The parent kills only its measured watchdog. The node must stop the domain
// without a parent stop command, revocation or expiry.
func runServiceLifecycleWatchdogLoss(ctx context.Context, scene *serviceLifecycleScene, node, watchdog *serviceLifecycleProcess, path, hash string) error {
	loss := &serviceLifecycleLoss{Protocol: serviceLifecycleLossProtocol, Signal: int(syscall.SIGKILL)}
	scene.Loss = loss
	var err error
	loss.Watchdog, err = inspectProcess(watchdog.pid, path, hash)
	if err != nil {
		return err
	}
	cutoff := scene.Active.Record.Evidence[len(scene.Active.Record.Evidence)-1].EffectiveDeadlineNS
	loss.SignalStartedNS = serviceMono()
	if cutoff <= loss.SignalStartedNS || cutoff-loss.SignalStartedNS < uint64(time.Second) {
		return errors.New("the watchdog loss cannot precede the grant cutoff")
	}
	err = watchdog.signal(syscall.SIGKILL)
	loss.SignalError = serviceError(err)
	loss.SignalFinishedNS = serviceMono()
	if err != nil {
		return err
	}
	loss.WatchdogExit, err = waitServiceLifecycleExit(ctx, watchdog, time.Second)
	if err != nil {
		return err
	}
	loss.Journal, err = waitServiceLifecycleLossJournal(ctx, *scene)
	if err != nil {
		return err
	}
	select {
	case <-node.done:
		loss.NodeExit, err = waitServiceLifecycleExit(ctx, node, time.Second)
	default:
		snapshot, inspectErr := inspectProcess(node.pid, scene.NodeSnapshot.Executable, scene.NodeSnapshot.ExecutableSHA256)
		if inspectErr == nil {
			loss.NodeAfterFault = &snapshot
		} else {
			loss.NodeExit, err = waitServiceLifecycleExit(ctx, node, time.Second)
			if err != nil {
				err = errors.Join(inspectErr, err)
			}
		}
	}
	if err != nil {
		return err
	}
	auditPath, err := serviceLifecycleAuditPath(*scene)
	if err != nil {
		return err
	}
	loss.TerminalFile = serviceLifecycleAuditFile{Path: auditPath[:len(auditPath)-len(filepath.Ext(auditPath))] + ".terminal.json", StartedNS: serviceMono()}
	loss.TerminalFile.Raw, err = readServiceLifecycleOwned(loss.TerminalFile.Path, 2<<20)
	loss.TerminalFile.FinishedNS = serviceMono()
	loss.TerminalFile.Error = serviceError(err)
	loss.TerminalFile.SHA256 = digestBytes(loss.TerminalFile.Raw)
	if err != nil {
		loss.TerminalFile.Errno = serviceLifecycleErrno(err)
		return err
	}
	return captureServiceLifecycleAudit(scene)
}

func waitServiceLifecycleExit(ctx context.Context, process *serviceLifecycleProcess, timeout time.Duration) (out serviceLifecycleExit, err error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return out, ctx.Err()
	case <-timer.C:
		return out, errors.New("the fixed fixture natural exit is unconfirmed")
	case <-process.done:
	}
	process.mu.Lock()
	defer process.mu.Unlock()
	out = serviceLifecycleExit{PID: process.pid, StartTicks: process.startTicks, ObservedNS: serviceMono(), ExitCode: -1, Error: serviceError(process.result)}
	if process.command.ProcessState == nil {
		return out, errors.New("the actual fixture wait status is absent")
	}
	out.ExitCode = process.command.ProcessState.ExitCode()
	status, ok := process.command.ProcessState.Sys().(syscall.WaitStatus)
	if !ok {
		return out, errors.New("the actual fixture wait status differs")
	}
	if status.Signaled() {
		out.Signal = int(status.Signal())
	}
	return out, nil
}

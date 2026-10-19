// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/qualification"
	"golang.org/x/sys/unix"
)

const serviceNodeLossProtocol = "agentgate.fixed-node-loss.v1"

// The parent kills only the measured node. The independent watchdog must
// kill the worker tree while it stays alive. Replacement-node recovery then
// reconciles the empty domain and records an incomplete terminal.
type serviceLifecycleNodeLoss struct {
	Protocol           string                           `json:"protocol"`
	Node               processSnapshot                  `json:"node"`
	Signal             int                              `json:"signal"`
	SignalStartedNS    uint64                           `json:"signal_started_mono_ns,string"`
	SignalFinishedNS   uint64                           `json:"signal_finished_mono_ns,string"`
	NodeExit           serviceLifecycleExit             `json:"node_exit"`
	WatchdogAfter      processSnapshot                  `json:"watchdog_after"`
	WatchdogStore      serviceLifecycleWatchdogReadback `json:"watchdog_store"`
	DomainEmptyNS      uint64                           `json:"domain_empty_mono_ns,string"`
	BeforeRecovery     []serviceLifecycleAfterProcess   `json:"before_recovery"`
	RecoveryStartedNS  uint64                           `json:"recovery_started_mono_ns,string"`
	RestartedNode      processSnapshot                  `json:"restarted_node"`
	RecoveryFinishedNS uint64                           `json:"recovery_finished_mono_ns,string"`
	Journal            serviceLifecycleJournalReadback  `json:"journal"`
	TerminalFile       serviceLifecycleAuditFile        `json:"terminal_file"`
}

func runServiceLifecycleNodeLoss(ctx context.Context, scene *serviceLifecycleScene, node, watchdog *serviceLifecycleProcess, watchdogPath, watchdogHash, nodePath, nodeHash string, authority *serviceLifecycleAuthority) error {
	loss := &serviceLifecycleNodeLoss{Protocol: serviceNodeLossProtocol, Signal: int(syscall.SIGKILL)}
	scene.NodeLoss = loss
	var err error
	loss.Node, err = inspectProcess(node.pid, scene.NodeSnapshot.Executable, scene.NodeSnapshot.ExecutableSHA256)
	if err != nil {
		return err
	}
	cutoff := scene.Active.Record.Evidence[len(scene.Active.Record.Evidence)-1].EffectiveDeadlineNS
	loss.SignalStartedNS = serviceMono()
	if cutoff <= loss.SignalStartedNS || cutoff-loss.SignalStartedNS < uint64(time.Second) {
		return errors.New("the node loss cannot precede the grant cutoff")
	}
	if err = node.signal(syscall.SIGKILL); err != nil {
		return err
	}
	loss.SignalFinishedNS = serviceMono()
	loss.NodeExit, err = waitServiceLifecycleExit(ctx, node, time.Second)
	if err != nil {
		return err
	}
	window, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		data, readErr := os.ReadFile(filepath.Join(scene.Domain, "cgroup.events"))
		store, storeErr := readServiceLifecycleWatchdog(window, *scene)
		if readErr == nil && strings.Contains("\n"+string(data), "\npopulated 0\n") && storeErr == nil && len(store.Rows) == 0 {
			loss.WatchdogStore = store
			loss.BeforeRecovery = serviceLifecycleAfter(scene.Actors)
			loss.DomainEmptyNS = serviceMono()
			if !serviceLifecycleActorsTerminated(scene.Actors, loss.BeforeRecovery) || loss.DomainEmptyNS >= cutoff {
				return errors.New("the watchdog descendant stop missed the grant cutoff")
			}
			break
		}
		select {
		case <-window.Done():
			return errors.Join(errors.New("the independent watchdog did not empty the node-loss worker tree"), readErr, storeErr, window.Err())
		case <-watchdog.done:
			return errors.New("the independent watchdog exited before node-loss cleanup")
		case <-tick.C:
		}
	}
	loss.WatchdogAfter, err = inspectProcess(watchdog.pid, watchdogPath, watchdogHash)
	if err != nil {
		return err
	}
	return recoverServiceLifecycleNodeLoss(ctx, scene, loss, nodePath, nodeHash, authority)
}

func recoverServiceLifecycleNodeLoss(ctx context.Context, scene *serviceLifecycleScene, loss *serviceLifecycleNodeLoss, path, hash string, authority *serviceLifecycleAuthority) (err error) {
	loss.RecoveryStartedNS = serviceMono()
	recovery, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start, err := sealedServiceLifecycleStart(scene.Start)
	if err != nil {
		return err
	}
	commands, childCommands, err := serviceLifecycleSocketpair()
	if err != nil {
		start.Close()
		return err
	}
	callbacks, childCallbacks, err := serviceLifecycleSocketpair()
	if err != nil {
		start.Close()
		commands.Close()
		childCommands.Close()
		return err
	}
	client, err := newServiceLifecycleHTTPClient(commands)
	if err != nil {
		start.Close()
		childCommands.Close()
		callbacks.Close()
		childCallbacks.Close()
		return err
	}
	defer client.close()
	server, err := serveServiceLifecycleAuthority(callbacks, authority)
	if err != nil {
		start.Close()
		childCommands.Close()
		childCallbacks.Close()
		return err
	}
	defer func() { err = errors.Join(err, server.close()) }()
	restarted, err := startServiceLifecycleProcess(recovery, path, hash, scene.Recipe.Spec.OwnedRoot, "node-restarted", []string{"qualification-fixture"}, []*os.File{start, childCommands, childCallbacks})
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, restarted.close()) }()
	loss.RestartedNode, err = inspectProcess(restarted.pid, path, hash)
	if err != nil {
		return err
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		_, errno, pins := serviceLifecycleFinalState(scene.Recipe)
		if errno == int(unix.ENOENT) && len(pins) == 0 {
			loss.RecoveryFinishedNS = serviceMono()
			break
		}
		select {
		case <-recovery.Done():
			return errors.New("the replacement node did not remove the empty domain and guard pins")
		case <-restarted.done:
			return errors.New("the replacement node exited before recovery cleanup")
		case <-tick.C:
		}
	}
	auditPath, err := serviceLifecycleAuditPath(*scene)
	if err != nil {
		return err
	}
	terminalPath := strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + ".terminal.json"
	var lastErr error
	for {
		journal, readErr := readServiceLifecycleJournal(recovery, *scene)
		if readErr == nil {
			var record lifecycle.Record
			readErr = lifecycle.DecodeTransport(bytes.NewReader(journal.Raw), &record)
			if readErr == nil && record.State == "stopped" {
				file := serviceLifecycleAuditFile{Path: terminalPath, StartedNS: serviceMono()}
				file.Raw, readErr = readServiceLifecycleOwned(file.Path, 2<<20)
				file.FinishedNS = serviceMono()
				file.Error = serviceError(readErr)
				file.SHA256 = digestBytes(file.Raw)
				if readErr == nil {
					loss.Journal, loss.TerminalFile = journal, file
					return nil
				}
				file.Errno = serviceLifecycleErrno(readErr)
				loss.TerminalFile = file
			}
		}
		lastErr = readErr
		select {
		case <-recovery.Done():
			return errors.Join(errors.New("the replacement node durable stop or incomplete terminal is unconfirmed"), lastErr, recovery.Err())
		case <-restarted.done:
			return errors.Join(errors.New("the replacement node exited before its durable stop"), lastErr)
		case <-tick.C:
		}
	}
}

func verifyServiceLifecycleNodeLoss(request qualification.Request, result qualification.Result, receipt serviceLifecycleReceipt, scene serviceLifecycleScene) error {
	if err := verifyServiceLifecycleActive(request, result, receipt, scene); err != nil {
		return err
	}
	loss := scene.NodeLoss
	if scene.Mode != "node-loss" || loss == nil || loss.Protocol != serviceNodeLossProtocol || scene.Loss != nil || scene.AuditFile != nil || len(scene.Audit) != 0 && !bytes.Equal(scene.Audit, []byte("null")) || len(scene.Calls) != 2 || scene.Calls[0].Path != "/fixture/prepare" || scene.Calls[1].Path != "/fixture/start" || scene.Stopped.Protocol != "" || scene.Repeat.Protocol != "" {
		return errors.New("the fixed node-loss scene scope differs")
	}
	cutoff := scene.Active.Record.Evidence[len(scene.Active.Record.Evidence)-1].EffectiveDeadlineNS
	if loss.Signal != int(syscall.SIGKILL) || loss.SignalStartedNS < scene.WatchdogState.FinishedNS || loss.SignalStartedNS <= loss.Node.MonoNS || loss.SignalFinishedNS < loss.SignalStartedNS || loss.SignalFinishedNS >= cutoff || loss.NodeExit.ObservedNS < loss.SignalFinishedNS || loss.DomainEmptyNS < loss.NodeExit.ObservedNS || loss.DomainEmptyNS >= cutoff || loss.WatchdogAfter.MonoNS < loss.DomainEmptyNS || loss.WatchdogAfter.MonoNS > result.FinishedMonoNS || loss.RecoveryStartedNS < loss.WatchdogAfter.MonoNS || loss.RecoveryFinishedNS < loss.RecoveryStartedNS || loss.RecoveryFinishedNS-loss.RecoveryStartedNS > uint64(10*time.Second) {
		return errors.New("the actual node-loss clock differs")
	}
	if !serviceLifecycleActorsTerminated(scene.Actors, loss.BeforeRecovery) || loss.RestartedNode.PID <= 1 || loss.RestartedNode.PID == loss.Node.PID || loss.RestartedNode.ExecutableSHA256 != request.Binding.ArtifactDigests["node"] || loss.RestartedNode.MonoNS < loss.RecoveryStartedNS || loss.RestartedNode.MonoNS > loss.RecoveryFinishedNS {
		return errors.New("the watchdog tree death or replacement node differs")
	}
	if loss.Node.PID != scene.NodeSnapshot.PID || loss.Node.StartTimeTicks != scene.NodeSnapshot.StartTimeTicks || loss.Node.ExecutableSHA256 != request.Binding.ArtifactDigests["node"] || loss.NodeExit.PID != loss.Node.PID || loss.NodeExit.StartTicks != loss.Node.StartTimeTicks || loss.NodeExit.Signal != int(syscall.SIGKILL) || loss.NodeExit.ExitCode != -1 || loss.NodeExit.Error == "" || loss.WatchdogAfter.PID <= 1 || loss.WatchdogAfter.PID == loss.Node.PID || loss.WatchdogAfter.ExecutableSHA256 != request.Binding.ArtifactDigests["watchdog"] {
		return errors.New("the measured node death or surviving watchdog differs")
	}
	for _, actor := range scene.Actors {
		if actor.MonoNS >= loss.SignalStartedNS {
			return errors.New("the node loss preceded a live worker tree")
		}
	}
	for _, call := range scene.Calls {
		if call.Status != 200 || call.MonoNS < result.StartedMonoNS || call.MonoNS >= loss.SignalStartedNS || verifyServiceLifecycleHTTPCall(call, scene) != nil {
			return errors.New("the node-loss command observation differs")
		}
	}
	for _, call := range scene.AuthorityCalls {
		if call.Operation == "revoke" {
			return errors.New("the node-loss scene contains a parent revocation")
		}
	}
	store := loss.WatchdogStore
	if store.Protocol != "agentgate.fixture-watchdog-readback.v1" || store.Path != scene.NodeConfig.WatchdogStore || store.Path != filepath.Join(scene.Recipe.Spec.OwnedRoot, "private/watchdog.db") || !validServiceLifecycleDatabase(store.Before) || store.Before != store.After || store.Before != scene.WatchdogState.Before || store.StartedNS < loss.NodeExit.ObservedNS || store.FinishedNS < store.StartedNS || store.FinishedNS > loss.DomainEmptyNS || len(store.Rows) != 0 {
		return errors.New("the independent watchdog stop readback differs")
	}
	record, err := verifyServiceLifecycleJournal(loss.Journal, scene)
	if err != nil || record.StopReason != "recovery-fail-closed" || loss.Journal.StartedNS < loss.RecoveryFinishedNS || loss.Journal.FinishedNS > result.FinishedMonoNS {
		return errors.New("the replacement node durable recovery differs")
	}
	auditPath, err := serviceLifecycleAuditPath(scene)
	if err != nil {
		return err
	}
	file := loss.TerminalFile
	if file.Path != strings.TrimSuffix(auditPath, filepath.Ext(auditPath))+".terminal.json" || file.Error != "" || file.Errno != 0 || len(file.Raw) == 0 || len(file.Raw) > 2<<20 || file.SHA256 != digestBytes(file.Raw) || file.StartedNS < loss.Journal.FinishedNS || file.FinishedNS < file.StartedNS || file.FinishedNS > result.FinishedMonoNS || uniqueJSON(file.Raw) != nil {
		return errors.New("the replacement node terminal file custody differs")
	}
	var stop serviceLifecycleStopRecord
	if lifecycle.DecodeTransport(bytes.NewReader(file.Raw), &stop) != nil || stop.Protocol != "agentgate.node.stop.v1" || len(record.Evidence) == 0 || !reflect.DeepEqual(stop.Evidence, record.Evidence[len(record.Evidence)-1]) || lifecycle.VerifyReadback(stop.Evidence, record.Binding, "stopped") != nil || !stop.Evidence.Terminated || !stop.Evidence.Empty || !stop.Evidence.RightsRemoved {
		return errors.New("the replacement node terminal and journal differ")
	}
	terminal := stop.Terminal
	if terminal.Protocol != lifecycle.TerminalProtocol || !reflect.DeepEqual(terminal.Binding, record.Binding) || terminal.State != "aborted" || terminal.ExitCode != -1 || !terminal.DomainEmpty || !terminal.RightsRemoved || terminal.EvidenceVerdict != "INCOMPLETE" || terminal.EvidenceDigest != stop.Evidence.Digest || terminal.OutputDigest != digestBytes(terminal.Output) {
		return errors.New("the lost-node terminal was not marked incomplete")
	}
	name, err := domainstore.ReservationName(scene.Recipe.FixtureRoot.OwnedPrefix, scene.Active.Record.Binding)
	if err != nil || scene.Domain != filepath.Join(domainstore.RootPath, name) || scene.FinalDomainErrno != int(unix.ENOENT) || len(scene.FinalPins) != 0 || len(scene.CleanupErrors) != 0 || !serviceLifecycleActorsTerminated(scene.Actors, scene.After) || scene.DomainInode != scene.Active.Record.Binding.CgroupID {
		return errors.New("the node-loss worker domain or descendants remain")
	}
	if !reflect.DeepEqual(scene.Start.Spec, scene.Recipe.Spec) || !reflect.DeepEqual(scene.Prepared.Record.Binding, scene.Active.Record.Binding) {
		return errors.New("the node-loss signed job binding differs")
	}
	return nil
}

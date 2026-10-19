// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/qualification"
)

func verifyServiceLifecycleLoss(request qualification.Request, result qualification.Result, receipt serviceLifecycleReceipt, scene serviceLifecycleScene) error {
	if err := verifyServiceLifecycleActive(request, result, receipt, scene); err != nil {
		return err
	}
	if err := verifyServiceLifecycleLossFault(request, result, scene); err != nil {
		return err
	}
	record, err := verifyServiceLifecycleJournal(scene.Loss.Journal, scene)
	if err != nil {
		return err
	}
	if record.StopReason != "manager-shutdown" && record.StopReason != "active-watchdog-unavailable" {
		return errors.New("the watchdog loss stop cause differs")
	}
	file := scene.Loss.TerminalFile
	auditPath, err := serviceLifecycleAuditPath(scene)
	if err != nil {
		return err
	}
	expectedPath := strings.TrimSuffix(auditPath, filepath.Ext(auditPath)) + ".terminal.json"
	if file.Path != expectedPath || file.Error != "" || file.Errno != 0 || len(file.Raw) == 0 || len(file.Raw) > 2<<20 || file.SHA256 != digestBytes(file.Raw) || file.StartedNS < scene.Loss.Journal.FinishedNS || file.FinishedNS < file.StartedNS || file.FinishedNS > result.FinishedMonoNS || uniqueJSON(file.Raw) != nil {
		return errors.New("the actual loss terminal file custody differs")
	}
	var stop serviceLifecycleStopRecord
	if lifecycle.DecodeTransport(bytes.NewReader(file.Raw), &stop) != nil || stop.Protocol != "agentgate.node.stop.v1" || len(record.Evidence) == 0 || !reflect.DeepEqual(stop.Evidence, record.Evidence[len(record.Evidence)-1]) {
		return errors.New("the actual loss terminal and journal differ")
	}
	e, t := stop.Evidence, stop.Terminal
	if lifecycle.VerifyReadback(e, record.Binding, "stopped") != nil || !e.CountersAvailable || e.Lost != 0 || t.Protocol != lifecycle.TerminalProtocol || !reflect.DeepEqual(t.Binding, record.Binding) || t.State != "aborted" || !t.DomainEmpty || !t.RightsRemoved || t.EvidenceVerdict != "VALID_COMPLETE" || t.EvidenceDigest != e.Digest || !bytes.Equal(t.Output, scene.Wire) || t.OutputDigest != digestBytes(scene.Wire) {
		return errors.New("the actual watchdog loss terminal is incomplete")
	}
	if err = verifyServiceLifecycleAuditTerminal(scene, record, &t); err != nil {
		return err
	}
	if scene.AuditFile == nil || scene.AuditFile.StartedNS < scene.Loss.Journal.FinishedNS || scene.AuditFile.FinishedNS > result.FinishedMonoNS {
		return errors.New("the loss audit read clock differs")
	}
	if err = verifyServiceLifecycleAuditFile(scene); err != nil {
		return err
	}
	if _, err = verifyServiceLifecycleAudit(request, scene.Recipe, scene.Audit, scene.NodeKeys, map[string]ed25519.PublicKey{serviceLifecycleAuthorityID + "/" + serviceLifecycleAuthorityKeyID: scene.AuthorityPublic}); err != nil {
		return err
	}
	if err = verifyServiceLifecycleMaps(scene); err != nil {
		return err
	}
	if err = verifyServiceLifecycleActors(scene, record.Binding, result); err != nil {
		return err
	}
	return verifyServiceLifecycleLossEmpty(scene)
}

func verifyServiceLifecycleLossFault(request qualification.Request, result qualification.Result, scene serviceLifecycleScene) error {
	loss := scene.Loss
	if scene.Mode != "watchdog-loss" || loss == nil || loss.Protocol != serviceLifecycleLossProtocol || scene.WatchdogState == nil || len(scene.Active.Record.Evidence) == 0 || len(scene.Calls) != 2 || scene.Calls[0].Path != "/fixture/prepare" || scene.Calls[1].Path != "/fixture/start" || !reflect.DeepEqual(scene.Stopped, serviceLifecycleScene{}.Stopped) || !reflect.DeepEqual(scene.Repeat, serviceLifecycleScene{}.Repeat) {
		return errors.New("the fixed watchdog loss scene scope differs")
	}
	cutoff := scene.Active.Record.Evidence[len(scene.Active.Record.Evidence)-1].EffectiveDeadlineNS
	if loss.Signal != int(syscall.SIGKILL) || loss.SignalError != "" || loss.SignalStartedNS < scene.WatchdogState.FinishedNS || loss.SignalFinishedNS < loss.SignalStartedNS || loss.SignalFinishedNS >= cutoff || loss.SignalStartedNS < result.StartedMonoNS || loss.NodeExit.ObservedNS > result.FinishedMonoNS {
		return errors.New("the actual watchdog loss signal clock differs")
	}
	for _, actor := range scene.Actors {
		if actor.MonoNS >= loss.SignalStartedNS {
			return errors.New("the watchdog loss precedes a live actor readback")
		}
	}
	w := loss.Watchdog
	if w.PID <= 1 || w.PID == scene.NodeSnapshot.PID || w.StartTimeTicks == 0 || w.ExecutableSHA256 != request.Binding.ArtifactDigests["watchdog"] || w.MonoNS < scene.WatchdogState.FinishedNS || w.MonoNS > loss.SignalStartedNS || strings.Join(strings.Fields(processFields(w.Status)["Uid"]), " ") != "0 0 0 0" || strings.Join(strings.Fields(processFields(w.Status)["Gid"]), " ") != "0 0 0 0" {
		return errors.New("the measured watchdog loss process differs")
	}
	if loss.WatchdogExit.PID != w.PID || loss.WatchdogExit.StartTicks != w.StartTimeTicks || loss.WatchdogExit.Signal != int(syscall.SIGKILL) || loss.WatchdogExit.ExitCode != -1 || loss.WatchdogExit.Error == "" || loss.WatchdogExit.ObservedNS < loss.SignalFinishedNS || loss.WatchdogExit.ObservedNS >= cutoff {
		return errors.New("the actual watchdog death wait status differs")
	}
	if err := verifyServiceLifecycleLossNode(request, result, scene); err != nil {
		return err
	}
	for _, call := range scene.AuthorityCalls {
		if call.Operation == "revoke" {
			return errors.New("the loss scene contains a parent revocation")
		}
	}
	for _, call := range scene.Calls {
		if call.Status != 200 || call.MonoNS < result.StartedMonoNS || call.MonoNS >= loss.SignalStartedNS {
			return errors.New("the loss scene command clock differs")
		}
		if err := verifyServiceLifecycleHTTPCall(call, scene); err != nil {
			return err
		}
	}
	var prepared noderuntime.QualificationPrepared
	if lifecycle.DecodeTransport(bytes.NewReader(scene.Calls[0].Response), &prepared) != nil || !reflect.DeepEqual(prepared, scene.Prepared) || scene.Calls[0].MonoNS < scene.Prepared.PreparedMonoNS || scene.Calls[0].MonoNS >= scene.Prepared.Record.PreparationDeadlineNS {
		return errors.New("the actual loss preparation response differs")
	}
	return nil
}

func verifyServiceLifecycleLossEmpty(scene serviceLifecycleScene) error {
	bundle, err := jobauthority.DecodeAuditBundle(scene.Audit)
	if err != nil {
		return err
	}
	cutoff := scene.Active.Record.Evidence[len(scene.Active.Record.Evidence)-1].EffectiveDeadlineNS
	found := false
	for _, event := range bundle.Events {
		if event.Stream != nodecontrol.Stream {
			continue
		}
		var record nodecontrol.Record
		if lifecycle.DecodeTransport(bytes.NewReader(event.Raw), &record) != nil {
			return errors.New("the loss control encoding differs")
		}
		if record.Phase != "domain_empty_readback" {
			continue
		}
		if found {
			return errors.New("the loss empty readback repeats")
		}
		found = true
		var empty nodecontrol.DomainEmpty
		if lifecycle.DecodeTransport(bytes.NewReader(record.Payload), &empty) != nil || empty.Validate() != nil || empty.ObservedMonoNS <= scene.Loss.SignalFinishedNS || empty.ObservedMonoNS >= cutoff {
			return errors.New("the loss domain stops outside the watchdog fault window")
		}
	}
	if !found {
		return errors.New("the actual watchdog loss empty readback is absent")
	}
	return nil
}

func verifyServiceLifecycleLossNode(request qualification.Request, result qualification.Result, scene serviceLifecycleScene) error {
	loss := scene.Loss
	if loss.Journal.StartedNS < loss.WatchdogExit.ObservedNS || loss.Journal.FinishedNS > result.FinishedMonoNS {
		return errors.New("the loss journal read clock differs")
	}
	if loss.NodeAfterFault != nil {
		node := loss.NodeAfterFault
		if !reflect.DeepEqual(loss.NodeExit, serviceLifecycleExit{}) || node.PID != scene.NodeSnapshot.PID || node.StartTimeTicks != scene.NodeSnapshot.StartTimeTicks || node.ExecutableSHA256 != request.Binding.ArtifactDigests["node"] || node.MonoNS < loss.Journal.FinishedNS || node.MonoNS > result.FinishedMonoNS {
			return errors.New("the actual live node after watchdog loss differs")
		}
		record, err := verifyServiceLifecycleJournal(loss.Journal, scene)
		if err != nil || record.StopReason != "active-watchdog-unavailable" && (record.StopReason != "manager-shutdown" || !bytes.Contains(scene.NodeStderr, []byte("the fixed fixture watchdog stopped"))) {
			return errors.New("the live node lacks its actual watchdog failure stop")
		}
		return nil
	}
	exit := loss.NodeExit
	if exit.PID != scene.NodeSnapshot.PID || exit.StartTicks != scene.NodeSnapshot.StartTimeTicks || exit.Signal != 0 || exit.ExitCode <= 0 || exit.Error == "" || exit.ObservedNS < loss.WatchdogExit.ObservedNS || exit.ObservedNS > result.FinishedMonoNS || !bytes.Contains(scene.NodeStderr, []byte("the fixed fixture watchdog stopped")) {
		return errors.New("the actual node watchdog failure exit differs")
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"errors"

	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/syscallrules"
)

// The caller first verifies the complete signed audit and scene. This extra
// case joins its actual wall-derived cutoff to both maps and watchdog custody.
func verifyServiceLifecycleCutoff(scene serviceLifecycleScene) error {
	if scene.Mode != "expiry" || scene.Error != "" || scene.Stopped.Terminal == nil || scene.Stopped.Terminal.State != "expired" || scene.Stopped.Terminal.EvidenceVerdict != "VALID_COMPLETE" || verifyServiceLifecycleSceneMode(scene) != nil {
		return errors.New("the actual expiry scene is incomplete")
	}
	bundle, err := jobauthority.DecodeAuditBundle(scene.Audit)
	if err != nil || bundle.Grant == nil {
		return errors.New("the signed expiry grant is absent")
	}
	var expiry jobaudit.GrantExpiry
	var observer nodecontrol.ObserverBinding
	var installed enforcement.InstalledReadback
	positions := map[string]uint64{}
	times := map[string]uint64{}
	for _, event := range bundle.Events {
		if event.Stream != nodecontrol.Stream {
			continue
		}
		var control nodecontrol.Record
		if err := lifecycle.DecodeTransport(bytes.NewReader(event.Raw), &control); err != nil {
			return err
		}
		switch control.Phase {
		case "grant_expiry_bound", "observer_binding_readback", "held", "installed_readback", "release_intent", "domain_empty_readback", "stopped":
			if positions[control.Phase] != 0 {
				return errors.New("an actual cutoff control repeats")
			}
			positions[control.Phase], times[control.Phase] = event.Index, event.Observation.TimestampNS
		}
		switch control.Phase {
		case "grant_expiry_bound":
			err = lifecycle.DecodeTransport(bytes.NewReader(control.Payload), &expiry)
		case "observer_binding_readback":
			err = lifecycle.DecodeTransport(bytes.NewReader(control.Payload), &observer)
		case "installed_readback":
			err = lifecycle.DecodeTransport(bytes.NewReader(control.Payload), &installed)
		}
		if err != nil {
			return err
		}
	}
	order := []string{"grant_expiry_bound", "observer_binding_readback", "held", "installed_readback", "release_intent", "domain_empty_readback", "stopped"}
	for index, phase := range order {
		if positions[phase] == 0 || index > 0 && (positions[phase] <= positions[order[index-1]] || times[phase] < times[order[index-1]]) {
			return errors.New("the actual cutoff control order differs")
		}
	}
	binding := scene.Active.Record.Binding
	cutoff := expiry.KernelDeadlineNS
	if expiry.Validate(binding, bundle.Grant.Claims.ExpiresAt) != nil || cutoff >= binding.DeadlineNS || expiry.MonoAfterNS > times["grant_expiry_bound"] || observer.Validate(binding) != nil || observer.ObservedMonoNS < times["grant_expiry_bound"] || observer.ObservedMonoNS > times["observer_binding_readback"] || times["observer_binding_readback"] >= cutoff {
		return errors.New("the exact wall and observer cutoff readback differs")
	}
	state, err := observer.State()
	if err != nil || state.ExpiresNS != cutoff || installed.Validate(binding.CgroupID, binding.Generation, cutoff) != nil || len(scene.Active.Record.Evidence) == 0 || scene.Active.Record.Evidence[len(scene.Active.Record.Evidence)-1].EffectiveDeadlineNS != cutoff {
		return errors.New("the actual installed cutoff differs")
	}
	if err = verifyServiceLifecycleWatchdog(scene, cutoff); err != nil {
		return err
	}
	for _, actor := range scene.Actors {
		if actor.MonoNS < times["release_intent"] || actor.MonoNS >= cutoff {
			return errors.New("the actual actor lacks a live interval before cutoff")
		}
	}
	if len(scene.Actors) != 3 || times["domain_empty_readback"] < cutoff {
		return errors.New("the actual expiry termination precedes its cutoff")
	}
	return verifyServiceLifecycleCutoffEvents(bundle, cutoff, times["observer_binding_readback"])
}

func verifyServiceLifecycleCutoffEvents(bundle jobaudit.Bundle, cutoff, observerAt uint64) error {
	for _, event := range bundle.Events {
		if event.Kind == "control" {
			continue
		}
		if event.Observation.TimestampNS < observerAt {
			return errors.New("an actual event precedes the observer cutoff readback")
		}
		if event.Observation.TimestampNS < cutoff {
			continue
		}
		if event.Observation.Decision != nil && *event.Observation.Decision {
			return errors.New("an actual allowed event follows its cutoff")
		}
		if event.Stream == "syscalls" {
			call, err := syscallrules.Decode(event.Raw)
			if err != nil || call.Type == syscallrules.Result && call.Result >= 0 {
				return errors.New("an actual successful syscall follows its cutoff")
			}
		}
	}
	return nil
}

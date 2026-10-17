// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"errors"
	"reflect"

	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
)

// These readbacks establish shared installation and cleanup order. They do not
// supply selector-wide file proof or a candidate positive-rights witness.
func verifyServiceLifecycleMaps(scene serviceLifecycleScene) error {
	bundle, err := jobauthority.DecodeAuditBundle(scene.Audit)
	if err != nil {
		return err
	}
	positions := map[string]uint64{}
	var installed enforcement.InstalledReadback
	var empty nodecontrol.DomainEmpty
	var installedPlan string
	for _, event := range bundle.Events {
		if event.Stream != nodecontrol.Stream {
			continue
		}
		var control nodecontrol.Record
		if lifecycle.DecodeTransport(bytes.NewReader(event.Raw), &control) != nil {
			return errors.New("the raw lifecycle map control differs")
		}
		switch control.Phase {
		case "quarantine_readback", "installed_readback", "installed", "release_intent", "domain_empty_readback", "stopped":
			if _, exists := positions[control.Phase]; exists {
				return errors.New("a lifecycle map control repeats")
			}
			positions[control.Phase] = event.Index
		}
		switch control.Phase {
		case "quarantine_readback":
			var actual enforcement.ResourceReadbackWire
			if lifecycle.DecodeTransport(bytes.NewReader(control.Payload), &actual) != nil || actual.Validate() != nil || !reflect.DeepEqual(actual, scene.Prepared.Quarantine) {
				return errors.New("the prepared and audited quarantine bytes differ")
			}
		case "installed_readback":
			if lifecycle.DecodeTransport(bytes.NewReader(control.Payload), &installed) != nil {
				return errors.New("the actual installed map bytes differ")
			}
		case "installed":
			var actual struct{ Plan, Broker string }
			if lifecycle.DecodeTransport(bytes.NewReader(control.Payload), &actual) != nil {
				return errors.New("the installed plan control differs")
			}
			installedPlan = actual.Plan
		case "domain_empty_readback":
			if lifecycle.DecodeTransport(bytes.NewReader(control.Payload), &empty) != nil || empty.Validate() != nil {
				return errors.New("the actual empty-domain bytes differ")
			}
		}
	}
	names := []string{"quarantine_readback", "installed_readback", "installed", "release_intent", "domain_empty_readback", "stopped"}
	for index, name := range names {
		position, present := positions[name]
		if !present || index > 0 && position <= positions[names[index-1]] {
			return errors.New("the actual lifecycle map control order differs")
		}
	}
	if scene.Active.Record.Process == nil || len(scene.Active.Record.Evidence) == 0 {
		return errors.New("the installed lifecycle actor is absent")
	}
	active := scene.Active.Record.Evidence[len(scene.Active.Record.Evidence)-1]
	if installed.Validate(scene.Active.Record.Binding.CgroupID, scene.Active.Record.Binding.Generation, active.EffectiveDeadlineNS) != nil || installed.PlanDigest != installedPlan {
		return errors.New("the actual installed map binding or plan differs")
	}
	baseline := scene.Prepared.Quarantine
	actual := installed.Resources
	if !reflect.DeepEqual(baseline.MapIDs, actual.MapIDs) || !reflect.DeepEqual(baseline.Markers, actual.Markers) || !reflect.DeepEqual(baseline.FileShared, actual.FileShared) || !reflect.DeepEqual(baseline.AnonymousShared, actual.AnonymousShared) {
		return errors.New("the installed lifecycle map identities changed")
	}
	for _, actor := range scene.Actors {
		if empty.ObservedMonoNS <= actor.MonoNS {
			return errors.New("the empty-domain readback precedes a live actor")
		}
	}
	return nil
}

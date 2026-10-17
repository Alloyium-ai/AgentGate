// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"testing"

	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
)

func lifecycleMapSceneFixture(t *testing.T) (serviceLifecycleScene, jobaudit.Bundle) {
	t.Helper()
	recipe := serviceLifecycleRecipeFixture(t)
	binding := recipe.Spec.Binding
	binding.CgroupID = 456
	baseline := enforcement.QuarantineReadback{Domain: binding.CgroupID, Markers: map[string]uint32{}, MapIDs: map[string]uint32{}}
	for index, name := range []string{"files/policies", "files/owned", "peers/net_policies", "sockets/sock_policies", "sockets/sock_managed", "custody/cust_bindings", "custody/cust_managed", "process/proc_policies", "process/proc_managed"} {
		baseline.MapIDs[name] = uint32(index + 1)
	}
	for _, name := range []string{"files/owned", "sockets/sock_managed", "custody/cust_managed", "process/proc_managed"} {
		baseline.Markers[name] = 1
	}
	wire, err := baseline.Wire()
	if err != nil {
		t.Fatal(err)
	}
	if err = wire.Validate(); err != nil {
		t.Fatal(err)
	}
	installed := baseline
	installed.Files.Generation, installed.Files.ExpiresNS = binding.Generation, binding.DeadlineNS
	installed.Peers.Generation, installed.Peers.ExpiresNS = binding.Generation, binding.DeadlineNS
	installed.Sockets.Generation, installed.Sockets.ExpiresNS = binding.Generation, binding.DeadlineNS
	installed.Custody = [2]uint64{binding.Generation, binding.DeadlineNS}
	installed.Process.Generation, installed.Process.ExpiresNS = binding.Generation, binding.DeadlineNS
	installedWire, err := installed.Wire()
	if err != nil {
		t.Fatal(err)
	}
	readback := enforcement.InstalledReadback{Protocol: "agentgate.installed-resource-readback.v1", PlanDigest: digestJSON("plan"), VerificationDigest: digestJSON("verified"), Resources: installedWire}
	events := []byte("populated 0\nfrozen 0\n")
	empty := nodecontrol.DomainEmpty{Events: events, ReadbackDigest: digestBytes(append([]byte("agentgate-domain-empty-v1\n"), events...)), ObservedMonoNS: 200}
	scene := serviceLifecycleScene{Recipe: recipe, Actors: []processSnapshot{{PID: 123, MonoNS: 100}}}
	scene.Prepared.Quarantine = wire
	scene.Active.Record = lifecycle.Record{Binding: binding, Process: &lifecycle.HeldProcess{PID: 123}, Evidence: []lifecycle.Evidence{{EffectiveDeadlineNS: binding.DeadlineNS}}}
	bundle := jobaudit.Bundle{}
	for index, item := range []struct {
		phase string
		value any
	}{{"quarantine_readback", wire}, {"installed_readback", readback}, {"installed", struct{ Plan, Broker string }{readback.PlanDigest, digestJSON("broker")}}, {"release_intent", struct{}{}}, {"domain_empty_readback", empty}, {"stopped", struct{}{}}} {
		raw, err := nodecontrol.Encode(binding, item.phase, item.value)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Events = append(bundle.Events, jobaudit.Event{Index: uint64(index), Stream: nodecontrol.Stream, Raw: raw})
	}
	scene.Audit = serviceJSON(bundle)
	return scene, bundle
}
func TestLifecycleMapProofRejectsAbsentAndReorderedReadbacks(t *testing.T) {
	scene, bundle := lifecycleMapSceneFixture(t)
	if err := verifyServiceLifecycleMaps(scene); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing-empty", "late-install", "changed-map"} {
		t.Run(mode, func(t *testing.T) {
			changed := bundle
			changed.Events = append([]jobaudit.Event{}, bundle.Events...)
			switch mode {
			case "missing-empty":
				changed.Events = append(changed.Events[:4], changed.Events[5:]...)
			case "late-install":
				changed.Events[1].Index = 4
			case "changed-map":
				scene.Prepared.Quarantine.MapIDs = map[string]uint32{"changed": 999}
			}
			scene.Audit = serviceJSON(changed)
			if verifyServiceLifecycleMaps(scene) == nil {
				t.Fatal("the map proof accepted an absent or changed raw readback")
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/qualification"
)

func TestServiceLifecycleSceneRejectsCrossSceneAndOversizeReceipts(t *testing.T) {
	request := adapterRequest(t)
	adapter := &serviceLifecycleAdapter{mode: "stop"}
	receipt := serviceLifecycleReceipt{Protocol: serviceLifecycleReceiptVersion, AdapterID: adapter.ID(), Binding: request.Binding, Scenes: []serviceLifecycleScene{{Mode: "stop", Error: "actual scene failed"}}}
	result := qualification.Result{Binding: request.Binding, StartedMonoNS: 1, FinishedMonoNS: 2, Raw: serviceJSON(receipt)}
	if coverage, err := adapter.Verify(request, result); err != nil || len(coverage) != 0 {
		t.Fatal("a failed scene supplied coverage", coverage, err)
	}
	changes := map[string]func(*serviceLifecycleReceipt){
		"another adapter": func(r *serviceLifecycleReceipt) { r.AdapterID = (&serviceLifecycleAdapter{mode: "expiry"}).ID() },
		"another scene":   func(r *serviceLifecycleReceipt) { r.Scenes[0].Mode = "expiry" },
		"combined scenes": func(r *serviceLifecycleReceipt) { r.Scenes = append(r.Scenes, r.Scenes[0]) },
		"old protocol":    func(r *serviceLifecycleReceipt) { r.Protocol = "agentgate.fixed-lifecycle-parent-receipt.v1" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			changed := receipt
			changed.Scenes = append([]serviceLifecycleScene{}, receipt.Scenes...)
			change(&changed)
			out := result
			out.Raw = serviceJSON(changed)
			if _, err := adapter.Verify(request, out); err == nil {
				t.Fatal("a substituted scene passed")
			}
		})
	}
	large := receipt
	large.Scenes = []serviceLifecycleScene{{Mode: "stop", Error: strings.Repeat("E", (2<<20)+1)}}
	result.Raw = serviceJSON(large)
	if coverage, err := adapter.Verify(request, result); err != nil || len(coverage) != 0 {
		t.Fatal("a bounded failed scene did not retain zero coverage", coverage, err)
	}
	result.Raw = serviceJSON(receipt)
	result.Raw = append(result.Raw[:len(result.Raw)-1], []byte(`,"unknown":true}`)...)
	if _, err := adapter.Verify(request, result); err == nil {
		t.Fatal("an unknown receipt field passed")
	}
	result.Raw = serviceJSON(receipt)
	result.Raw = append(result.Raw, []byte(strings.Repeat(" ", qualification.MaxRawBytes))...)
	if _, err := adapter.Verify(request, result); err == nil {
		t.Fatal("an oversized scene passed")
	}
}

func TestServiceLifecycleSceneRequiresItsActualStopCause(t *testing.T) {
	for mode, state := range map[string]string{"stop": "cancelled", "expiry": "expired", "revoke": "revoked"} {
		t.Run(mode, func(t *testing.T) {
			terminal := noderuntime.QualificationStatus{Terminal: &lifecycle.Terminal{State: state}}
			scene := serviceLifecycleScene{Mode: mode, Stopped: terminal, Calls: []serviceLifecycleHTTPCall{{Path: "/fixture/prepare"}, {Path: "/fixture/start"}, {Path: "/fixture/stop"}, {Path: "/fixture/stop"}}}
			if mode != "stop" {
				scene.Calls[2] = serviceLifecycleHTTPCall{Path: "/fixture/status", Response: serviceJSON(terminal), MonoNS: 10}
			}
			if mode == "expiry" {
				scene.Active.Record.Evidence = []lifecycle.Evidence{{EffectiveDeadlineNS: 10}}
			}
			if mode == "revoke" {
				scene.AuthorityCalls = []serviceLifecycleAuthorityCall{{Operation: "revoke"}}
			}
			if err := verifyServiceLifecycleSceneMode(scene); err != nil {
				t.Fatal(err)
			}
			scene.Stopped.Terminal = &lifecycle.Terminal{State: "aborted"}
			if err := verifyServiceLifecycleSceneMode(scene); err == nil {
				t.Fatal("an aborted terminal supplied scene coverage")
			}
			scene.Stopped = terminal
			scene.AuthorityCalls = append(scene.AuthorityCalls, serviceLifecycleAuthorityCall{Operation: "revoke"})
			if err := verifyServiceLifecycleSceneMode(scene); err == nil {
				t.Fatal("a changed revocation sequence passed")
			}
		})
	}
}

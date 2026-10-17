//go:build agentgate_native_evidence

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/qualification"
)

func actualCompleteServiceLifecycleFixture(t *testing.T) (qualification.Request, []qualification.Result) {
	t.Helper()
	root := filepath.Join("..", "..", "docs", "evidence", "service-lifecycle-target-20261016k")
	var request qualification.Request
	raw, err := os.ReadFile(filepath.Join(root, "request.json"))
	if err != nil || json.Unmarshal(raw, &request) != nil {
		t.Fatal("the retained K request differs", err)
	}
	raw, err = os.ReadFile(filepath.Join(root, "raw.json"))
	if err != nil || digestBytes(raw) != "573b3e12cae395ebedb71319844366c69308c0ff3d81bb880b33d85887724c99" {
		t.Fatal("the exact complete K output differs", err)
	}
	var output struct {
		Results []qualification.Result `json:"results"`
	}
	if err = json.Unmarshal(raw, &output); err != nil || len(output.Results) != 4 {
		t.Fatal("the retained K results differ", err)
	}
	return request, output.Results
}

func TestActualServiceLifecycleAllScenesAndCutoff(t *testing.T) {
	request, results := actualCompleteServiceLifecycleFixture(t)
	unique := map[string]bool{}
	for index, mode := range []string{"stop", "expiry", "revoke"} {
		coverage, err := (&serviceLifecycleAdapter{mode: mode}).Verify(request, results[index+1])
		if err != nil {
			t.Fatal(mode, err)
		}
		count := 0
		for _, item := range coverage {
			count += len(item.Cases)
			for _, name := range item.Cases {
				unique[item.CapabilityID+"/"+name] = true
			}
		}
		want := 22
		if mode == "stop" {
			want = 21
		}
		if count != want || len(coverage) != 6 {
			t.Fatal("the complete actual scene coverage differs", mode, coverage)
		}
	}
	if len(unique) != 23 || !unique["lifecycle.baseline.v1/grant-wall-and-mono-cutoff"] || !unique["lifecycle.baseline.v1/revoked-grant-stops"] {
		t.Fatal("the unique actual fixture coverage differs", unique)
	}
}

func TestActualServiceLifecycleCutoffRequiresEveryReadback(t *testing.T) {
	for name, change := range map[string]func(*serviceLifecycleScene){
		"missing watchdog row":  func(s *serviceLifecycleScene) { s.WatchdogState = nil },
		"wider watchdog cutoff": func(s *serviceLifecycleScene) { s.WatchdogState.Rows[0].EffectiveDeadlineNS++ },
		"different database":    func(s *serviceLifecycleScene) { s.WatchdogState.After.Inode++ },
		"revoke before expiry": func(s *serviceLifecycleScene) {
			s.AuthorityCalls = append(s.AuthorityCalls, serviceLifecycleAuthorityCall{Operation: "revoke"})
		},
		"missing observer": func(s *serviceLifecycleScene) {
			mutateActualCutoffControl(t, s, "observer_binding_readback", func(_ *nodecontrol.Record) bool { return false })
		},
		"wider observer cutoff": func(s *serviceLifecycleScene) {
			mutateActualCutoffControl(t, s, "observer_binding_readback", func(c *nodecontrol.Record) bool {
				var p nodecontrol.ObserverBinding
				if err := json.Unmarshal(c.Payload, &p); err != nil {
					t.Fatal(err)
				}
				binary.LittleEndian.PutUint64(p.Binding[8:], binary.LittleEndian.Uint64(p.Binding[8:])+1)
				c.Payload = serviceJSON(p)
				return true
			})
		},
		"changed wall sample": func(s *serviceLifecycleScene) {
			mutateActualCutoffControl(t, s, "grant_expiry_bound", func(c *nodecontrol.Record) bool {
				var p map[string]json.RawMessage
				if err := json.Unmarshal(c.Payload, &p); err != nil {
					t.Fatal(err)
				}
				p["wall_sample_unix_ns"] = json.RawMessage(`"1"`)
				c.Payload = serviceJSON(p)
				return true
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, results := actualCompleteServiceLifecycleFixture(t)
			var receipt serviceLifecycleReceipt
			if err := json.Unmarshal(results[2].Raw, &receipt); err != nil {
				t.Fatal(err)
			}
			scene := receipt.Scenes[0]
			if err := verifyServiceLifecycleCutoff(scene); err != nil {
				t.Fatal("the original actual cutoff proof failed", err)
			}
			change(&scene)
			if verifyServiceLifecycleCutoff(scene) == nil {
				t.Fatal("changed actual cutoff facts supplied coverage")
			}
		})
	}
}

func mutateActualCutoffControl(t *testing.T, scene *serviceLifecycleScene, phase string, mutate func(*nodecontrol.Record) bool) {
	t.Helper()
	bundle, err := jobauthority.DecodeAuditBundle(scene.Audit)
	if err != nil {
		t.Fatal(err)
	}
	for index := range bundle.Events {
		if bundle.Events[index].Stream != nodecontrol.Stream {
			continue
		}
		var control nodecontrol.Record
		if err = json.Unmarshal(bundle.Events[index].Raw, &control); err != nil {
			t.Fatal(err)
		}
		if control.Phase != phase {
			continue
		}
		if mutate(&control) {
			bundle.Events[index].Raw = serviceJSON(control)
		} else {
			bundle.Events = append(bundle.Events[:index], bundle.Events[index+1:]...)
		}
		scene.Audit = serviceJSON(bundle)
		return
	}
	t.Fatal("the actual cutoff control is absent", phase)
}

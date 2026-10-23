//go:build agentgate_native_evidence

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/qualification"
)

// Historical bytes exercise the verifier only. The producer still requires a
// fresh exact target, artifact set, binding and candidate-denial join.
func actualServiceLifecycleFixture(t *testing.T) (qualification.Request, []qualification.Result) {
	t.Helper()
	root := filepath.Join("..", "..", "docs", "evidence", "service-lifecycle-target-20261016g")
	var request qualification.Request
	raw, err := os.ReadFile(filepath.Join(root, "request.json"))
	if err != nil || json.Unmarshal(raw, &request) != nil {
		t.Fatal("the retained lifecycle request differs", err)
	}
	raw, err = os.ReadFile(filepath.Join(root, "raw.json"))
	if err != nil {
		t.Fatal(err)
	}
	if digestBytes(raw) != "357ce8e14cd458fa973e208d5483aca5290c64ce7f37938c75fe86e9254a8def" {
		t.Fatal("the complete target G output changed")
	}
	var output struct {
		Results []qualification.Result `json:"results"`
	}
	if err = json.Unmarshal(raw, &output); err != nil || len(output.Results) != 4 {
		t.Fatal("the retained lifecycle results differ", err)
	}
	return request, output.Results
}

func TestHistoricalServiceLifecycleCannotQualifyCurrentSchema(t *testing.T) {
	request, results := actualServiceLifecycleFixture(t)
	var old serviceLifecycleReceipt
	if err := json.Unmarshal(results[2].Raw, &old); err != nil {
		t.Fatal(err)
	}
	if verifyServiceLifecycleCutoff(old.Scenes[0]) == nil {
		t.Fatal("the historical expiry scene supplied missing observer and watchdog readbacks")
	}
	for index, mode := range []string{"stop", "expiry", "revoke"} {
		coverage, err := (&serviceLifecycleAdapter{mode: mode}).Verify(request, results[index+1])
		if err == nil || !strings.Contains(err.Error(), "qualification candidate binding differs") || len(coverage) != 0 {
			t.Fatal("a historical service scene supplied current-schema coverage", mode, coverage, err)
		}
	}
}

func TestActualServiceLifecycleRejectsChangedCustodyAuditAndCleanup(t *testing.T) {
	changes := map[string]func(*serviceLifecycleScene){
		"changed executed policy": func(s *serviceLifecycleScene) { s.Recipe.Spec.Document[0] ^= 1 },
		"changed held PID":        func(s *serviceLifecycleScene) { s.Active.Record.Process.PID++ },
		"changed descendant":      func(s *serviceLifecycleScene) { s.Actors[2].StartTimeTicks++ },
		"retained domain":         func(s *serviceLifecycleScene) { s.FinalDomainErrno = 0 },
		"retained pin":            func(s *serviceLifecycleScene) { s.FinalPins = []string{"owned-pin"} },
		"missing raw proc errno":  func(s *serviceLifecycleScene) { s.After[0].Errno = -1 },
		"wrong stop cause":        func(s *serviceLifecycleScene) { s.Stopped.Terminal.State = "aborted" },
		"changed worker output":   func(s *serviceLifecycleScene) { s.Wire[len(s.Wire)-1] ^= 1 },
		"changed command":         func(s *serviceLifecycleScene) { s.Calls[2].Path = "/fixture/stop" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			request, results := actualServiceLifecycleFixture(t)
			result := results[2]
			var receipt serviceLifecycleReceipt
			if err := json.Unmarshal(result.Raw, &receipt); err != nil {
				t.Fatal(err)
			}
			change(&receipt.Scenes[0])
			result.Raw = serviceJSON(receipt)
			coverage, err := (&serviceLifecycleAdapter{mode: "expiry"}).Verify(request, result)
			if err == nil || len(coverage) != 0 {
				t.Fatal("changed actual lifecycle evidence supplied coverage", coverage, err)
			}
		})
	}
	for _, name := range []string{"lost stream", "missing stream", "changed node seal", "changed authority receipt"} {
		t.Run(name, func(t *testing.T) {
			request, results := actualServiceLifecycleFixture(t)
			result := results[2]
			var receipt serviceLifecycleReceipt
			if err := json.Unmarshal(result.Raw, &receipt); err != nil {
				t.Fatal(err)
			}
			var bundle jobaudit.Bundle
			if err := json.Unmarshal(receipt.Scenes[0].Audit, &bundle); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "lost stream":
				c := bundle.Counters["syscalls"]
				c.Lost++
				bundle.Counters["syscalls"] = c
			case "missing stream":
				delete(bundle.Counters, "files")
			case "changed node seal":
				bundle.Seal.Signature = "AAAA"
			case "changed authority receipt":
				bundle.Authority.Signature = "AAAA"
			}
			receipt.Scenes[0].Audit = serviceJSON(bundle)
			result.Raw = serviceJSON(receipt)
			coverage, err := (&serviceLifecycleAdapter{mode: "expiry"}).Verify(request, result)
			if err == nil || len(coverage) != 0 {
				t.Fatal("changed actual audit supplied coverage", coverage, err)
			}
		})
	}
}

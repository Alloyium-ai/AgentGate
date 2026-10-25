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

func TestHistoricalCompleteServiceLifecycleCannotQualifyCurrentSchema(t *testing.T) {
	request, results := actualCompleteServiceLifecycleFixture(t)
	for index, mode := range []string{"stop", "expiry", "revoke"} {
		coverage, err := (&serviceLifecycleAdapter{mode: mode}).Verify(request, results[index+1])
		if err == nil || !strings.Contains(err.Error(), "qualification candidate binding differs") || len(coverage) != 0 {
			t.Fatal("a historical service scene supplied current-schema coverage", mode, coverage, err)
		}
	}
}

func TestHistoricalCompleteServiceCutoffIsNotCurrentProof(t *testing.T) {
	_, results := actualCompleteServiceLifecycleFixture(t)
	var receipt serviceLifecycleReceipt
	if err := json.Unmarshal(results[2].Raw, &receipt); err != nil {
		t.Fatal(err)
	}
	if len(receipt.Scenes) == 0 {
		t.Fatal("the historical expiry scene is absent")
	}
	if err := verifyServiceLifecycleCutoff(receipt.Scenes[0]); err == nil || !strings.Contains(err.Error(), "actual installed cutoff differs") {
		t.Fatal("a historical cutoff readback supplied current proof")
	}
}

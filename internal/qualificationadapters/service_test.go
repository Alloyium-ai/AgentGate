// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/buildinfo"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
)

func TestServiceReceiptRejectsEmptyAndSubstitutedBinding(t *testing.T) {
	request := adapterRequest(t)
	adapter := &serviceIdentity{}
	if coverage, err := adapter.Verify(request, qualification.Result{}); err == nil || len(coverage) != 0 {
		t.Fatal("an empty receipt supplied coverage")
	}
	raw := serviceJSON(serviceReceipt{Protocol: serviceReceiptVersion, Binding: request.Binding})
	if _, err := adapter.Verify(request, qualification.Result{Binding: request.Binding, StartedMonoNS: 1, FinishedMonoNS: 2, Raw: raw}); err == nil {
		t.Fatal("missing actual calls supplied coverage")
	}
}

func TestServiceActorUsesActualPrivateSocketAndDurableJournal(t *testing.T) {
	root := os.Getenv("AGENTGATE_TEST_SCRATCH")
	if root == "" || os.Geteuid() != 0 {
		t.Skip("the isolated root container and protected scratch are required")
	}
	request := adapterRequest(t)
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(executable)
	hash := hex.EncodeToString(sum[:])
	request.Binding.NodeID = "qualification-isolated-node"
	request.Binding.BootID = strings.TrimSpace(string(boot))
	request.Binding.SourceRevision = buildinfo.SourceRevision
	request.Binding.ArtifactDigests = map[string]string{"qualification": hash, "node": hash}
	closure, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil {
		t.Fatal(err)
	}
	request.Binding.ArtifactDigests["runtime.codex.files"] = closure.Digest()
	if buildinfo.SourceRevision == "" {
		t.Fatal("the source revision must come from the test build")
	}
	adapters, err := NewLifecycle(Config{ScratchRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	wantIDs := []string{"agentgate.service-identity-adapter.v1", "agentgate.fixed-lifecycle-stop-adapter.v1", "agentgate.fixed-lifecycle-expiry-adapter.v1", "agentgate.fixed-lifecycle-revoke-adapter.v1", "agentgate.fixed-lifecycle-watchdog-loss-adapter.v1", "agentgate.fixed-lifecycle-node-loss-adapter.v1", "agentgate.fixed-lifecycle-prepare-reply-loss-adapter.v1"}
	gotIDs := []string{}
	for _, adapter := range adapters {
		gotIDs = append(gotIDs, adapter.ID())
	}
	if !reflect.DeepEqual(gotIDs, wantIDs) {
		t.Fatal("the compiled service adapters differ", gotIDs)
	}
	result, err := adapters[0].Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := adapters[0].Verify(request, result)
	if err != nil {
		t.Fatal(err)
	}
	if len(coverage) != 2 || len(coverage[0].Cases) != 6 || len(coverage[1].Cases) != 6 {
		t.Fatal(coverage)
	}
	for _, c := range coverage {
		for _, name := range c.Cases {
			if name == "valid-binding-accepted" {
				t.Fatal("an unobserved admission case supplied coverage")
			}
		}
	}
	var original serviceReceipt
	if err = json.Unmarshal(result.Raw, &original); err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*serviceReceipt){
		"grant-signature": func(r *serviceReceipt) {
			r.Grant = []byte(strings.Replace(string(r.Grant), `"signature":"`, `"signature":"A`, 1))
		},
		"missing-call":              func(r *serviceReceipt) { r.Calls = r.Calls[:len(r.Calls)-1] },
		"changed-negative":          func(r *serviceReceipt) { r.Calls[1].Input = r.Authorization },
		"wrong-error":               func(r *serviceReceipt) { r.Calls[1].Error = "" },
		"generation-floor":          func(r *serviceReceipt) { r.GenerationFloor++ },
		"journal-binding":           func(r *serviceReceipt) { r.JournalRecords = []byte("[]") },
		"cleanup":                   func(r *serviceReceipt) { r.CleanupErrno = 1 },
		"socket-owner":              func(r *serviceReceipt) { r.Enrollment.SocketUID = 65534 },
		"missing-auth":              func(r *serviceReceipt) { r.Enrollment.Calls = r.Enrollment.Calls[1:] },
		"wrong-body-denial":         func(r *serviceReceipt) { r.Enrollment.Calls[7].Status = 200 },
		"replay-substitution":       func(r *serviceReceipt) { r.Enrollment.Calls[1].Token = r.Enrollment.Calls[2].Token },
		"key-role-reuse":            func(r *serviceReceipt) { r.KeyRoles[1].Error = "" },
		"runtime-file-substitution": func(r *serviceReceipt) { r.Enrollment.RuntimeCalls[5].Status = 503 },
		"persisted-replay":          func(r *serviceReceipt) { r.Enrollment.PersistedReplayError = "" },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			var receipt serviceReceipt
			if err := json.Unmarshal(result.Raw, &receipt); err != nil {
				t.Fatal(err)
			}
			change(&receipt)
			changed := result
			changed.Raw = serviceJSON(receipt)
			if _, err := adapters[0].Verify(request, changed); err == nil {
				t.Fatal("a substituted receipt supplied coverage")
			}
		})
	}
	changedRequest := request
	changedRequest.Binding.Challenge = "other"
	if _, err := adapters[0].Verify(changedRequest, result); err == nil {
		t.Fatal("another target challenge supplied coverage")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "service-") {
			t.Fatal("an owned service directory remains")
		}
	}
	if output := os.Getenv("AGENTGATE_SERVICE_RECEIPT"); output != "" {
		if !filepath.IsAbs(output) {
			t.Fatal("the receipt output must be absolute")
		}
		encoded, err := json.MarshalIndent(struct {
			Request  qualification.Request
			Result   qualification.Result
			Coverage []qualification.Coverage
		}{request, result, coverage}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(output, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(original.Binding, request.Binding) {
		t.Fatal("the actor changed the binding")
	}
}

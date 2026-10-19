//go:build agentgate_native_evidence

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/execbroker"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

// This historical fixture tests raw verification only. The production producer
// rejects stale evidence and a different current target or artifact binding.
func actualFixture(t *testing.T) (qualification.Request, qualification.Result, candidateReceipt) {
	t.Helper()
	var request qualification.Request
	var result qualification.Result
	root := filepath.Join("testdata", "target-20261016d")
	for name, out := range map[string]any{"request.json": &request, "result-meta.json": &result} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	var err error
	result.Raw, err = os.ReadFile(filepath.Join(root, "raw.json"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := parseCandidate(result.Raw)
	if err != nil {
		t.Fatal(err)
	}
	return request, result, receipt
}

func TestActualActorBoundaryRejectsChangedIdentityRoleAndCleanup(t *testing.T) {
	request, result, receipt := actualFixture(t)
	if err := verifyActorBinding(request, result, receipt); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*candidateReceipt){
		"changed held identity":     func(r *candidateReceipt) { r.HeldInstalled.StartTimeTicks++ },
		"claimed agent helper role": func(r *candidateReceipt) { r.BootstrapRole = "agentgate.measured-bootstrap.v1" },
		"retained domain":           func(r *candidateReceipt) { r.DomainRemovalErrno = 0 },
		"retained pin":              func(r *candidateReceipt) { r.PinRemovalErrno["files"] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			request, result, r := actualFixture(t)
			change(&r)
			if err := verifyActorBinding(request, result, r); err == nil {
				t.Fatal("changed actual evidence passed")
			}
		})
	}
}

func TestActualStreamsRequireOriginalIDsContiguousRecordsAndZeroLoss(t *testing.T) {
	_, _, receipt := actualFixture(t)
	calls, files, err := verifyCandidateStreams(receipt)
	if err != nil {
		t.Fatal(err)
	}
	receipt.Streams["syscalls"][0], receipt.Streams["syscalls"][1] = receipt.Streams["syscalls"][1], receipt.Streams["syscalls"][0]
	reordered, _, err := verifyCandidateStreams(receipt)
	if err != nil || len(reordered) != len(calls) || reordered[0].Sequence != 1 || reordered[1].Sequence != 2 {
		t.Fatal("a complete cross-CPU delivery reorder was rejected or lost its kernel sequence", err)
	}
	if !observedCall(calls, receipt, unix.SYS_GETPPID, -int64(unix.EPERM)) || !observedMemory(files, receipt, 2) {
		t.Fatal("the actual outcome and memory decisions are absent")
	}
	for name, change := range map[string]func(*candidateReceipt){
		"lost observation": func(r *candidateReceipt) { s := r.Counters["syscalls"]; s.Lost++; r.Counters["syscalls"] = s },
		"changed sequence": func(r *candidateReceipt) { r.Streams["syscalls"][0][0] ^= 1 },
		"unknown original ID": func(r *candidateReceipt) {
			raw := r.Streams["syscalls"][0]
			binary.LittleEndian.PutUint64(raw[48:], ^uint64(0))
			binary.LittleEndian.PutUint32(raw[92:], syscallrules.UnknownSyscallID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, r := actualFixture(t)
			change(&r)
			if _, _, err := verifyCandidateStreams(r); err == nil {
				t.Fatal("changed actual stream passed")
			}
		})
	}
}

func TestActualActorRecordBytesIncludeHeapGrowthAndRelease(t *testing.T) {
	request, _, receipt := actualFixture(t)
	records, err := verifyRecords(request, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if records[25].Result != records[24].Result+4096 || records[27].Result != 1 || records[26].Result != records[24].Result {
		t.Fatal("actual heap evidence differs")
	}
	receipt.RawRecords[8] ^= 1
	if _, err = verifyRecords(request, receipt); err == nil {
		t.Fatal("changed actor bytes passed")
	}
}

func listenerTargetFixture(t *testing.T, name string) (qualification.Request, qualification.Result, candidateReceipt) {
	t.Helper()
	root := filepath.Join("..", "..", "cmd", "native-startup-probe", "evidence", "candidate-denial-20261016", "listener-target-"+name)
	var request qualification.Request
	var result qualification.Result
	for name, out := range map[string]any{"request.json": &request, "result-meta.json": &result} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, "raw.json"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := parseCandidate(raw)
	if err != nil {
		t.Fatal(err)
	}
	result.Raw = raw
	return request, result, receipt
}

func TestActualListenerTargetRejectsUnknownOriginAndUnstructuredClosure(t *testing.T) {
	request, result, receipt := listenerTargetFixture(t, "f")
	var err error
	if _, _, err = verifyCandidateStreams(receipt); err == nil || !strings.Contains(err.Error(), "unknown original syscall number") {
		t.Fatal("the actual unknown syscall origin lost its rejection", err)
	}
	if string(receipt.Broker.Diagnostic) != "the exec listener closed\n" {
		t.Fatal("the retained broker diagnostic differs")
	}
	if err = verifyBrokerConfig(request, result, receipt); err == nil {
		t.Fatal("the unstructured broker closure produced proof")
	}
}

func TestActualHeapExpiryAndNoCreateFactsKeepEarlyClosureRejected(t *testing.T) {
	request, result, receipt := listenerTargetFixture(t, "g")
	calls, _, err := verifyCandidateStreams(receipt)
	if err != nil {
		t.Fatal(err)
	}
	records, err := verifyRecords(request, receipt)
	if err != nil {
		t.Fatal(err)
	}
	for name, check := range map[string]func() error{
		"actor":          func() error { return verifyActorBinding(request, result, receipt) },
		"maps":           func() error { return verifyMaps(request, receipt) },
		"no creation":    func() error { return verifyProcessProjection(request, receipt, calls, records) },
		"heap decisions": func() error { return verifyLiveHeapDecisions(request, receipt, calls, records) },
		"expiry phase":   func() error { return verifyExpiryBinding(request, result, receipt, calls) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := check(); err != nil {
				t.Fatal(err)
			}
		})
	}
	if verifyBrokerClosure(receipt, calls) == nil {
		t.Fatal("the actual early populated closure passed")
	}
}

func verifyListenerFixture(request qualification.Request, result qualification.Result, receipt candidateReceipt) ([]qualification.Coverage, error) {
	adapter := &candidateDenial{config: Config{Artifacts: map[string]string{"qualification-denial-worker": receipt.HeldBefore.Executable, "exec-broker": receipt.Broker.Process.Executable}}}
	return adapter.Verify(request, result)
}

func TestHistoricalCompleteHeapReceiptCannotQualifyCurrentSchema(t *testing.T) {
	request, result, receipt := listenerTargetFixture(t, "h")
	if digestBytes(result.Raw) != "4fe8915822ed83a58865c5e90b18cb7862ad966a559985c8f438bd5a98cdaf67" {
		t.Fatal("the exact target-h fixture changed")
	}
	coverage, err := verifyListenerFixture(request, result, receipt)
	if err == nil || !strings.Contains(err.Error(), "qualification candidate binding differs") || len(coverage) != 0 {
		t.Fatal("a historical candidate supplied current-schema coverage", coverage, err)
	}
	for name, change := range map[string]func(*candidateReceipt){
		"expired allocation succeeds": func(r *candidateReceipt) {
			for _, raw := range r.Streams["syscalls"] {
				event, _ := syscallrules.Decode(raw)
				if event.Type == syscallrules.Result && event.SyscallID == unix.SYS_BRK && event.MonoNS >= r.DeadlineNS {
					binary.LittleEndian.PutUint64(raw[56:], 0)
					return
				}
			}
			t.Fatal("the expired allocation result is absent")
		},
		"missing final population witness": func(r *candidateReceipt) {
			var closure execbroker.ListenerClosure
			if err := json.Unmarshal(r.Broker.Diagnostic, &closure); err != nil {
				t.Fatal(err)
			}
			closure.Readbacks = nil
			r.Broker.Diagnostic, _ = json.Marshal(closure)
		},
		"early expiry release": func(r *candidateReceipt) { r.Expiry.ResumedMonoNS = r.DeadlineNS - 1 },
		"additional process":   func(r *candidateReceipt) { r.FinalMembers += "99999\n" },
		"lost syscall result":  func(r *candidateReceipt) { c := r.Counters["syscalls"]; c.Lost++; r.Counters["syscalls"] = c },
	} {
		t.Run(name, func(t *testing.T) {
			request, result, receipt := listenerTargetFixture(t, "h")
			change(&receipt)
			result.Raw, _ = json.Marshal(receipt)
			coverage, err := verifyListenerFixture(request, result, receipt)
			if err == nil || len(coverage) != 0 {
				t.Fatal("changed target-h facts produced coverage", err)
			}
		})
	}
}

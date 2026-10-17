// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"alloyium.local/kernel-poc/internal/qualification"
	"golang.org/x/sys/unix"
)

func recordFixture(t *testing.T) (qualification.Request, candidateReceipt) {
	t.Helper()
	request := adapterRequest(t)
	r := candidateReceipt{Active: processSnapshot{PID: 42}}
	for _, id := range []uint32{1, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 99} {
		record := scalarRecord{ID: id, PID: 42, Result: -1, Error: uint32(unix.EPERM)}
		if id == 1 || id == 99 {
			record.Result = 0
			record.Error = 0
		}
		if id == 12 {
			record.Error = uint32(unix.ENOSYS)
		}
		r.Records = append(r.Records, record)
	}
	var raw bytes.Buffer
	for _, record := range r.Records {
		if err := binary.Write(&raw, binary.LittleEndian, record); err != nil {
			t.Fatal(err)
		}
	}
	r.RawRecords = raw.Bytes()
	return request, r
}
func TestVerifierUsesExactActorBytesAndActualErrno(t *testing.T) {
	request, r := recordFixture(t)
	if _, err := verifyRecords(request, r); err != nil {
		t.Fatal(err)
	}
	r.RawRecords = append([]byte{}, r.RawRecords...)
	r.RawRecords[0] ^= 1
	if _, err := verifyRecords(request, r); err == nil {
		t.Fatal("changed raw bytes passed")
	}
	request, r = recordFixture(t)
	r.Records[1].Error = uint32(unix.EACCES)
	var raw bytes.Buffer
	for _, record := range r.Records {
		_ = binary.Write(&raw, binary.LittleEndian, record)
	}
	r.RawRecords = raw.Bytes()
	if _, err := verifyRecords(request, r); err == nil {
		t.Fatal("a different actual denial passed")
	}
}
func TestVerifierRejectsSummaryClaimsAndDuplicateBindings(t *testing.T) {
	for _, raw := range []string{`{"passed":true,"witnesses":99}`, `{"protocol":"a","Protocol":"b"}`} {
		if _, err := parseCandidate([]byte(raw)); err == nil {
			t.Fatal("an untrusted summary or duplicate passed")
		}
	}
}
func TestRegistryCannotCreditEmptyRawOrDifferentBinding(t *testing.T) {
	request := adapterRequest(t)
	adapter := &candidateDenial{}
	if coverage, err := adapter.Verify(request, qualification.Result{}); err == nil || len(coverage) != 0 {
		t.Fatal("empty evidence produced coverage")
	}
	raw, _ := json.Marshal(candidateReceipt{Protocol: candidateReceiptVersion, Binding: qualification.Binding{PolicyDigest: "different"}})
	if err := verifyActorBinding(request, qualification.Result{Raw: raw}, candidateReceipt{Protocol: candidateReceiptVersion, Binding: qualification.Binding{PolicyDigest: "different"}}); err == nil {
		t.Fatal("a different candidate binding passed")
	}
}

func TestReleaseFactsRejectSpoofedSenderAndQueuedSignal(t *testing.T) {
	request, receipt := recordFixture(t)
	receipt.Protocol = candidateReceiptVersion
	receipt.ManagerPID = 99
	extra := []scalarRecord{{ID: 2, PID: 42, Result: 99}, {ID: 3, PID: 42}, {ID: 4, PID: 42}}
	records := append([]scalarRecord{receipt.Records[0]}, extra...)
	receipt.Records = append(records, receipt.Records[1:]...)
	for i, record := range receipt.Records {
		if record.ID == 12 {
			extra = []scalarRecord{{ID: 50, PID: 42, Result: -1, Error: uint32(unix.EPERM)}, {ID: 51, PID: 42, Result: -1, Error: uint32(unix.EPERM)}, {ID: 52, PID: 42, Result: -1, Error: uint32(unix.EPERM)}}
			rest := append([]scalarRecord{}, receipt.Records[i+1:]...)
			receipt.Records = append(receipt.Records[:i+1], extra...)
			receipt.Records = append(receipt.Records, rest...)
			break
		}
	}
	encode := func() {
		var raw bytes.Buffer
		for _, record := range receipt.Records {
			_ = binary.Write(&raw, binary.LittleEndian, record)
		}
		receipt.RawRecords = raw.Bytes()
	}
	encode()
	if _, err := verifyRecords(request, receipt); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		index int
		value int64
	}{{1, 100}, {2, 65534}, {3, -1}} {
		prior := receipt.Records[change.index].Result
		receipt.Records[change.index].Result = change.value
		encode()
		if _, err := verifyRecords(request, receipt); err == nil {
			t.Fatal("a changed release origin passed")
		}
		receipt.Records[change.index].Result = prior
	}
}

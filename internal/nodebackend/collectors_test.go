// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func sequenceDecode(raw []byte) (jobaudit.Observation, error) {
	if len(raw) != 8 {
		return jobaudit.Observation{}, errors.New("bad event")
	}
	return jobaudit.Observation{Sequence: binary.LittleEndian.Uint64(raw)}, nil
}
func seqRaw(n uint64) []byte {
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, n)
	return raw
}
func TestAtomicSequencesUseKernelOrder(t *testing.T) {
	var s orderedStream
	var got []uint64
	emit := func(raw []byte) error { got = append(got, binary.LittleEndian.Uint64(raw)); return nil }
	for _, n := range []uint64{3, 2, 1, 5, 4} {
		if err := s.accept(seqRaw(n), sequenceDecode, emit); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(got, []uint64{1, 2, 3, 4, 5}) || s.complete(5) != nil {
		t.Fatal(got)
	}
	if s.accept(seqRaw(1), sequenceDecode, emit) == nil {
		t.Fatal("duplicate accepted")
	}
}
func TestAuditGapsAndBoundsRemainFailures(t *testing.T) {
	var s orderedStream
	emit := func([]byte) error { return nil }
	if err := s.accept(seqRaw(2), sequenceDecode, emit); err != nil {
		t.Fatal(err)
	}
	if s.complete(2) == nil {
		t.Fatal("gap accepted")
	}
	if s.accept(seqRaw(maxReorder+1), sequenceDecode, emit) == nil {
		t.Fatal("bound accepted")
	}
	if s.accept([]byte{1}, sequenceDecode, emit) == nil {
		t.Fatal("malformed accepted")
	}
}

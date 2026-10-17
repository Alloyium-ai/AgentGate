// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package heldprocess

import (
	"encoding/binary"
	"testing"
)

func filterAckFixture() []byte {
	raw := make([]byte, 40)
	copy(raw, "AGFLT002")
	binary.LittleEndian.PutUint64(raw[8:], 9)
	binary.LittleEndian.PutUint32(raw[24:], 42)
	binary.LittleEndian.PutUint32(raw[28:], 30)
	binary.LittleEndian.PutUint32(raw[32:], 1)
	return raw
}
func TestFilterAcknowledgementRequiresActualSuccessfulInstallOutcomes(t *testing.T) {
	if _, err := DecodeFilterAcknowledgement(filterAckFixture()); err != nil {
		t.Fatal(err)
	}
	zeroFD := filterAckFixture()
	binary.LittleEndian.PutUint64(zeroFD[8:], 0)
	if _, err := DecodeFilterAcknowledgement(zeroFD); err != nil {
		t.Fatal("listener fd0 is valid after the helper closes standard descriptors", err)
	}
	for name, change := range map[string]func([]byte){
		"version":         func(b []byte) { b[0] = 'X' },
		"initial-failure": func(b []byte) { binary.LittleEndian.PutUint64(b[8:], ^uint64(0)) },
		"final-failure":   func(b []byte) { binary.LittleEndian.PutUint64(b[16:], ^uint64(0)) },
		"absent-final":    func(b []byte) { binary.LittleEndian.PutUint32(b[28:], 0) },
		"reserved":        func(b []byte) { b[36] = 1 },
		"listener":        func(b []byte) { binary.LittleEndian.PutUint32(b[32:], 2) },
	} {
		t.Run(name, func(t *testing.T) {
			raw := filterAckFixture()
			change(raw)
			if _, err := DecodeFilterAcknowledgement(raw); err == nil {
				t.Fatal("invalid acknowledgement supplied install proof")
			}
		})
	}
	if _, err := DecodeFilterAcknowledgement([]byte{1}); err == nil {
		t.Fatal("legacy readiness supplied filter proof")
	}
}

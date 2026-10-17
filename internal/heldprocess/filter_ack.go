// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package heldprocess

import (
	"encoding/binary"
	"errors"
)

const FilterAcknowledgementBytes = 40

type FilterAcknowledgement struct {
	InitialResult    int64
	FinalResult      int64
	InitialCount     uint32
	FinalCount       uint32
	ListenerRequired uint32
}

func DecodeFilterAcknowledgement(raw []byte) (FilterAcknowledgement, error) {
	var out FilterAcknowledgement
	if len(raw) != FilterAcknowledgementBytes || string(raw[:8]) != "AGFLT002" {
		return out, errors.New("the measured filter acknowledgement version differs")
	}
	out = FilterAcknowledgement{InitialResult: int64(binary.LittleEndian.Uint64(raw[8:])), FinalResult: int64(binary.LittleEndian.Uint64(raw[16:])), InitialCount: binary.LittleEndian.Uint32(raw[24:]), FinalCount: binary.LittleEndian.Uint32(raw[28:]), ListenerRequired: binary.LittleEndian.Uint32(raw[32:])}
	if out.InitialResult < 0 || out.InitialResult > 2147483647 || out.FinalResult != 0 || out.InitialCount == 0 || out.InitialCount > 4096 || out.FinalCount > 4096 || out.ListenerRequired > 1 || binary.LittleEndian.Uint32(raw[36:]) != 0 || out.ListenerRequired == 1 && out.FinalCount == 0 || out.ListenerRequired == 0 && (out.InitialResult != 0 || out.FinalCount != 0) {
		return out, errors.New("the measured filter installation outcome differs")
	}
	return out, nil
}
func (h *Held) FilterAcknowledgement() []byte { return append([]byte{}, h.filterAcknowledgement...) }

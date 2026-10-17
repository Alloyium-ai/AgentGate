// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package syscallrules

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func correlatedEvent() Event {
	e := event()
	e.SyscallID = -1
	e.Flags = UnknownSyscallID
	e.Version = 2
	e.OriginalID = 15
	e.EntryMonoNS = 90
	e.OriginFlags = EntryOrigin
	return e
}
func TestEntryCorrelationPreservesTheRawExitNumber(t *testing.T) {
	e := correlatedEvent()
	var raw bytes.Buffer
	if err := binary.Write(&raw, binary.LittleEndian, e); err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	original, known := got.OriginalNumber()
	if !known || original != 15 || got.SyscallID != -1 || got.Flags != UnknownSyscallID {
		t.Fatal("the raw exit number changed or the origin disappeared", got)
	}
	if err = Complete([]Event{got}, Counters{Records: 1}); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Event){
		"future entry":        func(v *Event) { v.EntryMonoNS = v.MonoNS + 1 },
		"missing entry clock": func(v *Event) { v.EntryMonoNS = 0 },
		"ambiguous sources":   func(v *Event) { v.OriginFlags = TraceOrigin | EntryOrigin },
		"unknown original":    func(v *Event) { v.OriginalID = -1 },
		"wrong version":       func(v *Event) { v.Version = 3 },
		"rewritten raw ID":    func(v *Event) { v.SyscallID = 15 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := e
			change(&bad)
			if Validate(bad) == nil {
				t.Fatal("invalid origin accepted")
			}
		})
	}
}
func TestLegacyAndMissingOriginsRemainDistinct(t *testing.T) {
	e := event()
	var frame bytes.Buffer
	_ = binary.Write(&frame, binary.LittleEndian, e)
	legacy, err := Decode(frame.Bytes()[:104])
	if err != nil {
		t.Fatal(err)
	}
	if n, known := legacy.OriginalNumber(); !known || n != 110 || legacy.Version != 0 {
		t.Fatal("legacy origin changed")
	}
	if _, err = Decode(frame.Bytes()); err == nil {
		t.Fatal("an unversioned padded event acquired current status")
	}
	missing := correlatedEvent()
	missing.OriginalID = -1
	missing.EntryMonoNS = 0
	missing.OriginFlags = 0
	if err = Validate(missing); err != nil {
		t.Fatal("truthful missing origin rejected", err)
	}
	if _, known := missing.OriginalNumber(); known {
		t.Fatal("missing origin acquired an ID")
	}
	if Complete([]Event{missing}, Counters{Records: 1}) == nil {
		t.Fatal("missing origin completed")
	}
}

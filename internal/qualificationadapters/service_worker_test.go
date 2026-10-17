// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"encoding/binary"
	"testing"
)

func lifecycleWireFixture() []byte {
	raw := make([]byte, 96)
	for index, actor := range []LifecycleProcess{{Role: 3, PID: 103, ParentPID: 102, ChildPID: 0, GettidResult: 103}, {Role: 1, PID: 101, ParentPID: 99, ChildPID: 102, GettidResult: 101}, {Role: 2, PID: 102, ParentPID: 101, ChildPID: 103, GettidResult: 102}} {
		record := raw[index*32:]
		binary.LittleEndian.PutUint32(record, 0x41474c32)
		binary.LittleEndian.PutUint32(record[4:], actor.Role)
		binary.LittleEndian.PutUint32(record[8:], actor.PID)
		binary.LittleEndian.PutUint32(record[12:], actor.ParentPID)
		binary.LittleEndian.PutUint64(record[16:], uint64(actor.ChildPID))
		binary.LittleEndian.PutUint32(record[28:], uint32(actor.GettidResult))
	}
	return raw
}
func TestLifecycleWorkerWireRequiresActualTreeShape(t *testing.T) {
	actors, err := DecodeLifecycleRecords(lifecycleWireFixture())
	if err != nil || len(actors) != 3 || actors[0].PID != 101 {
		t.Fatal(actors, err)
	}
	cases := map[string]func([]byte) []byte{
		"truncated":      func(raw []byte) []byte { return raw[:95] },
		"extra":          func(raw []byte) []byte { return append(raw, 0) },
		"magic":          func(raw []byte) []byte { raw[0]++; return raw },
		"duplicate-role": func(raw []byte) []byte { binary.LittleEndian.PutUint32(raw[4:], 1); return raw },
		"duplicate-pid":  func(raw []byte) []byte { binary.LittleEndian.PutUint32(raw[8:], 101); return raw },
		"wrong-parent":   func(raw []byte) []byte { binary.LittleEndian.PutUint32(raw[12:], 99); return raw },
		"failed-clone":   func(raw []byte) []byte { binary.LittleEndian.PutUint64(raw[48:], ^uint64(0)); return raw },
		"errno":          func(raw []byte) []byte { binary.LittleEndian.PutUint32(raw[24:], 1); return raw },
		"missing-gettid": func(raw []byte) []byte { binary.LittleEndian.PutUint32(raw[28:], 0); return raw },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeLifecycleRecords(change(lifecycleWireFixture())); err == nil {
				t.Fatal("an invalid lifecycle wire record passed")
			}
		})
	}
}

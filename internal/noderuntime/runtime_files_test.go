// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// This structural ELF fixture validates interpreter classification. It executes no code.
func runtimeELFFixture(interpreter string) []byte {
	size := 64
	if interpreter != "" {
		size += 56 + len(interpreter) + 1
	}
	raw := make([]byte, size)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	binary.LittleEndian.PutUint16(raw[16:], 2)
	binary.LittleEndian.PutUint16(raw[18:], 62)
	binary.LittleEndian.PutUint32(raw[20:], 1)
	binary.LittleEndian.PutUint16(raw[52:], 64)
	if interpreter != "" {
		binary.LittleEndian.PutUint64(raw[32:], 64)
		binary.LittleEndian.PutUint16(raw[54:], 56)
		binary.LittleEndian.PutUint16(raw[56:], 1)
		binary.LittleEndian.PutUint32(raw[64:], 3)
		binary.LittleEndian.PutUint64(raw[72:], 120)
		binary.LittleEndian.PutUint64(raw[96:], uint64(len(interpreter)+1))
		copy(raw[120:], interpreter)
	}
	return raw
}
func TestRuntimeELFRequiresAnExplicitMeasuredInterpreter(t *testing.T) {
	root := t.TempDir()
	exe := filepath.Join(root, "native")
	loader := filepath.Join(root, "loader")
	if err := os.WriteFile(exe, runtimeELFFixture(""), 0555); err != nil {
		t.Fatal(err)
	}
	if err := verifyRuntimeInterpreter(exe, []runtimeclosure.File{}); err != nil {
		t.Fatal("static ELF rejected explicit empty closure", err)
	}
	if err := os.WriteFile(loader, []byte("measured loader bytes"), 0444); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, runtimeELFFixture(loader), 0555); err != nil {
		t.Fatal(err)
	}
	if verifyRuntimeInterpreter(exe, []runtimeclosure.File{}) == nil {
		t.Fatal("dynamic ELF accepted an empty closure")
	}
	if verifyRuntimeInterpreter(exe, []runtimeclosure.File{{Path: filepath.Join(root, "other")}}) == nil {
		t.Fatal("dynamic ELF accepted another loader")
	}
	if err := verifyRuntimeInterpreter(exe, []runtimeclosure.File{{Path: loader}}); err != nil {
		t.Fatal("declared interpreter rejected", err)
	}
	if err := os.WriteFile(exe, []byte("an unmeasured shell interpreter"), 0555); err != nil {
		t.Fatal(err)
	}
	if verifyRuntimeInterpreter(exe, []runtimeclosure.File{}) == nil {
		t.Fatal("a nonnative runtime entered the native path")
	}
}

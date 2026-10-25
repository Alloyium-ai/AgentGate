// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package fsrules

import (
	"encoding/binary"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

func TestStdioGrantsAreExactAndRecordedOnce(t *testing.T) {
	read, out, errs := StdioPipe{11, StdioRead}, StdioPipe{12, StdioWrite}, StdioPipe{13, StdioWrite}
	if err := ValidateStdio([]StdioPipe{read, out, errs}); err != nil {
		t.Fatal(err)
	}
	if err := ValidateStdio([]StdioPipe{out}); err != nil {
		t.Fatal(err)
	}
	for name, pipes := range map[string][]StdioPipe{
		"none": {}, "four": {read, out, errs, {14, StdioWrite}}, "repeat": {out, {12, StdioRead}},
		"zero inode": {{0, StdioRead}}, "both directions": {{15, StdioRead | StdioWrite}}, "no direction": {{15, 0}},
		"other bit": {{15, 1}},
	} {
		if ValidateStdio(pipes) == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if RecordStdio(nil, 7, []StdioPipe{out}) == nil {
		t.Fatal("a missing stdio map was accepted")
	}
	m, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 16, ValueSize: 4, MaxEntries: 8})
	if err != nil {
		t.Skipf("no BPF map here (%v); the kernel-backed recording did not run", err)
	}
	defer m.Close()
	if RecordStdio(m, 0, []StdioPipe{out}) == nil {
		t.Fatal("a zero domain was accepted")
	}
	if err = RecordStdio(m, 7, []StdioPipe{read, out, errs}); err != nil {
		t.Fatal(err)
	}
	var rights uint32
	if m.Lookup(StdioKey{7, 11}, &rights) != nil || rights != StdioRead || m.Lookup(StdioKey{7, 13}, &rights) != nil || rights != StdioWrite {
		t.Fatal("the recorded rights differ")
	}
	if RecordStdio(m, 7, []StdioPipe{{21, StdioWrite}}) == nil {
		t.Fatal("a second grant was recorded")
	}
	wrong, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Hash, KeySize: 16, ValueSize: 8, MaxEntries: 8})
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if RecordStdio(wrong, 7, []StdioPipe{out}) == nil {
		t.Fatal("a stdio map with another ABI was accepted")
	}
}

// TestStdioMapABIInCompiledObject binds RecordStdio's map checks to the
// object when clang is present.
func TestStdioMapABIInCompiledObject(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang is not installed")
	}
	object := filepath.Join(t.TempDir(), "fs_access.o")
	build := exec.Command(clang, "-O2", "-g", "-target", "bpf", "-Wall", "-D__TARGET_ARCH_x86", "-I/usr/include/x86_64-linux-gnu", "-c", accessSource, "-o", object)
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		t.Skipf("the BPF object does not build here (%v): %s", buildErr, output)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Maps["stdio"]
	if m == nil || m.Type != ebpf.Hash || m.KeySize != uint32(binary.Size(StdioKey{})) || m.ValueSize != 4 || m.MaxEntries < MaxStdioPipes {
		t.Fatalf("stdio map %+v", m)
	}
}

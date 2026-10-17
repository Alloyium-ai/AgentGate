// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package syscallrules

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func event() Event {
	return Event{Sequence: 1, Domain: 42, Cgroup: 43, Generation: 7, MonoNS: 100, TaskStartBootNS: 80, SyscallID: 110, Result: -1, TGID: 9, TID: 10, UID: 65534, Type: Result}
}
func TestExactAuditABIsAndRawDeniedResult(t *testing.T) {
	if binary.Size(Event{}) != 128 || binary.Size(Binding{}) != 16 || binary.Size(Counters{}) != 16 {
		t.Fatal("audit ABI changed")
	}
	want := event()
	want.Version = 2
	want.OriginalID = want.SyscallID
	want.OriginFlags = TraceOrigin
	var raw bytes.Buffer
	if err := binary.Write(&raw, binary.LittleEndian, want); err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw.Bytes())
	if err != nil || got != want {
		t.Fatal("denied kernel result changed", err)
	}
	if _, err = Decode(raw.Bytes()[:96]); err == nil {
		t.Fatal("another stream ABI accepted")
	}
	jsonRaw, _ := json.Marshal(got)
	if strings.Contains(strings.ToLower(string(jsonRaw)), "allowed") {
		t.Fatal("result acquired an inferred policy effect")
	}
}
func TestMissingAndExpiredObservationsRetainGeneration(t *testing.T) {
	value := event()
	value.Generation = 0
	value.BindingState = Missing
	if err := Validate(value); err != nil {
		t.Fatal(err)
	}
	value.Generation = 7
	if err := Validate(value); err == nil {
		t.Fatal("missing binding relabeled as signed generation")
	}
	value.BindingState = Expired
	if err := Validate(value); err != nil {
		t.Fatal(err)
	}
}
func TestTaskExitHasNoInventedSyscallResult(t *testing.T) {
	value := event()
	value.Type = TaskExit
	value.SyscallID = -1
	value.Result = 0
	value.ExitCode = 17 << 8
	if err := Validate(value); err != nil {
		t.Fatal(err)
	}
	value.SyscallID = 231
	if err := Validate(value); err == nil {
		t.Fatal("task exit invented a syscall number")
	}
}
func TestLossUnknownOriginsAndSequenceGapsCannotComplete(t *testing.T) {
	a := event()
	b := event()
	b.Sequence = 2
	b.SyscallID = 39
	b.Result = 9
	if err := Complete([]Event{b, a}, Counters{Records: 2}); err != nil {
		t.Fatal("delivery reordering rejected", err)
	}
	if err := Complete([]Event{a, b}, Counters{Records: 3, Lost: 1}); err == nil {
		t.Fatal("loss accepted")
	}
	b.Sequence = 1
	if err := Complete([]Event{a, b}, Counters{Records: 2}); err == nil {
		t.Fatal("duplicate accepted")
	}
	a.SyscallID = -1
	a.Flags = UnknownSyscallID
	if err := Complete([]Event{a}, Counters{Records: 1}); err == nil {
		t.Fatal("unknown denied syscall number qualified")
	}
}
func TestCompileRequiresImmutableLiveBinding(t *testing.T) {
	p, err := Compile(42, 7, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err = p.Check(42, 99); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][4]uint64{{0, 7, 10, 100}, {42, 0, 10, 100}, {42, 7, 100, 100}} {
		if _, err = Compile(args[0], args[1], args[2], args[3]); err == nil {
			t.Fatal("invalid binding accepted")
		}
	}
	if err = p.Check(43, 99); err == nil {
		t.Fatal("foreign root accepted")
	}
	if err = p.Check(42, 100); err == nil {
		t.Fatal("expired install accepted")
	}
	copy := p
	copy.binding.Generation++
	if err = copy.Check(42, 99); err == nil {
		t.Fatal("changed binding accepted")
	}
}
func TestProgramsReturnSeparateTracepointDescriptors(t *testing.T) {
	a := Programs()
	a[0].Name = "changed"
	if Programs()[0].Name != "sys_enter" || len(Profile().Programs) != 3 {
		t.Fatal("trace descriptors changed across callers")
	}
}

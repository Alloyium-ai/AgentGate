// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package processrules

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/policy"
	"encoding/binary"
	"testing"
	"unsafe"
)

func fixture(signals ...int) policy.Runtime {
	declared := append([]int{}, signals...)
	return policy.Runtime{Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{}, Capabilities: []string{}, NoNewPrivileges: true, Seccomp: policy.Seccomp{Profile: "explicit-allowlist-notify.v2", Architecture: "x86_64", Default: "deny", AllowSyscalls: []string{}}, Signals: &declared}
}
func TestMaskIncludesOnlyExplicitSignalsAndPreservesUpperBit(t *testing.T) {
	for _, signals := range [][]int{nil, {}, {1}, {64}, {1, 10, 64}} {
		r := fixture(signals...)
		p, err := Compile(r, 44, 7, 100)
		if err != nil {
			t.Fatal(err)
		}
		expected := map[int]bool{}
		for _, signal := range signals {
			expected[signal] = true
		}
		for signal := 1; signal <= 64; signal++ {
			if got := p.State().Signals&(uint64(1)<<uint(signal-1)) != 0; got != expected[signal] {
				t.Fatalf("signal%d=%v", signal, got)
			}
		}
		state := p.State()
		state.Signals = ^uint64(0)
		if p.State().Signals != 0 && len(signals) == 0 {
			t.Fatal("caller changed a compiled plan")
		}
	}
	omitted := fixture()
	omitted.Signals = nil
	p, err := Compile(omitted, 44, 7, 100)
	if err != nil || p.State().Signals != 0 {
		t.Fatal("omission granted a signal", err)
	}
}
func TestCompilerRejectsInvalidSignalsRuntimeAndBindings(t *testing.T) {
	for _, signals := range [][]int{{0}, {-1}, {65}, {10, 10}} {
		if _, err := Compile(fixture(signals...), 44, 7, 100); err == nil {
			t.Fatal("an invalid signal list passed")
		}
	}
	for _, binding := range [][3]uint64{{0, 7, 100}, {44, 0, 100}, {44, 7, 0}} {
		if _, err := Compile(fixture(10), binding[0], binding[1], binding[2]); err == nil {
			t.Fatal("an unresolved binding passed")
		}
	}
	r := fixture(10)
	r.NoNewPrivileges = false
	if _, err := Compile(r, 44, 7, 100); err == nil {
		t.Fatal("an unsafe runtime passed")
	}
}
func TestInstallBindsDigestGenerationDeadlineAndQuiescence(t *testing.T) {
	p, err := Compile(fixture(10), 44, 7, 100)
	if err != nil {
		t.Fatal(err)
	}
	if validateInstall(p, 44, 99, 6) != nil {
		t.Fatal("a fresh generation failed")
	}
	for _, arguments := range [][3]uint64{{45, 99, 6}, {44, 100, 6}, {44, 99, 7}, {0, 99, 6}} {
		if validateInstall(p, arguments[0], arguments[1], arguments[2]) == nil {
			t.Fatal("a changed binding passed")
		}
	}
	p.state.Signals = ^uint64(0)
	if validateInstall(p, 44, 99, 6) == nil {
		t.Fatal("mutated rights passed the digest")
	}
	if Install(&kernel.Runtime{}, p, nil) == nil {
		t.Fatal("an absent quiescence verifier passed")
	}
}
func TestOwnershipAndPtraceRestrictions(t *testing.T) {
	one, zero := uint32(1), uint32(0)
	state := State{7, 100, uint64(1) << 9}
	tests := []struct {
		name                       string
		state                      State
		source, target             uint64
		sourceMarker, targetMarker *uint32
		hook                       uint32
		signal                     int32
		mode                       uint32
		now                        uint64
		allow                      bool
		reason                     uint32
	}{
		{"unmanaged supervisor", State{}, 44, 45, nil, &one, SignalHook, 9, 0, 1, true, Allowed},
		{"invalid source marker", state, 44, 44, &zero, &one, SignalHook, 10, 0, 1, false, InvalidManaged},
		{"same root requested signal", state, 44, 44, &one, &one, SignalHook, 10, 0, 1, true, Allowed},
		{"zero signal", state, 44, 44, &one, &one, SignalHook, 0, 0, 1, false, UnsupportedSignal},
		{"undeclared signal", state, 44, 44, &one, &one, SignalHook, 12, 0, 1, false, UnlistedSignal},
		{"foreign job", state, 44, 45, &one, &one, SignalHook, 10, 0, 1, false, ForeignTarget},
		{"unmanaged target", state, 44, 45, &one, nil, SignalHook, 10, 0, 1, false, UnownedTarget},
		{"unresolved target", state, 44, 0, &one, nil, SignalHook, 10, 0, 1, false, UnknownTarget},
		{"missing policy", State{}, 44, 44, &one, &one, SignalHook, 10, 0, 1, false, MissingPolicy},
		{"expired policy", state, 44, 44, &one, &one, SignalHook, 10, 0, 100, false, ExpiredPolicy},
		{"own read check", state, 44, 44, &one, &one, PtraceHook, 0, 1 | 8, 1, true, Allowed},
		{"foreign read check", state, 44, 45, &one, &one, PtraceHook, 0, 1 | 8, 1, false, ForeignTarget},
		{"attach denied", state, 44, 44, &one, &one, PtraceHook, 0, 2 | 16, 1, false, TracingDenied},
		{"unknown read mode", state, 44, 44, &one, &one, PtraceHook, 0, 1 | 32, 1, false, UnsupportedPtraceMode},
		{"traceme denied", state, 44, 44, &one, &one, TracemeHook, 0, 0, 1, false, TracingDenied},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			allow, reason := Decide(test.state, test.source, test.target, test.sourceMarker, test.targetMarker, test.hook, test.signal, test.mode, test.now)
			if allow != test.allow || reason != test.reason {
				t.Fatalf("got%v/%d want%v/%d", allow, reason, test.allow, test.reason)
			}
		})
	}
}
func TestMapAndEventABIAndMandatoryHooks(t *testing.T) {
	if binary.Size(State{}) != 24 || unsafe.Sizeof(State{}) != 24 || binary.Size(Event{}) != 80 || unsafe.Sizeof(Event{}) != 80 || binary.Size(Counters{}) != 16 {
		t.Fatal("the process map ABI changed")
	}
	programs := Programs()
	programs[0] = "foreign"
	profile := Profile()
	if len(profile.LSMPrograms) != 3 || profile.LSMPrograms[0] != "process_signal" || profile.EventsMap != "proc_events" || profile.CountersMap != "proc_stats" {
		t.Fatal("mandatory process hooks changed")
	}
}

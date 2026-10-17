// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package kernel

import (
	"github.com/cilium/ebpf"
	"testing"
)

func TestFixtureProfileRequiresExplicitInitializationAndUniquePrograms(t *testing.T) {
	initialize := func(*Runtime) error { return nil }
	for _, profile := range []Profile{
		{},
		{Initialize: initialize},
		{LSMPrograms: []string{"one"}},
		{Initialize: initialize, LSMPrograms: []string{""}},
		{Initialize: initialize, LSMPrograms: []string{"one", "one"}},
		{Initialize: initialize, LSMPrograms: []string{"one"}, CgroupPrograms: []CgroupProgram{{Name: "one", Attach: ebpf.AttachCGroupInet4Connect}}},
		{Initialize: initialize, TracepointPrograms: []TracepointProgram{{Name: "one", Group: "../syscalls", Event: "sys_exit"}}},
		{Initialize: initialize, TracepointPrograms: []TracepointProgram{{Name: "one", Group: "raw_syscalls", Event: "sys_exit/other"}}},
		{Initialize: initialize, LSMPrograms: []string{"one"}, TracepointPrograms: []TracepointProgram{{Name: "one", Group: "raw_syscalls", Event: "sys_exit"}}},
	} {
		if err := validateProfile(profile); err == nil {
			t.Fatal("an incomplete or ambiguous fixture profile passed")
		}
	}
	for _, profile := range []Profile{
		{Initialize: initialize, LSMPrograms: []string{"one"}},
		{Initialize: initialize, CgroupPrograms: []CgroupProgram{{Name: "connect", Attach: ebpf.AttachCGroupInet4Connect}}, EventsMap: "net_events", CountersMap: "net_stats"},
		{Initialize: initialize, TracepointPrograms: []TracepointProgram{{Name: "audit_sys_exit", Group: "raw_syscalls", Event: "sys_exit"}}},
	} {
		if err := validateProfile(profile); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCoupledAuditProfileRequiresBothSharedMaps(t *testing.T) {
	p := Profile{Initialize: func(*Runtime) error { return nil }, LSMPrograms: []string{"anonymous_use"}, EventsMap: "events", CountersMap: "stats", NoEventReader: true}
	for _, maps := range []map[string]*ebpf.Map{nil, {"events": {}}, {"stats": {}}} {
		p.MapReplacements = maps
		if validateProfile(p) == nil {
			t.Fatal("an incomplete shared ring profile passed")
		}
	}
	p.MapReplacements = map[string]*ebpf.Map{"events": {}, "stats": {}}
	if err := validateProfile(p); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Runtime{}).Drain(); err == nil {
		t.Fatal("a coupled runtime exposed a second audit consumer")
	}
}

func TestOwnedComponentNamesAndReadbackAreStrict(t *testing.T) {
	for _, s := range []string{"", "../other", "a/b", ".rodata", "socket_guard", "A"} {
		if validComponentName(s) {
			t.Fatalf("unsafe name accepted: %q", s)
		}
	}
	for _, s := range []string{"files", "socket-operations", "peer6"} {
		if !validComponentName(s) {
			t.Fatalf("valid name rejected: %q", s)
		}
	}
	if _, err := AttachOwnedProfile("missing", "/sys/fs/cgroup/alloyium-poc-unit", "files", 0, Profile{}); err == nil {
		t.Fatal("zero domain accepted")
	}
	r := &Runtime{hooks: []string{"fs_open"}}
	copy := r.Hooks()
	copy[0] = "changed"
	if r.Hooks()[0] != "fs_open" {
		t.Fatal("readback changed through caller copy")
	}
}

func TestCgroupMembershipRejectsOtherDomainsAndDuplicateViews(t *testing.T) {
	for _, s := range []string{"0::/owned\n", "0::/owned/workload\n"} {
		if !memberOf(s, "owned") {
			t.Fatal("owned membership rejected")
		}
	}
	for _, s := range []string{"0::/other\n", "0::/owned-other\n", "0::/owned/../other\n", "0::/owned\n0::/owned\n", "1:cpu:/owned\n"} {
		if memberOf(s, "owned") {
			t.Fatal("foreign or ambiguous membership accepted")
		}
	}
}

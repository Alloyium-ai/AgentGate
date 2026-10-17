// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package execbroker

import (
	"alloyium.local/kernel-poc/internal/fsrules"
	"errors"
	"golang.org/x/sys/unix"
	"strings"
	"testing"
	"unsafe"
)

func TestBrokerConfigRequiresExactPinsAndState(t *testing.T) {
	c := Config{Protocol: "agentgate.exec-broker.v1", Domain: "/sys/fs/cgroup/alloyium-poc-owned", DomainID: 42, Generation: 1, DeadlineNS: 100, BootID: "owned-boot", PolicyDigest: strings.Repeat("a", 64), ExecLink: "/sys/fs/bpf/alloyium-poc-owned-files/link-5", ExecProgramID: 3, Files: fsrules.State{Generation: 1, ExpiresNS: 100}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){func(c *Config) { c.ExecLink += "extra" }, func(c *Config) { c.ExecLink = "/sys/fs/bpf/foreign-files/link-5" }, func(c *Config) { c.Files.Generation++ }, func(c *Config) { c.Files.ExpiresNS-- }, func(c *Config) { c.Domain = "/sys/fs/cgroup" }, func(c *Config) { c.PolicyDigest = "" }, func(c *Config) { c.ExecProgramID = 0 }} {
		bad := c
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatal("an inexact broker binding was accepted")
		}
	}
}

func TestExplicitExecNotificationsRequireLiveDomainAndPolicy(t *testing.T) {
	c := Config{DeadlineNS: 100}
	n := Notification{ID: 1, PID: 42, Data: Data{Number: unix.SYS_EXECVE, Architecture: unix.AUDIT_ARCH_X86_64}}
	ok := func(int) error { return nil }
	installed := func() error { return nil }
	if Check(c, n, 1, ok, installed) != "continue-to-file-hooks" {
		t.Fatal("the explicit live exec notification failed")
	}
	for _, mutate := range []func(*Notification){func(n *Notification) { n.ID = 0 }, func(n *Notification) { n.PID = 0 }, func(n *Notification) { n.Flags = 1 }, func(n *Notification) { n.Data.Architecture = unix.AUDIT_ARCH_I386 }, func(n *Notification) { n.Data.Number = unix.SYS_OPENAT }} {
		bad := n
		mutate(&bad)
		if Check(c, bad, 1, ok, installed) == "continue-to-file-hooks" {
			t.Fatal("an unsupported notification continued")
		}
	}
	if Check(c, n, 100, ok, installed) != "expired-binding" || Check(c, n, 0, ok, installed) != "expired-binding" {
		t.Fatal("the deadline was not exact")
	}
	if Check(c, n, 1, func(int) error { return errors.New("foreign domain") }, installed) != "domain-membership-differs" {
		t.Fatal("a foreign task continued")
	}
	if Check(c, n, 1, ok, func() error { return errors.New("missing policy") }) != "installed-policy-differs" {
		t.Fatal("a missing policy continued")
	}
	if Check(c, n, 1, nil, installed) == "continue-to-file-hooks" || Check(c, n, 1, ok, nil) == "continue-to-file-hooks" {
		t.Fatal("a required verifier was optional")
	}
	if unsafe.Sizeof(Notification{}) != 80 || unsafe.Sizeof(Response{}) != 24 || unsafe.Sizeof(Data{}) != 64 {
		t.Fatal("the Linux ABI differs")
	}
}

func TestHeapNotificationsRequireExplicitLiveState(t *testing.T) {
	c := Config{DeadlineNS: 100, Files: fsrules.State{Memory: 32}}
	n := Notification{ID: 1, PID: 42, Data: Data{Number: unix.SYS_BRK, Architecture: unix.AUDIT_ARCH_X86_64}}
	member := func(int) error { return nil }
	installed := func() error { return nil }
	if Check(c, n, 99, member, installed) != "continue-live-heap" {
		t.Fatal("a live explicit heap call failed")
	}
	if Check(c, n, 100, member, installed) != "expired-binding" {
		t.Fatal("an expired heap call continued")
	}
	if Check(c, n, 99, member, func() error { return errors.New("missing map") }) != "installed-policy-differs" {
		t.Fatal("a missing policy allowed heap allocation")
	}
	if Check(c, n, 99, func(int) error { return errors.New("foreign task") }, installed) != "domain-membership-differs" {
		t.Fatal("a foreign task allocated heap")
	}
	c.Files.Memory = 0
	if Check(c, n, 99, member, installed) != "heap-permission-absent" {
		t.Fatal("a missing explicit heap bit allowed allocation")
	}
	for _, reason := range []string{"expired-binding", "heap-permission-absent", "unexpected-notification"} {
		if continues(reason) {
			t.Fatal("a refusal continued")
		}
	}
}

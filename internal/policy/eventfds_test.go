// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy_test

import (
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/testpolicy"
	"bytes"
	"slices"
	"testing"
)

func TestEventFDContractPreservesOmissionAndExplicitEmpty(t *testing.T) {
	for _, present := range []bool{false, true} {
		d := testpolicy.Deny()
		d.Runtime.IPC = &policy.IPCPolicy{Default: "deny", Pipes: []string{}}
		if present {
			empty := []string{}
			d.Runtime.IPC.EventFDs = &empty
		}
		d.RequiredCapabilities, _ = policy.Requirements(d)
		raw, err := d.Canonical()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`"eventfds"`)) != present {
			t.Fatal("explicit empty or omission changed")
		}
		parsed, err := policy.Parse(raw, "json")
		if err != nil {
			t.Fatal(err)
		}
		if (parsed.Runtime.IPC.EventFDs != nil) != present {
			t.Fatal("the field presence changed")
		}
	}
}
func TestEventFDAndNamespaceCapabilitiesComeFromTheSchema(t *testing.T) {
	d := testpolicy.Deny()
	ops := []string{"create", "read", "write"}
	d.Runtime.IPC = &policy.IPCPolicy{Default: "deny", Pipes: []string{}, EventFDs: &ops}
	d.Runtime.Seccomp.AllowSyscalls = []string{"readlinkat"}
	d.Runtime.Bootstrap = &policy.BootstrapPolicy{Profile: "measured-held-exec.v1", HelperDigest: string(bytes.Repeat([]byte("a"), 64)), Operations: []string{"credential_namespace"}, MaxHoldSeconds: 10}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	if err := d.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, cap := range []string{"runtime.explicit-eventfds.v1", "runtime.credential-namespace.v1", "fs.readlink.v1"} {
		if !slices.Contains(d.RequiredCapabilities, cap) {
			t.Fatal("missing schema requirement", cap)
		}
	}
	ops = append(ops, "implicit")
	if err := d.Validate(); err == nil {
		t.Fatal("an unknown anonymous right passed")
	}
}

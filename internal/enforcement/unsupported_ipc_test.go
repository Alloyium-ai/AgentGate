// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/testpolicy"
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestUnqualifiedAnonymousAndCredentialRightsRejectPreparation(t *testing.T) {
	for _, op := range []string{"create", "read", "write", "credential_namespace"} {
		d := testpolicy.Deny()
		if op == "credential_namespace" {
			d.Runtime.Bootstrap = &policy.BootstrapPolicy{Profile: "measured-held-exec.v1", HelperDigest: strings.Repeat("a", 64), Operations: []string{op}, MaxHoldSeconds: 10}
		} else {
			ops := []string{op}
			d.Runtime.IPC = &policy.IPCPolicy{Default: "deny", Pipes: []string{}, EventFDs: &ops}
		}
		d.RequiredCapabilities, _ = policy.Requirements(d)
		if _, err := Compile(d, 42, 1, 100, 1000, nil); err == nil {
			t.Fatal("an unavailable guard reached preparation", op)
		}
	}
}

func TestEventFDCompilerRequiresSignedSupportAndExplicitRights(t *testing.T) {
	d := testpolicy.Deny()
	ops := []string{"create", "read", "write"}
	d.Runtime.IPC = &policy.IPCPolicy{Default: "deny", Pipes: []string{}, EventFDs: &ops}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	report := policy.CapabilityReport{SchemaVersion: policy.CapabilityVersion, Node: "node", Boot: "boot", Challenge: "challenge", Kernel: "qualified-test", Architecture: "x86_64", SourceRevision: strings.Repeat("1", 40), ArtifactSHA256: strings.Repeat("2", 64), PolicySchemaDigest: policy.SchemaDigest(), InventorySHA256: strings.Repeat("3", 64), BTFSHA256: strings.Repeat("4", 64), KernelConfigSHA256: strings.Repeat("5", 64), IssuedAt: 100, ValidUntil: 200, Capabilities: map[string]policy.Capability{}}
	for _, id := range d.RequiredCapabilities {
		report.Capabilities[id] = policy.Capability{State: "enforced", Mechanisms: []string{"explicit-unit-fixture"}, ReceiptSHA256: strings.Repeat("6", 64)}
	}
	policyDigest, err := d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	report.Qualification = &policy.QualificationScope{
		Protocol: policy.QualificationScopeVersion, ProducerSHA256: strings.Repeat("7", 64),
		CompilerSHA256: strings.Repeat("8", 64), ArtifactsSHA256: strings.Repeat("9", 64),
		PolicyDigests: []string{policyDigest}, RequiredCapabilities: d.RequiredCapabilities,
		ContractsSHA256: strings.Repeat("a", 64), EvidenceSHA256: strings.Repeat("b", 64),
	}
	verified := func() policy.VerifiedTarget {
		t.Helper()
		raw, err := policy.SignReport(report, key)
		if err != nil {
			t.Fatal(err)
		}
		target, err := policy.VerifyTarget(raw, key.Public().(ed25519.PublicKey), policy.TargetBinding{Node: "node", Boot: "boot", Challenge: "challenge"}, 100)
		if err != nil {
			t.Fatal(err)
		}
		return target
	}
	target := verified()
	p, err := CompileForTarget(d, 42, 1, 100, 1000, nil, target, 100)
	if err != nil || !p.anonymous || p.files.State().Pipes != (uint64(1)<<63|56) {
		t.Fatal(p, err)
	}
	if p.files.State().Memory != 0 || p.files.State().SocketGeneration != 0 || p.files.Effect("/workspace", "read") != "deny" || len(p.Syscalls().Names()) != 0 {
		t.Fatal("eventfd rights added another permission")
	}
	if _, err = CompileForTarget(d, 42, 1, 100, 1000, nil, target, 200); err == nil {
		t.Fatal("expired support accepted eventfds")
	}
	report.Capabilities["runtime.explicit-eventfds.v1"] = policy.Capability{State: "unavailable"}
	if _, err = CompileForTarget(d, 42, 1, 100, 1000, nil, verified(), 100); err == nil {
		t.Fatal("unavailable support accepted eventfds")
	}
	empty := []string{}
	d.Runtime.IPC.EventFDs = &empty
	d.RequiredCapabilities, _ = policy.Requirements(d)
	p, err = Compile(d, 42, 1, 100, 1000, nil)
	if err != nil || p.anonymous || p.files.State().Pipes != 0 {
		t.Fatal("an explicit empty section enabled delegation", err)
	}
}

func TestAnonymousAliasUsesTheSingleFileCounterStream(t *testing.T) {
	files, anonymous := &kernel.Runtime{}, &kernel.Runtime{}
	g := &Group{Files: files, Anonymous: anonymous}
	all, streams := g.components(), g.counterComponents()
	if len(all) != 6 || all[5] != anonymous || len(streams) != 5 || streams[0] != files {
		t.Fatal("anonymous aliases changed the counter streams")
	}
	for _, r := range streams {
		if r == anonymous {
			t.Fatal("anonymous shared counters counted twice")
		}
	}
}

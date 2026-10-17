// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/testpolicy"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCredentialBootstrapRequiresCurrentSignedTargetSupport(t *testing.T) {
	d := testpolicy.Deny()
	d.Runtime.Bootstrap = &policy.BootstrapPolicy{Profile: "measured-held-exec.v1", HelperDigest: strings.Repeat("a", 64), Operations: []string{"credential_namespace"}, MaxHoldSeconds: 10}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	if _, err := Compile(d, 42, 1, 100, 1000, nil); err == nil {
		t.Fatal("the unqualified compiler accepted credential setup")
	}
	if _, err := CompileForTarget(d, 42, 1, 100, 1000, nil, policy.VerifiedTarget{}, 100); err == nil {
		t.Fatal("missing target trust accepted credential setup")
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	report := policy.CapabilityReport{SchemaVersion: policy.CapabilityVersion, Node: "node", Boot: "boot", Challenge: "challenge", Kernel: "qualified-test", Architecture: "x86_64", SourceRevision: strings.Repeat("1", 40), ArtifactSHA256: strings.Repeat("2", 64), PolicySchemaDigest: policy.SchemaDigest(), InventorySHA256: strings.Repeat("3", 64), BTFSHA256: strings.Repeat("4", 64), KernelConfigSHA256: strings.Repeat("5", 64), IssuedAt: 100, ValidUntil: 200, Capabilities: map[string]policy.Capability{}}
	for _, id := range d.RequiredCapabilities {
		report.Capabilities[id] = policy.Capability{State: "enforced", Mechanisms: []string{"explicit-test-fixture"}, ReceiptSHA256: strings.Repeat("6", 64)}
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
	if err != nil || !p.bootstrapCredentialNamespace {
		t.Fatal(p, err)
	}
	if _, err = CompileForTarget(d, 42, 1, 100, 1000, nil, target, 200); err == nil {
		t.Fatal("stale target support accepted credential setup")
	}
	report.Capabilities["runtime.credential-namespace.v1"] = policy.Capability{State: "unavailable"}
	if _, err = CompileForTarget(d, 42, 1, 100, 1000, nil, verified(), 100); err == nil {
		t.Fatal("an unavailable capability accepted credential setup")
	}
}

func TestCompositeEmptyPolicyAddsNoRights(t *testing.T) {
	p, err := Compile(testpolicy.Deny(), 42, 1, 100, 1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Digest() == "" || p.files.State().Memory != 0 || p.files.State().Pipes != 0 || p.files.State().SocketGeneration != 0 || p.peers.Policy.Count != 0 || p.sockets.Plan.Count != 0 || len(p.Syscalls().Names()) != 0 {
		t.Fatal("empty composite added rights")
	}
	for _, path := range []string{"/", "/workspace", "/usr/bin/agent", "/etc/config"} {
		for _, op := range []string{"read", "write", "execute", "map_execute", "mprotect"} {
			if p.files.Effect(path, op) != "deny" {
				t.Fatal("implicit resource permission")
			}
		}
	}
}
func TestCompositeRejectsInvalidAndUnsupportedRequests(t *testing.T) {
	for _, mutate := range []func(*policy.Document){func(d *policy.Document) { d.Runtime.Seccomp.AllowSyscalls = []string{"clone3"} }, func(d *policy.Document) { *d.RuntimeTemplates = []string{"implicit-runtime"} }, func(d *policy.Document) { (*d.Extensions)["future"] = json.RawMessage(`{}`) }, func(d *policy.Document) { d.Defaults.MissingManagedPolicy = "allow" }} {
		d := testpolicy.Deny()
		mutate(&d)
		d.RequiredCapabilities, _ = policy.Requirements(d)
		if _, err := Compile(d, 42, 1, 100, 1000, nil); err == nil {
			t.Fatal("unsupported request accepted")
		}
	}
	for _, domain := range []uint64{0} {
		if _, err := Compile(testpolicy.Deny(), domain, 1, 100, 1000, nil); err == nil {
			t.Fatal("invalid binding accepted")
		}
	}
	g := &Group{}
	called := false
	if err := g.Install(Plan{}, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("incomplete composite reached backend effects")
	}
}

func TestCompositeRejectsUnsupportedPositiveFileRightsBeforePreparation(t *testing.T) {
	for _, operation := range []string{"create", "mkdir", "delete", "rename", "hardlink", "symlink", "metadata"} {
		d := testpolicy.Deny()
		d.Files.Rules = []policy.FileRule{{ID: "requested", Selector: policy.Selector{Kind: "subtree", Path: "/workspace"}, Operations: []string{operation}, Effect: "allow"}}
		d.RequiredCapabilities, _ = policy.Requirements(d)
		if _, err := Compile(d, 42, 1, 100, 1000, nil); err == nil {
			t.Fatalf("unsupported positive right reached preparation: %s", operation)
		}
	}
}

func TestBootstrapPermissionRequiresAnExactMeasuredHelper(t *testing.T) {
	d := testpolicy.Deny()
	d.Runtime.Seccomp.AllowSyscalls = []string{"read", "close"}
	d.Runtime.Bootstrap = &policy.BootstrapPolicy{Profile: "measured-held-exec.v1", HelperDigest: strings.Repeat("a", 64), Operations: []string{"barrier_read"}, MaxHoldSeconds: 10}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	p, err := Compile(d, 42, 1, 100, 1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !p.bootstrapRead || p.bootstrapDigest != strings.Repeat("a", 64) || p.bootstrapMaxHold != 10 {
		t.Fatal("bootstrap permissions differ")
	}
	d.Runtime.Bootstrap.HelperDigest = strings.Repeat("b", 64)
	if p.bootstrapDigest != strings.Repeat("a", 64) {
		t.Fatal("caller changed compiled bootstrap identity")
	}
	g := &Group{}
	if err = g.BindBootstrap(context.Background(), p, nil, time.Second); err == nil {
		t.Fatal("bootstrap helper identity was optional")
	}
}

func TestAgentChildRequiresEveryExplicitBootstrapRole(t *testing.T) {
	d := testpolicy.Deny()
	digest := strings.Repeat("a", 64)
	d.Runtime.Seccomp.AllowSyscalls = []string{"read", "write", "close", "openat", "fstat", "dup2", "execve", "exit_group"}
	d.Runtime.Bootstrap = &policy.BootstrapPolicy{Profile: "measured-held-exec.v1", HelperDigest: digest, Operations: []string{"barrier_read", "listener_send", "filter_finalize", "working_directory"}, MaxHoldSeconds: 10}
	compile := func() Plan {
		t.Helper()
		d.RequiredCapabilities, _ = policy.Requirements(d)
		p, e := Compile(d, 42, 1, 100, 1000, nil)
		if e != nil {
			t.Fatal(e)
		}
		return p
	}
	if err := compile().ValidateChildBootstrap(digest); err != nil {
		t.Fatal(err)
	}
	if err := compile().ValidateChildBootstrap(strings.Repeat("b", 64)); err == nil {
		t.Fatal("a different measured helper was accepted")
	}
	all := append([]string{}, d.Runtime.Bootstrap.Operations...)
	for index := range all {
		d.Runtime.Bootstrap.Operations = append(append([]string{}, all[:index]...), all[index+1:]...)
		if err := compile().ValidateChildBootstrap(digest); err == nil {
			t.Fatalf("bootstrap role %s was implicit", all[index])
		}
	}
	d.Runtime.Bootstrap.Operations = all
	d.Runtime.Seccomp.AllowSyscalls = []string{"read", "close"}
	if err := compile().ValidateChildBootstrap(digest); err == nil {
		t.Fatal("the child acquired implicit syscall rights")
	}
}

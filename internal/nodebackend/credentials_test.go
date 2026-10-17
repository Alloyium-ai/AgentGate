// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/testpolicy"
	"strings"
	"testing"
)

func TestCredentialRegistryRequiresPrivateSourceAndExactArtifacts(t *testing.T) {
	digest := strings.Repeat("a", 64)
	valid := CredentialConfig{Policy: lifecycle.CredentialPolicy{SourceRoot: "/var/lib/agentgate/broker", SourceUID: 0, RuntimeUID: 65534}, References: []lifecycle.CredentialReference{{ID: "login", AgentID: "agent", AgentKind: "claude", SourcePath: "/var/lib/agentgate/broker/login", ExposedPath: "/var/lib/agentgate/job/auth", Digest: digest}}}
	artifacts := map[string]string{"credential.login": digest}
	if err := valid.validate(artifacts); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*CredentialConfig){func(c *CredentialConfig) { c.Policy.RuntimeUID = 0 }, func(c *CredentialConfig) { c.Policy.SourceUID = 65534 }, func(c *CredentialConfig) { c.References = nil }, func(c *CredentialConfig) { c.References = append(c.References, c.References[0]) }, func(c *CredentialConfig) { c.References[0].Digest = strings.Repeat("b", 64) }, func(c *CredentialConfig) { c.References[0].SourcePath = "/var/lib/agentgate/broker/../other/login" }, func(c *CredentialConfig) { c.Policy.SourceRoot = "/tmp/broker" }} {
		bad := copyValue(valid)
		change(&bad)
		if err := bad.validate(artifacts); err == nil {
			t.Fatalf("an invalid credential configuration passed: %+v", bad)
		}
	}
}

func TestCredentialBootstrapRemainsExplicit(t *testing.T) {
	d := testpolicy.Deny()
	if needsCredentials(d) {
		t.Fatal("an omitted bootstrap acquired credential custody")
	}
	d.Runtime.Bootstrap = &policy.BootstrapPolicy{Profile: "measured-held-exec.v1", HelperDigest: strings.Repeat("a", 64), MaxHoldSeconds: 1, Operations: []string{}}
	if needsCredentials(d) {
		t.Fatal("an empty bootstrap acquired credential custody")
	}
	d.Runtime.Bootstrap.Operations = []string{"credential_namespace"}
	if !needsCredentials(d) {
		t.Fatal("an explicit credential namespace was lost")
	}
}

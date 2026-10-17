// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package testpolicy supplies explicit deny fixtures for private evaluation commands.
package testpolicy

import (
	"alloyium.local/kernel-poc/internal/policy"
	"encoding/json"
)

func Deny() policy.Document {
	extensions := map[string]json.RawMessage{}
	templates := []string{}
	d := policy.Document{SchemaVersion: policy.Version, Profile: policy.KernelProfile, Defaults: &policy.Defaults{RegisteredOperations: "deny", UnmatchedResources: "deny", MissingManagedPolicy: "deny"}, Files: &policy.Files{Defaults: policy.FileDefaults{Read: "deny", Write: "deny"}, ResourceUse: "recheck-and-terminate", Rules: []policy.FileRule{}}, Programs: &policy.Programs{Default: "deny", Rules: []policy.ProgramRule{}}, Network: &policy.Network{Default: "deny", Rules: []policy.NetworkRule{}, DNS: policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"}}, Sockets: &policy.SocketPolicy{Default: "deny", Rules: []policy.SocketRule{}}, Identity: &policy.Identity{TrustSource: "local-enrollment", ProofOfPossession: true, JobBinding: true, NodeBinding: true, BootBinding: true, ProcessDomain: "job-cgroup", Descendants: "inherit"}, Runtime: &policy.Runtime{Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{}, Capabilities: []string{}, NoNewPrivileges: true, Seccomp: policy.Seccomp{Profile: "explicit-allowlist-notify.v2", Architecture: "x86_64", Default: "deny", AllowSyscalls: []string{}}}, Lifecycle: &policy.Lifecycle{BaselineVersion: "deny-empty.v1", DurationSeconds: 30, Release: "restore-baseline", Revoke: "terminate-job", Recovery: "pinned-generation-reconcile"}, Evidence: &policy.Evidence{Profile: "node-chain-authority-batch.v1", MaxReportedLoss: 0, BatchEvents: 500, BatchSeconds: 5}, RuntimeTemplates: &templates, Extensions: &extensions}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	return d
}

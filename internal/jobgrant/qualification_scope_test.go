// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobgrant

import (
	"alloyium.local/kernel-poc/internal/policy"
	"strings"
	"testing"
)

func TestScopedRefreshPreservesOnlyIdenticalBehaviorContracts(t *testing.T) {
	f := setup(t)
	s := f.deps.snapshot
	s.ArtifactDigests["qualification"] = strings.Repeat("1", 64)
	artifacts, err := policy.ArtifactSetDigest(s.ArtifactDigests)
	if err != nil {
		t.Fatal(err)
	}
	r := f.report
	r.Qualification = &policy.QualificationScope{Protocol: policy.QualificationScopeVersion, ProducerSHA256: s.ArtifactDigests["qualification"], CompilerSHA256: s.CompilerDigest, ArtifactsSHA256: artifacts, PolicyDigests: []string{f.c.DocumentDigest}, RequiredCapabilities: f.c.RequiredCapabilities, ContractsSHA256: strings.Repeat("2", 64), EvidenceSHA256: strings.Repeat("3", 64)}
	s.Target = signedTarget(t, r, f.key)
	first, err := QualificationDigest(s)
	if err != nil {
		t.Fatal(err)
	}
	r.Qualification.EvidenceSHA256 = strings.Repeat("4", 64)
	r.IssuedAt++
	r.ValidUntil++
	for id, capability := range r.Capabilities {
		capability.ReceiptSHA256 = strings.Repeat("5", 64)
		r.Capabilities[id] = capability
	}
	s.Target = signedTarget(t, r, f.key)
	second, err := QualificationDigest(s)
	if err != nil || second != first {
		t.Fatal("fresh evidence changed identical qualification", err)
	}
	r.Qualification.ContractsSHA256 = strings.Repeat("6", 64)
	s.Target = signedTarget(t, r, f.key)
	changed, err := QualificationDigest(s)
	if err != nil || changed == first {
		t.Fatal("changed behavior contract retained qualification", err)
	}
	r.Qualification.ContractsSHA256 = strings.Repeat("2", 64)
	r.Qualification.PolicyDigests = []string{strings.Repeat("7", 64)}
	s.Target = signedTarget(t, r, f.key)
	changed, err = QualificationDigest(s)
	if err != nil || changed == first {
		t.Fatal("changed policy scope retained qualification", err)
	}
	r.Capabilities[f.c.RequiredCapabilities[0]] = policy.Capability{State: "unavailable"}
	s.Target = signedTarget(t, r, f.key)
	if _, err = QualificationDigest(s); err == nil {
		t.Fatal("unavailable refreshed capability retained qualification")
	}
}

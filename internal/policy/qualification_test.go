// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"strings"
	"testing"
)

func scopedTarget(t *testing.T) (VerifiedTarget, map[string]string) {
	t.Helper()
	artifacts := map[string]string{"qualification": strings.Repeat("1", 64), "node": strings.Repeat("2", 64)}
	digest, err := ArtifactSetDigest(artifacts)
	if err != nil {
		t.Fatal(err)
	}
	s := &QualificationScope{Protocol: QualificationScopeVersion, ProducerSHA256: artifacts["qualification"], CompilerSHA256: strings.Repeat("3", 64), ArtifactsSHA256: digest, PolicyDigests: []string{strings.Repeat("4", 64)}, RequiredCapabilities: []string{"fs.read.v1"}, ContractsSHA256: strings.Repeat("5", 64), EvidenceSHA256: strings.Repeat("6", 64)}
	r := CapabilityReport{Qualification: s, Capabilities: map[string]Capability{"fs.read.v1": {State: "enforced", Mechanisms: []string{"actual-file-use"}, ReceiptSHA256: strings.Repeat("7", 64)}}}
	return VerifiedTarget{report: r}, artifacts
}
func TestProductionScopeBindsExactPolicyCompilerProducerAndArtifacts(t *testing.T) {
	target, artifacts := scopedTarget(t)
	s := target.report.Qualification
	if err := target.CheckQualificationScope(s.PolicyDigests, s.CompilerSHA256, artifacts); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(){"policy": func() { s.PolicyDigests[0] = strings.Repeat("8", 64) }, "compiler": func() { s.CompilerSHA256 = strings.Repeat("8", 64) }, "producer": func() { s.ProducerSHA256 = strings.Repeat("8", 64) }, "artifact": func() { artifacts["node"] = strings.Repeat("8", 64) }, "capability": func() { target.report.Capabilities["fs.read.v1"] = Capability{State: "probe-only"} }} {
		t.Run(name, func(t *testing.T) {
			target, artifacts = scopedTarget(t)
			s = target.report.Qualification
			expected := append([]string{}, s.PolicyDigests...)
			compiler := s.CompilerSHA256
			change()
			if target.CheckQualificationScope(expected, compiler, artifacts) == nil {
				t.Fatal("substituted scope accepted")
			}
		})
	}
}
func TestLegacyAndIncompleteScopesCannotAuthorizeProduction(t *testing.T) {
	target, artifacts := scopedTarget(t)
	compiler := target.report.Qualification.CompilerSHA256
	policies := target.report.Qualification.PolicyDigests
	target.report.Qualification = nil
	if target.CheckQualificationScope(policies, compiler, artifacts) == nil {
		t.Fatal("legacy report authorized production")
	}
	target, artifacts = scopedTarget(t)
	target.report.Capabilities["fs.write.v1"] = Capability{State: "enforced"}
	if target.CheckQualificationScope(policies, compiler, artifacts) == nil {
		t.Fatal("unscoped capability accepted")
	}
	target, artifacts = scopedTarget(t)
	target.report.Qualification.PolicyDigests = append(target.report.Qualification.PolicyDigests, policies[0])
	if target.report.Qualification.Validate() == nil {
		t.Fatal("duplicate policy accepted")
	}
}

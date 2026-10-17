// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobgrant

import (
	"alloyium.local/kernel-poc/internal/policy"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// QualificationDigest pins stable target and behavior contracts. Fresh scoped
// receipts may renew those same contracts. Verification still checks every
// current signature, scope, capability receipt and freshness window.
func QualificationDigest(s Snapshot) (string, error) {
	r := s.Target.Report()
	if s.Target.Digest() == "" || !hash64.MatchString(s.CompilerDigest) || len(s.ArtifactDigests) == 0 || len(s.ArtifactDigests) > 64 {
		return "", errors.New("a verified qualification snapshot is required")
	}
	for name, value := range s.ArtifactDigests {
		if !identifier.MatchString(name) || !hash64.MatchString(value) {
			return "", errors.New("the qualification artifact registry is invalid")
		}
	}
	for _, digest := range []string{r.ArtifactSHA256, r.InventorySHA256, r.BTFSHA256, r.KernelConfigSHA256, r.PolicySchemaDigest} {
		if !hash64.MatchString(digest) {
			return "", errors.New("the qualification target measurements are incomplete")
		}
	}
	r.Challenge = ""
	r.IssuedAt = 0
	r.ValidUntil = 0
	protocol := "agentgate.full-qualification.v1"
	if r.Qualification != nil {
		if err := s.Target.CheckQualificationScope(r.Qualification.PolicyDigests, s.CompilerDigest, s.ArtifactDigests); err != nil {
			return "", err
		}
		protocol = "agentgate.full-qualification.v2"
		r.Qualification.EvidenceSHA256 = ""
		for id, capability := range r.Capabilities {
			capability.ReceiptSHA256 = ""
			r.Capabilities[id] = capability
		}
	}
	raw, _ := json.Marshal(struct {
		Protocol  string                  `json:"protocol"`
		Report    policy.CapabilityReport `json:"report"`
		Compiler  string                  `json:"compiler_digest"`
		Artifacts map[string]string       `json:"artifact_digests"`
	}{protocol, r, s.CompilerDigest, s.ArtifactDigests})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

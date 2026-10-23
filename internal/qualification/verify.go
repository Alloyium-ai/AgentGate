// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualification

import (
	"alloyium.local/kernel-poc/internal/policy"
	"crypto/ed25519"
	"errors"
	"reflect"
	"slices"
	"time"
)

// VerifyOutput checks publication bytes against this producer's immutable inputs.
// It does not replace a behavior adapter's raw event verifier.
func (p *Producer) VerifyOutput(out Output, key ed25519.PublicKey, now int64) error {
	raw := out.Envelope
	complete := len(raw) > 0
	if complete && len(out.UnavailableEnvelope) > 0 {
		return errors.New("qualification output contains conflicting report types")
	}
	if !complete {
		raw = out.UnavailableEnvelope
	}
	if len(raw) == 0 {
		return nil
	}
	b := p.config.Expected
	target, err := policy.VerifyTarget(raw, key, policy.TargetBinding{Node: b.NodeID, Boot: b.BootID, Challenge: b.Challenge}, now)
	if err != nil {
		return err
	}
	r := target.Report()
	if !reflect.DeepEqual(r, out.Report) || r.SourceRevision != b.SourceRevision || r.ArtifactSHA256 != b.ArtifactDigests["qualification"] || r.InventorySHA256 != b.InventorySHA256 || r.BTFSHA256 != b.BTFSHA256 || r.KernelConfigSHA256 != b.KernelConfigSHA256 || r.Kernel != b.Kernel {
		return errors.New("qualification publication report identity differs")
	}
	if !reflect.DeepEqual(out.CaseMatrix, buildCaseMatrix(p.requests, out.Evidence.Records, r)) {
		return errors.New("qualification per-case evidence index differs")
	}
	for _, record := range out.Evidence.Records {
		if record.Failure != "" && (complete || len(record.Coverage) != 0 ||
			!slices.Contains(out.AdapterErrors, record.AdapterID+": "+record.Failure)) {
			return errors.New("a failed qualification result supplied case coverage or lost its error")
		}
	}
	policies := make([]string, 0, len(p.requests))
	required := map[string]bool{}
	for _, request := range p.requests {
		policies = append(policies, request.Binding.PolicyDigest)
		for _, contract := range request.Contracts {
			required[contract.CapabilityID] = true
		}
	}
	if len(required) != len(r.Capabilities) {
		return errors.New("qualification publication required set differs")
	}
	for name := range required {
		capability, ok := r.Capabilities[name]
		if !ok || !complete && capability.State != "unavailable" {
			return errors.New("qualification diagnostic attempted an enforced state")
		}
	}
	if !complete {
		if r.Qualification != nil {
			return errors.New("qualification diagnostic contains an admission scope")
		}
		return nil
	}
	if err = target.CheckQualificationScope(policies, p.config.CompilerDigest, b.ArtifactDigests); err != nil {
		return err
	}
	if !reflect.DeepEqual(out.Evidence.Target, b) || r.Qualification.EvidenceSHA256 != out.Evidence.Digest() || r.Qualification.ContractsSHA256 != digestValue("AGENTGATE_QUALIFICATION_CONTRACTS_V1", p.requests) {
		return errors.New("qualification publication evidence or contract digest differs")
	}
	e := out.Evidence
	if e.StartedWallUnixNS <= 0 || e.FinishedWallUnixNS < e.StartedWallUnixNS || e.FinishedMonoNS < e.StartedMonoNS || e.MaxEvidenceAgeNS != uint64(p.config.MaxEvidenceAge) || e.ValidForNS != uint64(p.config.ValidFor) || e.FinishedMonoNS-e.StartedMonoNS > e.MaxEvidenceAgeNS {
		return errors.New("qualification evidence clock proof differs")
	}
	finish := time.Unix(0, e.FinishedWallUnixNS)
	limit := finish.Add(p.config.ValidFor)
	if ageLimit := time.Unix(0, e.StartedWallUnixNS).Add(p.config.MaxEvidenceAge - PairingBound); ageLimit.Before(limit) {
		limit = ageLimit
	}
	if r.IssuedAt != finish.Unix() || r.ValidUntil > limit.Unix() {
		return errors.New("qualification report widens its behavior freshness bound")
	}
	return nil
}

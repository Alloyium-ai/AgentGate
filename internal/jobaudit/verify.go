// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobaudit

import (
	"alloyium.local/kernel-poc/internal/jobgrant"
	"encoding/json"
)

func complete(b Bundle, t Terminal) bool {
	cutoff, _, bounded := auditExpiry(b)
	if !bounded {
		return false
	}
	if !t.Empty || !t.RightsRemoved || !t.CountersAvailable || !hash64.MatchString(t.OutputDigest) {
		return false
	}
	if t.StderrDigest != "" && !hash64.MatchString(t.StderrDigest) {
		return false
	}
	switch t.State {
	case "completed":
		if t.ExitCode != 0 {
			return false
		}
	case "failed", "cancelled", "expired", "revoked", "aborted":
	default:
		return false
	}
	if len(b.Counters) != len(b.Header.RequiredStreams) {
		return false
	}
	last := map[string]uint64{}
	seen := map[string]map[uint64]bool{}
	for _, e := range b.Events {
		if e.Kind != "control" && e.Observation.TimestampNS >= cutoff && t.State == "completed" {
			return false
		}
		if e.Kind == "observation" && (e.Observation.BindingState == 1 || e.Observation.BindingState == 3) {
			return false
		}
		if seen[e.Stream] == nil {
			seen[e.Stream] = map[uint64]bool{}
		}
		if e.Observation.Sequence == 0 || seen[e.Stream][e.Observation.Sequence] {
			return false
		}
		seen[e.Stream][e.Observation.Sequence] = true
		if e.Observation.Sequence > last[e.Stream] {
			last[e.Stream] = e.Observation.Sequence
		}
	}
	for _, s := range b.Header.RequiredStreams {
		c, ok := b.Counters[s.Name]
		if !ok || !c.Available || c.Sequence != last[s.Name] || uint64(len(seen[s.Name])) != c.Sequence || c.Lost != 0 || (s.Kind == "resource" && c.Decisions != c.Sequence) || (s.Kind != "resource" && c.Decisions != 0) {
			return false
		}
	}
	return true
}
func VerifyOffline(b Bundle, t Trust) Verdict { return verify(b, t, true) }
func verify(b Bundle, t Trust, requireAuthority bool) Verdict {
	incomplete := func(reason string) Verdict { return Verdict{"INCOMPLETE", reason} }
	tampered := func(reason string) Verdict { return Verdict{"TAMPERED", reason} }
	if !separateTrust(t.NodeKeys, t.AuthorityKeys) {
		return Verdict{"UNKNOWN_KEY", "signing-trust-roles-overlap-or-missing"}
	}
	digest, err := HeaderDigest(b.Header)
	if err != nil {
		return tampered("header-invalid")
	}
	if b.Grant == nil {
		return incomplete("grant-missing")
	}
	if len(t.AuthorityKeys[b.Grant.AuthorityID+"/"+b.Grant.KeyID]) == 0 {
		return Verdict{"UNKNOWN_KEY", "grant-authority-unknown"}
	}
	if grantMatches(b.Header, *b.Grant, t) != nil {
		return tampered("grant-header-binding-differs")
	}
	streams := map[string]Stream{}
	for _, s := range b.Header.RequiredStreams {
		streams[s.Name] = s
	}
	last := map[string]uint64{}
	seen := map[string]map[uint64]bool{}
	chain := digest
	var cutoff, boundAt uint64
	needsBound := false
	filesVerified, needsFiles := false, false
	var filesAt uint64
	for i, e := range b.Events {
		s, ok := streams[e.Stream]
		if !ok || e.Kind != s.Kind || e.Version != s.Version || e.Index != uint64(i)+1 || e.PreviousDigest != chain || e.Digest != eventDigest(e) || len(e.Raw) == 0 || len(e.Raw) > 65536 || e.Observation.Sequence == 0 || seen[e.Stream][e.Observation.Sequence] || (s.Kind == "control" && e.Observation.Sequence != last[e.Stream]+1) {
			return tampered("event-chain-differs")
		}
		o := e.Observation
		if o.CgroupID != b.Header.Binding.CgroupID || o.TimestampNS < b.Header.CreatedMonoNS {
			return tampered("event-binding-differs")
		}
		if s.Kind == "resource" || s.Kind == "observation" {
			if !filesVerified {
				needsFiles = true
			}
			if cutoff == 0 {
				needsBound = true
			}
			decode := t.Registry[s.Name+"/"+s.Version]
			if decode == nil {
				return incomplete("resource-decoder-unavailable")
			}
			actual, err := decode(append([]byte{}, e.Raw...))
			format := resourceFormats[s.Name]
			if s.Kind == "observation" {
				format = observationFormat(s.Name, s.Version)
			}
			limit := cutoff
			if limit == 0 {
				limit = b.Header.Binding.DeadlineNS
			}
			if len(e.Raw) != format.Bytes || err != nil || o.GrantExpiry != nil || !same(actual, o) || (boundAt != 0 && o.TimestampNS < boundAt) || (filesAt != 0 && o.TimestampNS < filesAt) || !validProvenance(s.Kind, o, b.Header.Binding.Generation, limit) {
				return tampered("raw-resource-event-differs")
			}
		} else {
			decode := t.Registry[s.Name+"/"+s.Version]
			if decode == nil {
				return incomplete("control-decoder-unavailable")
			}
			actual, err := decode(append([]byte{}, e.Raw...))
			if err != nil || !json.Valid(e.Raw) || o.Decision != nil || o.DNSLeaseRevision != 0 || o.BindingState != 0 || o.Generation != b.Header.Binding.Generation || actual.CgroupID != o.CgroupID || actual.Generation != o.Generation {
				return tampered("control-event-invalid")
			}
			if !same(actual.GrantExpiry, o.GrantExpiry) {
				return tampered("grant-expiry-raw-control-differs")
			}
			if actual.GrantExpiry != nil {
				if cutoff != 0 || needsBound || actual.ControlPhase != "grant_expiry_bound" || validGrantExpiry(*actual.GrantExpiry, b.Header, b.Grant, o.TimestampNS) != nil {
					return tampered("grant-expiry-bound-invalid-or-late")
				}
				for _, prior := range b.Events[:i] {
					if prior.Observation.TimestampNS > actual.GrantExpiry.MonoSampleNS {
						return tampered("grant-expiry-samples-precede-activity")
					}
				}
				cutoff, boundAt = actual.GrantExpiry.KernelDeadlineNS, o.TimestampNS
			} else if cutoff == 0 && !preparationControl(actual.ControlPhase) {
				needsBound = true
			}
			if actual.ControlPhase == "runtime_files_verified" {
				if filesVerified || needsFiles || (cutoff != 0 && o.TimestampNS >= cutoff) {
					return tampered("runtime-files-proof-invalid-or-late")
				}
				filesVerified = true
				filesAt = o.TimestampNS
			} else if actual.GrantExpiry == nil && !preparationControl(actual.ControlPhase) && !filesVerified {
				needsFiles = true
			}
		}
		if seen[e.Stream] == nil {
			seen[e.Stream] = map[uint64]bool{}
		}
		seen[e.Stream][o.Sequence] = true
		if o.Sequence > last[e.Stream] {
			last[e.Stream] = o.Sequence
		}
		chain = e.Digest
	}
	if b.Seal == nil {
		return incomplete("node-seal-missing")
	}
	s := *b.Seal
	if len(t.NodeKeys[s.NodeID+"/"+s.KeyID]) == 0 {
		return Verdict{"UNKNOWN_KEY", "node-key-unknown"}
	}
	if s.Protocol != "agentgate.full-job-node-seal.v1" || s.NodeID != b.Header.Binding.NodeID || s.HeaderDigest != digest || s.GrantDigest != jobgrant.Digest(*b.Grant) || s.EventsDigest != chain || s.CountersDigest != hash("AGENTGATE_JOB_AUDIT_COUNTERS_V1\n", b.Counters) || s.SealedMonoNS < b.Header.CreatedMonoNS || s.SealedMonoNS < b.Grant.Claims.IssuedMonoNS || !validSignature(t.NodeKeys[s.NodeID+"/"+s.KeyID], sealBytes(s), s.Signature) {
		return tampered("node-seal-differs")
	}
	for _, e := range b.Events {
		if e.Observation.TimestampNS > s.SealedMonoNS {
			return tampered("event-after-seal")
		}
	}
	if cutoff == 0 {
		return incomplete("grant-expiry-bound-missing")
	}
	if !filesVerified {
		return incomplete("runtime-files-proof-missing")
	}
	if !complete(b, s.Terminal) {
		return incomplete("terminal-or-counters-incomplete")
	}
	if requireAuthority {
		if b.Authority == nil {
			return incomplete("authority-receipt-missing")
		}
		r := *b.Authority
		if len(t.AuthorityKeys[r.AuthorityID+"/"+r.KeyID]) == 0 {
			return Verdict{"UNKNOWN_KEY", "receipt-authority-unknown"}
		}
		if r.Protocol != "agentgate.full-job-authority-receipt.v1" || !r.Accepted || r.IssuedAt < b.Grant.Claims.IssuedAt || !same(r.Binding, b.Header.Binding) || r.NodeSealDigest != SealDigest(s) || !validSignature(t.AuthorityKeys[r.AuthorityID+"/"+r.KeyID], receiptBytes(r), r.Signature) {
			return tampered("authority-receipt-differs")
		}
	}
	return Verdict{"VALID_COMPLETE", "all-required-streams-and-separate-signatures-verified"}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dnslease

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"alloyium.local/kernel-poc/internal/netrules"
)

// Snapshot has private custody fields. Copy accessors cannot change the
// validated state. Its digest is an integrity record, not a grant signature.
type Snapshot struct {
	binding        Binding
	networkDigest  string
	revision       uint64
	plan           netrules.Policy
	records        []Record
	resolver       ResolverEvidence
	reason, digest string
}

func (s Snapshot) Binding() Binding           { return s.binding }
func (s Snapshot) Revision() uint64           { return s.revision }
func (s Snapshot) Digest() string             { return s.digest }
func (s Snapshot) NetworkDigest() string      { return s.networkDigest }
func (s Snapshot) Reason() string             { return s.reason }
func (s Snapshot) Plan() netrules.Policy      { return s.plan }
func (s Snapshot) Records() []Record          { return cloneRecords(s.records) }
func (s Snapshot) Resolver() ResolverEvidence { return s.resolver }

func (s Snapshot) NextExpiryNS() uint64 {
	var expires uint64
	for _, record := range s.records {
		if expires == 0 || record.ExpiresNS < expires {
			expires = record.ExpiresNS
		}
	}
	return expires
}

// Check runs under the caller's policy update lock. The caller also verifies
// its signed rules and atomically replaces the endpoint value before release.
func (s Snapshot) Check(binding Binding, networkDigest string, resolver ResolverEvidence, previousRevision, now uint64) error {
	if s.binding != binding || s.networkDigest != networkDigest || s.resolver != resolver || s.revision == 0 || s.revision > MaxLeaseRevision || s.revision <= previousRevision || s.plan.Reserved != uint32(s.revision) || s.digest != s.computeDigest() {
		return fmt.Errorf("mismatched, changed, or stale DNS lease snapshot")
	}
	if s.plan.Generation != binding.Generation || s.plan.ExpiresNS != binding.DeadlineNS || s.plan.Count > netrules.MaxRules {
		return fmt.Errorf("DNS endpoint plan differs from its binding")
	}
	if s.plan.Count != 0 && now >= binding.DeadlineNS {
		return fmt.Errorf("DNS endpoint plan expired")
	}
	for _, rule := range s.plan.Rules[:s.plan.Count] {
		if rule.ExpiresNS <= now || rule.ExpiresNS > binding.DeadlineNS {
			return fmt.Errorf("DNS endpoint rule expired or exceeds the binding")
		}
	}
	return nil
}

func (s Snapshot) computeDigest() string {
	var raw bytes.Buffer
	_ = binary.Write(&raw, binary.LittleEndian, s.plan)
	planSum := sha256.Sum256(raw.Bytes())
	value := struct {
		Binding       Binding
		NetworkDigest string
		Revision      uint64
		PlanSHA256    string
		Records       []Record
		Resolver      ResolverEvidence
		Reason        string
	}{s.binding, s.networkDigest, s.revision, hex.EncodeToString(planSum[:]), s.records, s.resolver, s.reason}
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

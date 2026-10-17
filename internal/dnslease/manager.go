// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dnslease

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"

	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/policy"
	"golang.org/x/net/dns/dnsmessage"
)

type Manager struct {
	mu            sync.Mutex
	binding       Binding
	network       policy.Network
	networkDigest string
	resolver      Resolver
	evidence      ResolverEvidence
	now           Clock
	queries       map[string][]policy.NetworkRule
	cache         map[string][]Record
	revision      uint64
	revoked       bool
}

func New(config Config) (*Manager, error) {
	if config.Now == nil || config.Resolver == nil {
		return nil, fmt.Errorf("a trusted clock and resolver are required")
	}
	now, err := config.Now()
	if err != nil {
		return nil, err
	}
	if err = validateBinding(config.Binding, now); err != nil {
		return nil, err
	}
	if err = policy.ValidateNetworkSection(config.Network); err != nil {
		return nil, err
	}
	evidence := config.Resolver.Evidence()
	if err = validateResolverEvidence(evidence); err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(config.Network)
	var network policy.Network
	if err = json.Unmarshal(raw, &network); err != nil {
		return nil, err
	}
	m := &Manager{binding: config.Binding, network: network, networkDigest: NetworkDigest(network), resolver: config.Resolver, evidence: evidence, now: config.Now, queries: map[string][]policy.NetworkRule{}, cache: map[string][]Record{}}
	literals := network
	literals.Rules = nil
	for _, rule := range network.Rules {
		if rule.Destination.Kind != "hostname" {
			literals.Rules = append(literals.Rules, rule)
			continue
		}
		if !canonicalHostname(rule.Destination.Value) {
			return nil, fmt.Errorf("a DNS rule requires a canonical hostname")
		}
		typeID := dnsmessage.TypeA
		if rule.Family == "ipv6" {
			typeID = dnsmessage.TypeAAAA
		}
		key := queryKey(rule.Destination.Value+".", typeID)
		m.queries[key] = append(m.queries[key], rule)
	}
	if _, err = netrules.Compile(literals, config.Binding.Generation, now, config.Binding.DeadlineNS, nil); err != nil {
		return nil, err
	}
	return m, nil
}

// Forward accepts only an explicit hostname/family question in this job's
// policy. The caller publishes every Changed outcome, even when Error is set.
func (m *Manager) Forward(ctx context.Context, binding Binding, wire []byte) Outcome {
	m.mu.Lock()
	defer m.mu.Unlock()
	if binding != m.binding {
		return Outcome{Error: "job binding differs"}
	}
	if m.revision >= MaxLeaseRevision {
		m.revoked = true
		return Outcome{Fatal: true, Error: "lease revision exhausted; stop the domain and rebind"}
	}
	if ctx == nil {
		return Outcome{Error: "a DNS query context is required"}
	}
	query, err := parseQuery(wire)
	if err != nil {
		return Outcome{Error: err.Error()}
	}
	question := query.Questions[0]
	key := queryKey(question.Name.String(), question.Type)
	rules := m.queries[key]
	if len(rules) == 0 {
		return Outcome{Error: "DNS question is absent from the explicit policy"}
	}
	if m.revoked {
		return m.failed(query, key, "job binding is revoked")
	}
	start, err := m.now()
	if err != nil {
		return m.failed(query, key, "trusted clock is unavailable")
	}
	if start >= binding.DeadlineNS {
		return m.failed(query, key, "job binding expired")
	}
	upstream := query
	var id [2]byte
	if _, err = rand.Read(id[:]); err != nil {
		return m.failed(query, key, "DNS transaction identity is unavailable")
	}
	upstream.ID = binary.BigEndian.Uint16(id[:])
	packet, _ := upstream.Pack()
	reply, err := m.resolver.Exchange(ctx, packet)
	if err != nil {
		return m.failed(query, key, "trusted DNS exchange failed: "+err.Error())
	}
	now, err := m.now()
	if err != nil {
		return m.failed(query, key, "trusted clock is unavailable")
	}
	validated, err := validateReply(upstream, reply, start, now, binding.DeadlineNS)
	if err != nil {
		return m.failed(query, key, err.Error())
	}
	records := makeRecords(rules, validated, m.evidence)
	if m.expandedCount(key, records, now) > netrules.MaxRules {
		return m.failed(query, key, "expanded DNS lease limit exceeded")
	}
	m.cache[key] = records
	validated.message.ID = query.ID
	response, err := validated.message.Pack()
	if err != nil {
		return m.failed(query, key, "validated DNS response encoding failed")
	}
	return Outcome{Changed: true, Snapshot: m.snapshot(now, ""), Response: response}
}

// Snapshot removes expired records and returns a complete replacement. A
// missing hostname, including a deny hostname, forces zero endpoint rules.
func (m *Manager) Snapshot(binding Binding) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if binding != m.binding {
		return Snapshot{}, fmt.Errorf("job binding differs")
	}
	if m.revision >= MaxLeaseRevision {
		m.revoked = true
		return Snapshot{}, fmt.Errorf("lease revision exhausted; stop the domain and rebind")
	}
	now, err := m.now()
	if err != nil {
		return m.snapshot(0, "trusted-clock-unavailable"), nil
	}
	snapshot := m.snapshot(now, "")
	if snapshot.Revision() == 0 {
		return snapshot, fmt.Errorf("lease revision exhausted; stop the domain and rebind")
	}
	return snapshot, nil
}

// Revoke is permanent for this manager. Reuse requires a new trusted binding.
func (m *Manager) Revoke(binding Binding) (Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if binding != m.binding {
		return Snapshot{}, fmt.Errorf("job binding differs")
	}
	m.revoked = true
	m.cache = map[string][]Record{}
	snapshot := m.snapshot(0, "revoked")
	if snapshot.Revision() == 0 {
		return snapshot, fmt.Errorf("lease revision exhausted; stop the domain and rebind")
	}
	return snapshot, nil
}

func (m *Manager) failed(query dnsmessage.Message, key, reason string) Outcome {
	delete(m.cache, key)
	return Outcome{Changed: true, Snapshot: m.snapshot(0, "resolution-failed"), Response: errorResponse(query, dnsmessage.RCodeServerFailure), Error: reason}
}

func (m *Manager) snapshot(now uint64, reason string) Snapshot {
	if m.revision >= MaxLeaseRevision {
		m.revoked = true
		return Snapshot{reason: "lease-revision-exhausted"}
	}
	m.revision++
	s := Snapshot{binding: m.binding, networkDigest: m.networkDigest, resolver: m.evidence, revision: m.revision, plan: netrules.Policy{Generation: m.binding.Generation, ExpiresNS: m.binding.DeadlineNS, Reserved: uint32(m.revision)}, reason: reason}
	for key, records := range m.cache {
		live := records[:0]
		for _, record := range records {
			if now < record.ExpiresNS {
				live = append(live, record)
			}
		}
		if len(live) == 0 {
			delete(m.cache, key)
		} else {
			m.cache[key] = live
			s.records = append(s.records, cloneRecords(live)...)
		}
	}
	sort.Slice(s.records, func(i, j int) bool {
		a, b := s.records[i], s.records[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		return a.Address.Less(b.Address)
	})
	if reason == "" && !m.revoked && now < m.binding.DeadlineNS {
		compiled, err := netrules.Compile(m.network, m.binding.Generation, now, m.binding.DeadlineNS, leases(s.records))
		if err == nil {
			s.plan = compiled.Policy
			s.plan.Reserved = uint32(m.revision)
		} else {
			s.reason = "incomplete-or-unsupported-lease-snapshot"
		}
	} else if s.reason == "" {
		s.reason = "revoked-or-expired"
	}
	s.digest = s.computeDigest()
	return s
}

func makeRecords(rules []policy.NetworkRule, reply validatedReply, evidence ResolverEvidence) []Record {
	records := []Record{}
	for _, rule := range rules {
		for _, address := range reply.addresses {
			records = append(records, Record{RuleID: rule.ID, Hostname: rule.Destination.Value, Address: address, Chain: append([]string(nil), reply.chain...), ExpiresNS: reply.expires, ReplySHA256: reply.digest, Resolver: evidence})
		}
	}
	return records
}

func queryKey(name string, typeID dnsmessage.Type) string { return fmt.Sprintf("%s/%d", name, typeID) }

func (m *Manager) expandedCount(replacing string, records []Record, now uint64) int {
	count := len(records)
	for _, rule := range m.network.Rules {
		if rule.Destination.Kind != "hostname" {
			count++
		}
	}
	for key, previous := range m.cache {
		if key != replacing {
			for _, record := range previous {
				if now < record.ExpiresNS {
					count++
				}
			}
		}
	}
	return count
}

func validateBinding(binding Binding, now uint64) error {
	if binding.JobID == "" || len(binding.JobID) > 256 || binding.DomainID == 0 || binding.Generation == 0 || binding.DeadlineNS <= now || !digestString(binding.PolicySHA256) {
		return fmt.Errorf("an immutable live job binding is required")
	}
	for _, c := range binding.JobID {
		if c < 32 || c == 127 {
			return fmt.Errorf("job identity contains a control character")
		}
	}
	return nil
}

func validateResolverEvidence(e ResolverEvidence) error {
	address, err := netip.ParseAddrPort(e.Address)
	if err != nil || address.Port() == 0 || address.Addr().IsUnspecified() || address.Addr().IsMulticast() || address.Addr().Is4In6() || address.Addr().Zone() != "" || e.Transport != "tls1.3" || !canonicalHostname(e.ServerName) || !digestString(e.RootsSHA256) || e.TimeoutMS < 1 || e.TimeoutMS > 5000 || strings.TrimSpace(e.Address) != e.Address {
		return fmt.Errorf("explicit verified TLS resolver settings are required")
	}
	return nil
}

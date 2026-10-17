// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/cilium/ebpf"
)

type dnsState struct {
	binding  dnslease.Binding
	network  string
	resolver dnslease.ResolverEvidence
	snapshot dnslease.Snapshot
}

func (s dnsState) check(previous uint64) error {
	now, err := kernel.MonotonicNS()
	if err != nil {
		return err
	}
	if now >= s.binding.DeadlineNS {
		return errors.New("the DNS publication binding expired")
	}
	return s.snapshot.Check(s.binding, s.network, s.resolver, previous, now)
}

// CompileResolved accepts only a complete trusted snapshot of the signed rules.
// It recompiles every lease and compares the exact kernel plan before staging.
func CompileResolved(document policy.Document, binding dnslease.Binding, now uint64, snapshot dnslease.Snapshot, resolver dnslease.ResolverEvidence) (Plan, error) {
	return compileResolved(document, binding, now, snapshot, resolver, false)
}
func CompileResolvedForTarget(document policy.Document, binding dnslease.Binding, now uint64, snapshot dnslease.Snapshot, resolver dnslease.ResolverEvidence, target policy.VerifiedTarget, wallUnix int64) (Plan, error) {
	if _, err := policy.PreviewForTarget(document, target, wallUnix); err != nil {
		return Plan{}, err
	}
	return compileResolved(document, binding, now, snapshot, resolver, true)
}
func compileResolved(document policy.Document, binding dnslease.Binding, now uint64, snapshot dnslease.Snapshot, resolver dnslease.ResolverEvidence, qualified bool) (Plan, error) {
	var zero Plan
	digest, err := document.Digest()
	if err != nil {
		return zero, err
	}
	if document.Network == nil || binding.JobID == "" || binding.PolicySHA256 != digest {
		return zero, errors.New("the DNS binding differs from the signed policy")
	}
	network := dnslease.NetworkDigest(*document.Network)
	if err = snapshot.Check(binding, network, resolver, 0, now); err != nil {
		return zero, err
	}
	if snapshot.Reason() != "" {
		return zero, errors.New("the DNS lease set is incomplete or denied")
	}
	leases := []netrules.Lease{}
	for _, r := range snapshot.Records() {
		leases = append(leases, netrules.Lease{RuleID: r.RuleID, Hostname: r.Hostname, Address: r.Address, Chain: r.Chain, ExpiresNS: r.ExpiresNS})
	}
	p, err := compile(document, binding.DomainID, binding.Generation, now, binding.DeadlineNS, leases, qualified)
	if err != nil {
		return zero, err
	}
	p.peers.Policy.Reserved = uint32(snapshot.Revision())
	if p.peers.Policy != snapshot.Plan() {
		return zero, errors.New("the trusted DNS snapshot differs from the recompiled rules")
	}
	p.dns = &dnsState{binding: binding, network: network, resolver: resolver, snapshot: snapshot}
	sum := sha256.Sum256([]byte(p.digest + "\nagentgate-dns-plan-v1\n" + snapshot.Digest()))
	p.digest = hex.EncodeToString(sum[:])
	return p, nil
}

type DNSPublication struct {
	Phase                         string
	Binding                       dnslease.Binding
	Revision                      uint64
	Digest, NetworkDigest, Reason string
	Resolver                      dnslease.ResolverEvidence
	Plan                          netrules.Policy
	Records                       []dnslease.Record
}

func publication(phase string, s dnslease.Snapshot) DNSPublication {
	return DNSPublication{Phase: phase, Binding: s.Binding(), Revision: s.Revision(), Digest: s.Digest(), NetworkDigest: s.NetworkDigest(), Reason: s.Reason(), Resolver: s.Resolver(), Plan: s.Plan(), Records: s.Records()}
}

type DNSPublisher struct {
	group   *Group
	binding dnslease.Binding
	record  func(context.Context, DNSPublication) error
}

// DNSPublisher requires a durable provenance writer. It shares the Group mutex.
func (g *Group) DNSPublisher(p Plan, record func(context.Context, DNSPublication) error) (*DNSPublisher, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || record == nil || p.dns == nil || g.dns == nil || g.generation != p.generation || g.dns.snapshot.Digest() != p.dns.snapshot.Digest() {
		return nil, errors.New("the DNS publisher requires the exact installed plan and provenance writer")
	}
	return &DNSPublisher{group: g, binding: p.dns.binding, record: record}, nil
}
func (p *DNSPublisher) state(binding dnslease.Binding) (*dnsState, error) {
	g := p.group
	if g.closed || binding != p.binding || g.dns == nil || g.dns.binding != binding || g.generation != binding.Generation || g.Peers == nil {
		return nil, errors.New("the active DNS publisher binding differs")
	}
	return g.dns, nil
}
func (p *DNSPublisher) Activate(ctx context.Context, binding dnslease.Binding, snapshot dnslease.Snapshot) error {
	g := p.group
	g.mu.Lock()
	defer g.mu.Unlock()
	s, err := p.state(binding)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if s.snapshot.Digest() != snapshot.Digest() || s.snapshot.Revision() != snapshot.Revision() {
		return errors.New("the initial DNS snapshot differs")
	}
	if err = s.check(snapshot.Revision() - 1); err != nil {
		return err
	}
	var actual netrules.Policy
	if err = g.Peers.Collection.Maps["net_policies"].Lookup(binding.DomainID, &actual); err != nil {
		return err
	}
	if actual != snapshot.Plan() {
		return errors.New("the initial DNS map readback differs")
	}
	return p.record(ctx, publication("activated", snapshot))
}
func (p *DNSPublisher) Publish(ctx context.Context, binding dnslease.Binding, snapshot dnslease.Snapshot) (err error) {
	g := p.group
	g.mu.Lock()
	defer g.mu.Unlock()
	defer func() {
		if err != nil {
			_ = g.StopRetain()
		}
	}()
	s, err := p.state(binding)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	now, err := kernel.MonotonicNS()
	if err != nil {
		return err
	}
	if now >= binding.DeadlineNS {
		return errors.New("the DNS publisher deadline expired")
	}
	if err = snapshot.Check(binding, s.network, s.resolver, s.snapshot.Revision(), now); err != nil {
		return err
	}
	m := g.Peers.Collection.Maps["net_policies"]
	var actual netrules.Policy
	if err = m.Lookup(binding.DomainID, &actual); err != nil {
		return err
	}
	if actual != s.snapshot.Plan() {
		return errors.New("the previous DNS map readback differs")
	}
	if err = p.record(ctx, publication("replace-intent", snapshot)); err != nil {
		return err
	}
	if err = m.Update(binding.DomainID, snapshot.Plan(), ebpf.UpdateExist); err != nil {
		return err
	}
	if err = m.Lookup(binding.DomainID, &actual); err != nil {
		return err
	}
	if actual != snapshot.Plan() {
		return errors.New("the replacement DNS map readback differs")
	}
	s.snapshot = snapshot
	return p.record(ctx, publication("replaced", snapshot))
}
func (p *DNSPublisher) Stop(ctx context.Context, binding dnslease.Binding, reason string) error {
	g := p.group
	g.mu.Lock()
	defer g.mu.Unlock()
	if binding != p.binding {
		return errors.New("a foreign DNS owner cannot stop this domain")
	}
	return g.StopRetain()
}

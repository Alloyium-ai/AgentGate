// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/policy"
)

type pilotPublisherWitness struct {
	published int
	stopped   int
}

func TestPilotAliasesRequireEveryAllowedHostname(t *testing.T) {
	network := policy.Network{Rules: []policy.NetworkRule{
		{ID: "web4", Family: "ipv4", Effect: "allow", Destination: policy.Destination{Kind: "hostname", Value: "example.org"}},
		{ID: "web6", Family: "ipv6", Effect: "allow", Destination: policy.Destination{Kind: "hostname", Value: "example.org"}},
		{ID: "other", Family: "ipv4", Effect: "deny", Destination: policy.Destination{Kind: "hostname", Value: "other.example"}},
	}}
	v4 := dnslease.Record{RuleID: "web4", Hostname: "example.org", Address: netip.MustParseAddr("93.184.215.14"), ExpiresNS: 200}
	v6 := dnslease.Record{RuleID: "web6", Hostname: "example.org", Address: netip.MustParseAddr("2606:4700::1111"), ExpiresNS: 200}
	if aliases, err := PilotHostAliases(network, []dnslease.Record{v4}, 100); err == nil || len(aliases) != 0 {
		t.Fatal("a partial hostname refresh was accepted", aliases, err)
	}
	if aliases, err := PilotHostAliases(network, []dnslease.Record{v4, v6}, 100); err != nil || len(aliases) != 2 {
		t.Fatal("complete trusted hostname leases were rejected", aliases, err)
	}
	bad := v6
	bad.Address = netip.MustParseAddr("93.184.215.14")
	if _, err := PilotHostAliases(network, []dnslease.Record{v4, bad}, 100); err == nil {
		t.Fatal("a lease of the wrong address family was accepted")
	}
	bad = v6
	bad.Hostname = "other.example"
	if _, err := PilotHostAliases(network, []dnslease.Record{v4, bad}, 100); err == nil {
		t.Fatal("a lease for another hostname was accepted")
	}
	if _, err := PilotHostAliases(network, []dnslease.Record{v4, v6}, 200); err == nil {
		t.Fatal("expired leases were accepted")
	}
}

func (*pilotPublisherWitness) Activate(context.Context, dnslease.Binding, dnslease.Snapshot) error {
	return nil
}
func (p *pilotPublisherWitness) Publish(context.Context, dnslease.Binding, dnslease.Snapshot) error {
	p.published++
	return nil
}
func (p *pilotPublisherWitness) Stop(context.Context, dnslease.Binding, string) error {
	p.stopped++
	return nil
}

func TestPilotLeaseRefreshRequiresCurrentTargetAlias(t *testing.T) {
	inner := &pilotPublisherWitness{}
	stale := errors.New("the target hostname mapping differs from the trusted lease")
	p := pilotHostPublisher{inner: inner, verify: func(context.Context, dnslease.Snapshot) error { return stale }}
	ctx := context.Background()
	var binding dnslease.Binding
	var snapshot dnslease.Snapshot
	if err := p.Publish(ctx, binding, snapshot); !errors.Is(err, stale) || inner.published != 0 {
		t.Fatalf("stale target alias reached the kernel publisher: %v, %d", err, inner.published)
	}
	if err := p.Stop(ctx, binding, "stale-target-alias"); err != nil || inner.stopped != 1 {
		t.Fatalf("the coordinator could not stop the stale target: %v, %d", err, inner.stopped)
	}
	p.verify = func(context.Context, dnslease.Snapshot) error { return nil }
	if err := p.Publish(ctx, binding, snapshot); err != nil || inner.published != 1 {
		t.Fatalf("the unchanged alias could not publish a renewed lease: %v, %d", err, inner.published)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/testpolicy"
	"context"
	"strings"
	"testing"
)

type inertResolver struct{ e dnslease.ResolverEvidence }

func (r inertResolver) Evidence() dnslease.ResolverEvidence { return r.e }
func (r inertResolver) Exchange(context.Context, []byte) ([]byte, error) {
	panic("literal plans must not query DNS")
}
func TestResolvedPlanRequiresExactRulesBindingAndResolver(t *testing.T) {
	d := testpolicy.Deny()
	d.Network.Rules = []policy.NetworkRule{{ID: "literal", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "ip", Value: "127.0.0.1"}, PortFrom: 1234, PortTo: 1234, Effect: "allow"}}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	digest, err := d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	binding := dnslease.Binding{JobID: "run", DomainID: 42, Generation: 3, DeadlineNS: 1000000, PolicySHA256: digest}
	resolver := inertResolver{dnslease.ResolverEvidence{Transport: "tls1.3", Address: "127.0.0.1:853", ServerName: "resolver.example", RootsSHA256: strings.Repeat("a", 64), TimeoutMS: 1000}}
	manager, err := dnslease.New(dnslease.Config{Binding: binding, Network: *d.Network, Resolver: resolver, Now: func() (uint64, error) { return 100, nil }})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := manager.Snapshot(binding)
	if err != nil {
		t.Fatal(err)
	}
	p, err := CompileResolved(d, binding, 100, snapshot, resolver.e)
	if err != nil {
		t.Fatal(err)
	}
	if p.dns == nil || p.peers.Policy != snapshot.Plan() || p.peers.Policy.Reserved == 0 || p.files.State().SocketGeneration != 0 {
		t.Fatal("the resolved plan differs or added an implicit delegation")
	}
	bad := binding
	bad.PolicySHA256 = strings.Repeat("b", 64)
	if _, err = CompileResolved(d, bad, 100, snapshot, resolver.e); err == nil {
		t.Fatal("a different signed policy reused the snapshot")
	}
	wrongResolver := resolver.e
	wrongResolver.ServerName = "foreign.example"
	if _, err = CompileResolved(d, binding, 100, snapshot, wrongResolver); err == nil {
		t.Fatal("a foreign resolver reused the snapshot")
	}
	if _, err = CompileResolved(d, binding, binding.DeadlineNS, snapshot, resolver.e); err == nil {
		t.Fatal("an expired endpoint plan compiled")
	}
	revoked, err := manager.Revoke(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = CompileResolved(d, binding, 100, revoked, resolver.e); err == nil {
		t.Fatal("a denied snapshot activated as a complete plan")
	}
	if _, err = (&Group{}).DNSPublisher(p, nil); err == nil {
		t.Fatal("the DNS provenance writer was optional")
	}
}

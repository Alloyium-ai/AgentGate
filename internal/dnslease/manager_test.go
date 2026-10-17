// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dnslease

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/policy"
	"golang.org/x/net/dns/dnsmessage"
)

type fakeResolver struct {
	calls int
	reply func(dnsmessage.Message) ([]byte, error)
}

func (f *fakeResolver) Evidence() ResolverEvidence {
	return ResolverEvidence{Transport: "tls1.3", Address: "127.0.0.1:853", ServerName: "resolver.example.test", RootsSHA256: strings.Repeat("a", 64), TimeoutMS: 1000}
}
func (f *fakeResolver) Exchange(_ context.Context, wire []byte) ([]byte, error) {
	f.calls++
	var q dnsmessage.Message
	if err := q.Unpack(wire); err != nil {
		return nil, err
	}
	return f.reply(q)
}

func testNetwork() policy.Network {
	return policy.Network{Default: "deny", DNS: policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"}, Rules: []policy.NetworkRule{{ID: "api", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: "api.example.test"}, PortFrom: 443, PortTo: 443, Effect: "allow"}}}
}
func question(t *testing.T, name string, typeID dnsmessage.Type) []byte {
	t.Helper()
	wire, err := (&dnsmessage.Message{Header: dnsmessage.Header{ID: 17, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName(name), Type: typeID, Class: dnsmessage.ClassINET}}}).Pack()
	if err != nil {
		t.Fatal(err)
	}
	return wire
}
func answer(q dnsmessage.Message, alias bool) dnsmessage.Message {
	q.Header = dnsmessage.Header{ID: q.ID, Response: true, RecursionDesired: q.RecursionDesired, RecursionAvailable: true}
	owner := q.Questions[0].Name
	if alias {
		target := dnsmessage.MustNewName("edge.example.test.")
		q.Answers = append(q.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: owner, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 2}, Body: &dnsmessage.CNAMEResource{CNAME: target}})
		owner = target
	}
	q.Answers = append(q.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: owner, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 10}, Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 10}}})
	return q
}
func managerFixture(t *testing.T, network policy.Network) (*Manager, *fakeResolver, *atomic.Uint64, Binding) {
	t.Helper()
	clock := new(atomic.Uint64)
	clock.Store(uint64(time.Second))
	binding := Binding{JobID: "owned-dns-job", DomainID: 42, Generation: 7, DeadlineNS: uint64(20 * time.Second), PolicySHA256: strings.Repeat("b", 64)}
	resolver := &fakeResolver{reply: func(q dnsmessage.Message) ([]byte, error) { m := answer(q, true); return m.Pack() }}
	m, err := New(Config{Binding: binding, Network: network, Resolver: resolver, Now: func() (uint64, error) { return clock.Load(), nil }})
	if err != nil {
		t.Fatal(err)
	}
	return m, resolver, clock, binding
}
func checkSnapshot(t *testing.T, m *Manager, s Snapshot, b Binding, previous, now uint64) {
	t.Helper()
	if err := s.Check(b, m.networkDigest, m.evidence, previous, now); err != nil {
		t.Fatal(err)
	}
}

func TestValidatedLeaseExpiryRefreshAndRevoke(t *testing.T) {
	m, resolver, clock, binding := managerFixture(t, testNetwork())
	initial, _ := m.Snapshot(binding)
	if initial.Plan().Count != 0 {
		t.Fatal("unresolved hostname authorized an endpoint")
	}
	result := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
	if result.Error != "" || !result.Changed || result.Snapshot.Plan().Count != 1 || resolver.calls != 1 {
		t.Fatalf("validated reply: %+v", result)
	}
	checkSnapshot(t, m, result.Snapshot, binding, initial.Revision(), clock.Load())
	record := result.Snapshot.Records()[0]
	if record.ExpiresNS != uint64(3*time.Second) || len(record.Chain) != 2 || record.Address != netip.MustParseAddr("192.0.2.10") {
		t.Fatal(record)
	}
	var response dnsmessage.Message
	if err := response.Unpack(result.Response); err != nil || response.ID != 17 || response.Answers[1].Header.TTL != 2 {
		t.Fatal("client reply does not retain identity and bounded TTL", err)
	}
	clock.Store(uint64(3 * time.Second))
	expired, _ := m.Snapshot(binding)
	if expired.Plan().Count != 0 {
		t.Fatal("expired lease remained authorized")
	}
	checkSnapshot(t, m, expired, binding, result.Snapshot.Revision(), clock.Load())
	refreshed := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
	if refreshed.Error != "" || refreshed.Snapshot.Plan().Count != 1 {
		t.Fatal(refreshed.Error)
	}
	revoked, _ := m.Revoke(binding)
	if revoked.Plan().Count != 0 {
		t.Fatal("revocation left an endpoint")
	}
	closed := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
	if closed.Error == "" || closed.Snapshot.Plan().Count != 0 || resolver.calls != 2 {
		t.Fatal("revoked binding reused the resolver")
	}
}

func TestUnknownQueryCannotForwardOrChangeLeases(t *testing.T) {
	m, resolver, clock, binding := managerFixture(t, testNetwork())
	valid := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
	for name, wire := range map[string][]byte{
		"other-name": question(t, "other.example.test.", dnsmessage.TypeA), "other-family": question(t, "api.example.test.", dnsmessage.TypeAAAA), "other-type": question(t, "api.example.test.", dnsmessage.TypeMX), "uppercase": question(t, "API.example.test.", dnsmessage.TypeA), "ip-name": question(t, "192.0.2.10.", dnsmessage.TypeA), "trailing": append(question(t, "api.example.test.", dnsmessage.TypeA), 0), "short": {0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			out := m.Forward(context.Background(), binding, wire)
			if out.Error == "" || out.Changed {
				t.Fatal("unapproved question changed state")
			}
		})
	}
	if resolver.calls != 1 {
		t.Fatal("unapproved question reached the resolver")
	}
	snapshot, _ := m.Snapshot(binding)
	if snapshot.Plan().Count != 1 {
		t.Fatal("an unapproved query changed a live lease")
	}
	checkSnapshot(t, m, snapshot, binding, valid.Snapshot.Revision(), clock.Load())
}

func TestReplyFailuresReplaceAllEndpointsWithDeny(t *testing.T) {
	changes := map[string]func(*dnsmessage.Message){
		"wrong-id": func(m *dnsmessage.Message) { m.ID++ }, "wrong-question": func(m *dnsmessage.Message) { m.Questions[0].Name = dnsmessage.MustNewName("other.example.test.") }, "truncated": func(m *dnsmessage.Message) { m.Truncated = true }, "not-response": func(m *dnsmessage.Message) { m.Response = false }, "nxdomain": func(m *dnsmessage.Message) { m.RCode = dnsmessage.RCodeNameError }, "empty": func(m *dnsmessage.Message) { m.Answers = nil }, "zero-ttl": func(m *dnsmessage.Message) { m.Answers[0].Header.TTL = 0 }, "unrelated": func(m *dnsmessage.Message) {
			extra := m.Answers[1]
			extra.Header.Name = dnsmessage.MustNewName("unrelated.example.test.")
			m.Answers = append(m.Answers, extra)
		}, "incomplete": func(m *dnsmessage.Message) { m.Answers = m.Answers[:1] }, "cycle": func(m *dnsmessage.Message) { m.Answers[0].Body = &dnsmessage.CNAMEResource{CNAME: m.Questions[0].Name} }, "class": func(m *dnsmessage.Message) { m.Answers[0].Header.Class = dnsmessage.ClassANY }, "family": func(m *dnsmessage.Message) {
			m.Answers[1].Header.Type = dnsmessage.TypeAAAA
			m.Answers[1].Body = &dnsmessage.AAAAResource{AAAA: [16]byte{15: 1}}
		}, "unspecified": func(m *dnsmessage.Message) { m.Answers[1].Body = &dnsmessage.AResource{} }, "additional": func(m *dnsmessage.Message) { m.Additionals = []dnsmessage.Resource{m.Answers[1]} }, "authority": func(m *dnsmessage.Message) { m.Authorities = []dnsmessage.Resource{m.Answers[1]} },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			m, resolver, _, binding := managerFixture(t, testNetwork())
			live := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
			if live.Error != "" {
				t.Fatal(live.Error)
			}
			resolver.reply = func(q dnsmessage.Message) ([]byte, error) {
				reply := answer(q, true)
				change(&reply)
				return reply.Pack()
			}
			failed := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
			if failed.Error == "" || !failed.Changed || failed.Snapshot.Plan().Count != 0 || failed.Snapshot.Revision() <= live.Snapshot.Revision() {
				t.Fatalf("failure did not revoke snapshot: %+v", failed)
			}
		})
	}
}

func TestDenyHostnameCannotDisappearIntoBroaderAllow(t *testing.T) {
	network := testNetwork()
	network.Rules[0].Effect = "deny"
	network.Rules = append(network.Rules, policy.NetworkRule{ID: "broad", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "prefix", Value: "0.0.0.0/0"}, PortFrom: 443, PortTo: 443, Effect: "allow"})
	m, _, clock, binding := managerFixture(t, network)
	initial, _ := m.Snapshot(binding)
	if initial.Plan().Count != 0 {
		t.Fatal("unresolved deny exposed a broader allow")
	}
	result := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
	if result.Error != "" {
		t.Fatal(result.Error)
	}
	if netrules.Evaluate(result.Snapshot.Plan(), netrules.Endpoint{Address: netip.MustParseAddr("192.0.2.10"), Protocol: netrules.TCP, Port: 443}, clock.Load()).Allowed {
		t.Fatal("hostname deny lost precedence")
	}
	clock.Store(uint64(3 * time.Second))
	expired, _ := m.Snapshot(binding)
	if expired.Plan().Count != 0 {
		t.Fatal("expired hostname deny exposed a broader allow")
	}
}

func TestSnapshotCustodyAndJobIsolation(t *testing.T) {
	network := testNetwork()
	m, _, clock, binding := managerFixture(t, network)
	live := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA)).Snapshot
	changed := binding
	changed.DomainID++
	if out := m.Forward(context.Background(), changed, question(t, "api.example.test.", dnsmessage.TypeA)); out.Changed || out.Error == "" {
		t.Fatal("another job changed leases")
	}
	if live.Check(changed, m.networkDigest, m.evidence, 0, clock.Load()) == nil || live.Check(binding, m.networkDigest, m.evidence, live.Revision(), clock.Load()) == nil {
		t.Fatal("borrowed or stale snapshot accepted")
	}
	if live.Check(binding, strings.Repeat("c", 64), m.evidence, 0, clock.Load()) == nil {
		t.Fatal("changed network accepted")
	}
	copyPlan := live.Plan()
	copyPlan.Rules[0].Effect = netrules.Deny
	copyRecords := live.Records()
	copyRecords[0].Chain[0] = "other.example.test"
	checkSnapshot(t, m, live, binding, 0, clock.Load())
	if live.Plan().Rules[0].Effect != netrules.Allow || live.Records()[0].Chain[0] != "api.example.test" {
		t.Fatal("copy accessor changed snapshot")
	}
	network.Rules[0].Destination.Value = "mutated.example.test"
	if m.network.Rules[0].Destination.Value != "api.example.test" {
		t.Fatal("caller changed manager rules")
	}
	other, _, _, otherBinding := managerFixture(t, testNetwork())
	otherBinding.JobID = "other"
	other.binding = otherBinding
	if live.Check(otherBinding, other.networkDigest, other.evidence, 0, clock.Load()) == nil {
		t.Fatal("another manager borrowed a snapshot")
	}
}

func TestDeadlineAndFailedTransportProduceDeny(t *testing.T) {
	m, resolver, clock, binding := managerFixture(t, testNetwork())
	clock.Store(binding.DeadlineNS - uint64(time.Second))
	result := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
	if result.Error != "" || result.Snapshot.Records()[0].ExpiresNS != binding.DeadlineNS {
		t.Fatal("TTL exceeds the grant", result.Error)
	}
	resolver.reply = func(dnsmessage.Message) ([]byte, error) { return nil, fmt.Errorf("owned transport failure") }
	failed := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
	if failed.Error == "" || failed.Snapshot.Plan().Count != 0 {
		t.Fatal("transport failure retained a grant")
	}
	clock.Store(binding.DeadlineNS)
	expired := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
	if expired.Error == "" || expired.Snapshot.Plan().Count != 0 || resolver.calls != 2 {
		t.Fatal("expired job reached the resolver")
	}
}

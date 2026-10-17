// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dnslease

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/policy"
	"golang.org/x/net/dns/dnsmessage"
)

func TestCNAMEBoundAndUnorderedCompleteChain(t *testing.T) {
	for _, depth := range []int{0, 8, 9} {
		t.Run(fmt.Sprint(depth), func(t *testing.T) {
			m, resolver, _, binding := managerFixture(t, testNetwork())
			resolver.reply = func(q dnsmessage.Message) ([]byte, error) {
				reply := answer(q, false)
				terminal := reply.Answers[0]
				reply.Answers = nil
				owner := q.Questions[0].Name
				for i := 0; i < depth; i++ {
					target := dnsmessage.MustNewName(fmt.Sprintf("edge%d.example.test.", i))
					reply.Answers = append(reply.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: owner, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 3}, Body: &dnsmessage.CNAMEResource{CNAME: target}})
					owner = target
				}
				terminal.Header.Name = owner
				reply.Answers = append(reply.Answers, terminal)
				for left, right := 0, len(reply.Answers)-1; left < right; left, right = left+1, right-1 {
					reply.Answers[left], reply.Answers[right] = reply.Answers[right], reply.Answers[left]
				}
				return reply.Pack()
			}
			out := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
			if depth <= 8 {
				if out.Error != "" || len(out.Snapshot.Records()[0].Chain) != depth+1 {
					t.Fatal(out.Error)
				}
			} else if out.Error == "" || out.Snapshot.Plan().Count != 0 {
				t.Fatal("CNAME depth overflow accepted")
			}
		})
	}
}

func TestReplyWireBoundsAndTTLInFlight(t *testing.T) {
	for _, mode := range []string{"trailing", "short", "pointer", "large-length", "expired-ttl", "expired-job", "clock-rollback"} {
		t.Run(mode, func(t *testing.T) {
			m, resolver, clock, binding := managerFixture(t, testNetwork())
			resolver.reply = func(q dnsmessage.Message) ([]byte, error) {
				reply := answer(q, true)
				wire, err := reply.Pack()
				if err != nil {
					return nil, err
				}
				switch mode {
				case "trailing":
					wire = append(wire, 0)
				case "short":
					wire = wire[:len(wire)-1]
				case "pointer":
					query, _ := q.Pack()
					offset := len(query)
					wire[offset] = 0xc0 | byte(offset>>8)
					wire[offset+1] = byte(offset)
				case "large-length":
					query, _ := q.Pack()
					offset, scanErr := skipWireName(wire, len(query))
					if scanErr != nil {
						return nil, scanErr
					}
					binary.BigEndian.PutUint16(wire[offset+8:offset+10], 65535)
				case "expired-ttl":
					clock.Store(uint64(4 * time.Second))
				case "expired-job":
					clock.Store(binding.DeadlineNS)
				case "clock-rollback":
					clock.Store(uint64(time.Second / 2))
				}
				return wire, nil
			}
			out := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
			if out.Error == "" || !out.Changed || out.Snapshot.Plan().Count != 0 {
				t.Fatalf("bad reply remained authorized: %+v", out)
			}
		})
	}
}

func TestAAAAAndMultipleRuleLeaseCustody(t *testing.T) {
	network := testNetwork()
	network.Rules[0].Family = "ipv6"
	copyRule := network.Rules[0]
	copyRule.ID = "other-port"
	copyRule.Protocol = "udp"
	copyRule.PortFrom = 8443
	copyRule.PortTo = 8443
	network.Rules = append(network.Rules, copyRule)
	m, resolver, _, binding := managerFixture(t, network)
	resolver.reply = func(q dnsmessage.Message) ([]byte, error) {
		reply := answer(q, false)
		reply.Answers[0].Header.Type = dnsmessage.TypeAAAA
		reply.Answers[0].Body = &dnsmessage.AAAAResource{AAAA: netip.MustParseAddr("2001:db8::10").As16()}
		return reply.Pack()
	}
	out := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeAAAA))
	if out.Error != "" || out.Snapshot.Plan().Count != 2 || resolver.calls != 1 {
		t.Fatal("one validated AAAA did not bind both explicit rules", out.Error)
	}
	for _, record := range out.Snapshot.Records() {
		if !record.Address.Is6() || record.Hostname != "api.example.test" {
			t.Fatal(record)
		}
	}
	if a := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA)); a.Changed || a.Error == "" {
		t.Fatal("AAAA rule granted an A query")
	}
}

func TestExpandedLeaseLimitRejectsCompleteSnapshot(t *testing.T) {
	network := testNetwork()
	for i := 1; i < 128; i++ {
		rule := network.Rules[0]
		rule.ID = fmt.Sprintf("rule-%03d", i)
		network.Rules = append(network.Rules, rule)
	}
	m, resolver, _, binding := managerFixture(t, network)
	resolver.reply = func(q dnsmessage.Message) ([]byte, error) {
		reply := answer(q, false)
		extra := reply.Answers[0]
		extra.Body = &dnsmessage.AResource{A: [4]byte{192, 0, 2, 11}}
		reply.Answers = append(reply.Answers, extra)
		return reply.Pack()
	}
	out := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
	if out.Error == "" || out.Snapshot.Plan().Count != 0 {
		t.Fatal("expanded rule overflow accepted")
	}
}

func TestManagerSerializesLeaseRevisions(t *testing.T) {
	m, _, clock, binding := managerFixture(t, testNetwork())
	wire := question(t, "api.example.test.", dnsmessage.TypeA)
	outcomes := make(chan Outcome, 16)
	var wait sync.WaitGroup
	for i := 0; i < 16; i++ {
		wait.Add(1)
		go func() { defer wait.Done(); outcomes <- m.Forward(context.Background(), binding, wire) }()
	}
	wait.Wait()
	close(outcomes)
	seen := map[uint64]bool{}
	for out := range outcomes {
		if out.Error != "" || seen[out.Snapshot.Revision()] {
			t.Fatal("concurrent queries reused a revision", out.Error)
		}
		seen[out.Snapshot.Revision()] = true
		checkSnapshot(t, m, out.Snapshot, binding, 0, clock.Load())
	}
}

func TestMalformedBindingAndSourcePolicyReject(t *testing.T) {
	m, resolver, clock, binding := managerFixture(t, testNetwork())
	for _, change := range []func(*Config){func(c *Config) { c.Binding.DomainID = 0 }, func(c *Config) { c.Binding.Generation = 0 }, func(c *Config) { c.Binding.DeadlineNS = clock.Load() }, func(c *Config) { c.Binding.PolicySHA256 = "unbound" }, func(c *Config) { c.Now = nil }, func(c *Config) { c.Resolver = nil }, func(c *Config) { c.Network.Default = "allow" }, func(c *Config) {
		c.Network.Rules[0].Destination = policy.Destination{Kind: "hostname", Value: "UPPER.example.test"}
	}} {
		config := Config{Binding: binding, Network: testNetwork(), Resolver: resolver, Now: m.now}
		change(&config)
		if _, err := New(config); err == nil {
			t.Fatal("invalid manager configuration accepted")
		}
	}
}

func TestKernelLeaseRevisionNeverWrapsOrReuses(t *testing.T) {
	m, resolver, clock, binding := managerFixture(t, testNetwork())
	m.revision = MaxLeaseRevision - 1
	last := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
	if last.Error != "" || last.Snapshot.Revision() != MaxLeaseRevision || last.Snapshot.Plan().Reserved != ^uint32(0) {
		t.Fatal("last lease revision differs")
	}
	checkSnapshot(t, m, last.Snapshot, binding, MaxLeaseRevision-1, clock.Load())
	exhausted := m.Forward(context.Background(), binding, question(t, "api.example.test.", dnsmessage.TypeA))
	if !exhausted.Fatal || exhausted.Changed || exhausted.Error == "" || resolver.calls != 1 {
		t.Fatal("lease revision exhaustion did not require a stop")
	}
	if _, err := m.Snapshot(binding); err == nil {
		t.Fatal("exhausted manager returned a usable snapshot")
	}
	if _, err := m.Revoke(binding); err == nil {
		t.Fatal("exhausted manager reused a kernel revision")
	}
}

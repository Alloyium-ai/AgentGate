// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package netrules

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"

	"alloyium.local/kernel-poc/internal/policy"
)

func network(rules ...policy.NetworkRule) policy.Network {
	return policy.Network{Default: "deny", Rules: rules, DNS: policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"}}
}
func source(id, family, protocol, kind, value string, from, to int, effect string) policy.NetworkRule {
	return policy.NetworkRule{ID: id, Family: family, Protocol: protocol, Destination: policy.Destination{Kind: kind, Value: value}, PortFrom: from, PortTo: to, Effect: effect}
}
func endpoint(address string, protocol uint8, port uint16) Endpoint {
	return Endpoint{Address: netip.MustParseAddr(address), Protocol: protocol, Port: port}
}
func compiled(t *testing.T, rules ...policy.NetworkRule) Policy {
	t.Helper()
	c, err := Compile(network(rules...), 7, 100, 1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c.Policy
}

func TestMapABI(t *testing.T) {
	if binary.Size(Rule{}) != 40 || binary.Size(Policy{}) != 5144 {
		t.Fatal("BPF map ABI changed")
	}
}

func TestDenyDefaultsAndProtocols(t *testing.T) {
	p := compiled(t)
	if Evaluate(p, endpoint("127.0.0.1", TCP, 443), 200).Allowed {
		t.Fatal("empty policy allowed")
	}
	p = compiled(t, source("tcp4", "ipv4", "tcp", "ip", "127.0.0.1", 443, 443, "allow"), source("udp6", "ipv6", "udp", "ip", "::1", 5000, 5002, "allow"))
	for _, test := range []struct {
		name  string
		ep    Endpoint
		allow bool
	}{
		{"tcp4", endpoint("127.0.0.1", TCP, 443), true},
		{"wrong-address", endpoint("127.0.0.2", TCP, 443), false},
		{"wrong-port", endpoint("127.0.0.1", TCP, 444), false},
		{"wrong-transport", endpoint("127.0.0.1", UDP, 443), false},
		{"udp6-low", endpoint("::1", UDP, 5000), true},
		{"udp6-high", endpoint("::1", UDP, 5002), true},
		{"udp6-outside", endpoint("::1", UDP, 5003), false},
		{"mapped", endpoint("::ffff:127.0.0.1", TCP, 443), false},
		{"zero-port", endpoint("::1", UDP, 0), false},
		{"unsupported-protocol", endpoint("::1", 132, 5000), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := Evaluate(p, test.ep, 200).Allowed; got != test.allow {
				t.Fatalf("allow=%v, want %v", got, test.allow)
			}
		})
	}
}

func TestPrecedenceAndStableOrder(t *testing.T) {
	rules := []policy.NetworkRule{
		source("broad-deny", "ipv4", "tcp", "prefix", "192.0.2.0/24", 1, 65535, "deny"),
		source("specific-allow", "ipv4", "tcp", "prefix", "192.0.2.128/25", 400, 500, "allow"),
		source("port-deny", "ipv4", "tcp", "prefix", "192.0.2.128/25", 443, 443, "deny"),
		source("tie-allow", "ipv4", "tcp", "prefix", "192.0.2.128/25", 443, 443, "allow"),
		source("exact-allow", "ipv4", "tcp", "ip", "192.0.2.200", 443, 443, "allow"),
	}
	first, err := Compile(network(rules...), 7, 100, 1000, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		address string
		port    uint16
		allow   bool
	}{{"192.0.2.10", 450, false}, {"192.0.2.150", 450, true}, {"192.0.2.150", 443, false}, {"192.0.2.200", 443, true}} {
		if got := Evaluate(first.Policy, endpoint(test.address, TCP, test.port), 200).Allowed; got != test.allow {
			t.Fatalf("%s:%d allow=%v", test.address, test.port, got)
		}
	}
	for i, j := 0, len(rules)-1; i < j; i, j = i+1, j-1 {
		rules[i], rules[j] = rules[j], rules[i]
	}
	second, err := Compile(network(rules...), 7, 100, 1000, nil)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("source order changed compiled policy", err)
	}
}

func TestPrefixBitBoundaries(t *testing.T) {
	p := compiled(t, source("v4", "ipv4", "udp", "prefix", "192.0.2.128/25", 53, 53, "allow"), source("v6", "ipv6", "tcp", "prefix", "2001:db8:0:0:8000::/65", 443, 443, "allow"))
	for _, test := range []struct {
		ep    Endpoint
		allow bool
	}{{endpoint("192.0.2.127", UDP, 53), false}, {endpoint("192.0.2.128", UDP, 53), true}, {endpoint("2001:db8::7fff:ffff:ffff:ffff", TCP, 443), false}, {endpoint("2001:db8::8000:0:0:1", TCP, 443), true}} {
		if Evaluate(p, test.ep, 200).Allowed != test.allow {
			t.Fatal(test)
		}
	}
}

func TestExpiryReplacementAndRevocation(t *testing.T) {
	p := compiled(t, source("allow", "ipv4", "tcp", "ip", "127.0.0.1", 443, 443, "allow"))
	ep := endpoint("127.0.0.1", TCP, 443)
	if !Evaluate(p, ep, 999).Allowed || Evaluate(p, ep, 1000).Allowed {
		t.Fatal("grant deadline is not exclusive")
	}
	if Evaluate(Policy{}, ep, 200).Allowed {
		t.Fatal("zero replacement allowed")
	}
	p.Count = MaxRules + 1
	if Evaluate(p, ep, 200).Allowed {
		t.Fatal("corrupt policy allowed")
	}
	p = compiled(t, source("allow", "ipv4", "tcp", "ip", "127.0.0.1", 443, 443, "allow"))
	p.Rules[0].Effect = 2
	if Evaluate(p, ep, 200).Allowed {
		t.Fatal("corrupt rule allowed")
	}
}

func TestWidePrefixesKeepUnsupportedDestinationsDenied(t *testing.T) {
	p := compiled(t, source("v4", "ipv4", "tcp", "prefix", "0.0.0.0/0", 1, 65535, "allow"), source("v6", "ipv6", "tcp", "prefix", "::/0", 1, 65535, "allow"))
	for _, address := range []string{"0.0.0.0", "224.0.0.1", "255.255.255.255", "::", "ff02::1", "::ffff:192.0.2.1", "fe80::1%eth0"} {
		if Evaluate(p, endpoint(address, TCP, 443), 200).Allowed {
			t.Fatal("unsupported destination allowed", address)
		}
	}
}

func TestRejectMalformedOrUnsupportedSource(t *testing.T) {
	base := source("one", "ipv4", "tcp", "ip", "127.0.0.1", 443, 443, "allow")
	for _, change := range []func(*policy.NetworkRule){
		func(r *policy.NetworkRule) { r.ID = "" }, func(r *policy.NetworkRule) { r.Family = "unix" }, func(r *policy.NetworkRule) { r.Protocol = "icmp" },
		func(r *policy.NetworkRule) { r.PortFrom = 0 }, func(r *policy.NetworkRule) { r.PortFrom = 444 }, func(r *policy.NetworkRule) { r.PortTo = 65536 },
		func(r *policy.NetworkRule) { r.Effect = "audit" }, func(r *policy.NetworkRule) { r.Destination.Kind = "anything" },
		func(r *policy.NetworkRule) { r.Destination.Value = "::1" }, func(r *policy.NetworkRule) { r.Destination.Value = "255.255.255.255" },
		func(r *policy.NetworkRule) { r.Destination = policy.Destination{Kind: "prefix", Value: "192.0.2.1/24"} },
		func(r *policy.NetworkRule) {
			r.Destination = policy.Destination{Kind: "hostname", Value: "Example.test"}
		},
	} {
		r := base
		change(&r)
		if _, err := Compile(network(r), 7, 100, 1000, nil); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	if _, err := Compile(network(base, base), 7, 100, 1000, nil); err == nil {
		t.Fatal("accepted duplicate ID")
	}
	if _, err := Compile(network(base), 0, 100, 1000, nil); err == nil {
		t.Fatal("accepted zero generation")
	}
	n := network(base)
	n.Default = "allow"
	if _, err := Compile(n, 7, 100, 1000, nil); err == nil {
		t.Fatal("accepted allow default")
	}
}

func TestDNSLeasesAndFailClosedRefresh(t *testing.T) {
	r := source("dns", "ipv4", "tcp", "hostname", "code.example.test", 443, 443, "allow")
	lease := Lease{RuleID: r.ID, Hostname: r.Destination.Value, Address: netip.MustParseAddr("192.0.2.1"), Chain: []string{"code.example.test", "edge.example.test"}, ExpiresNS: 400}
	c, err := Compile(network(r), 7, 100, 1000, []Lease{lease})
	if err != nil {
		t.Fatal(err)
	}
	ep := endpoint("192.0.2.1", TCP, 443)
	if !Evaluate(c.Policy, ep, 399).Allowed || Evaluate(c.Policy, ep, 400).Allowed {
		t.Fatal("DNS allow survived the TTL")
	}
	if _, err := Compile(network(r), 8, 100, 1000, nil); err == nil {
		t.Fatal("unresolved hostname allowed")
	}
	for _, modify := range []func(*Lease){func(l *Lease) { l.ExpiresNS = 100 }, func(l *Lease) { l.ExpiresNS = 1001 }, func(l *Lease) { l.Hostname = "other.test" }, func(l *Lease) { l.Address = netip.MustParseAddr("::1") }, func(l *Lease) { l.Chain = []string{"code.example.test", "code.example.test"} }, func(l *Lease) { l.RuleID = "unknown" }} {
		bad := lease
		modify(&bad)
		if _, err := Compile(network(r), 7, 100, 1000, []Lease{bad}); err == nil {
			t.Fatalf("accepted bad lease %+v", bad)
		}
	}
	// Expiry must not expose a broad allowance below a DNS deny.
	r.Effect = "deny"
	broad := source("broad", "ipv4", "tcp", "prefix", "192.0.2.0/24", 443, 443, "allow")
	c, err = Compile(network(r, broad), 7, 100, 1000, []Lease{lease})
	if err != nil || Evaluate(c.Policy, ep, 500).Allowed {
		t.Fatal("expired DNS deny exposed a broad allowance", err)
	}
	lease.Address = netip.MustParseAddr("192.0.2.2")
	lease.ExpiresNS = 800
	c, err = Compile(network(source("dns", "ipv4", "tcp", "hostname", "code.example.test", 443, 443, "allow")), 8, 500, 1000, []Lease{lease})
	if err != nil || Evaluate(c.Policy, ep, 600).Allowed || !Evaluate(c.Policy, endpoint("192.0.2.2", TCP, 443), 600).Allowed {
		t.Fatal("refresh retained the old address", err)
	}
}

func TestExpandedRuleLimit(t *testing.T) {
	r := source("dns", "ipv4", "udp", "hostname", "service.example.test", 53, 53, "allow")
	leases := make([]Lease, MaxRules+1)
	for i := range leases {
		leases[i] = Lease{RuleID: r.ID, Hostname: r.Destination.Value, Address: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}), Chain: []string{r.Destination.Value}, ExpiresNS: 500}
	}
	if _, err := Compile(network(r), 7, 100, 1000, leases); err == nil {
		t.Fatal("accepted excessive expanded rules")
	}
}

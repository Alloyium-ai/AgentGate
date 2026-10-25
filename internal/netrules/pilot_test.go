// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package netrules

import (
	"net/netip"
	"testing"

	"alloyium.local/kernel-poc/internal/policy"
)

func pilotNetwork(rules ...policy.NetworkRule) policy.Network {
	n := network(rules...)
	n.Pilot = &policy.PilotNetwork{Mode: "ssh-coding.v1", TaskboardIP: "10.77.0.2", TaskboardPort: 18080, TaskboardTaskID: 42}
	return n
}

func TestPilotLANBoundaryAndExactTaskboard(t *testing.T) {
	taskboard := source("taskboard", "ipv4", "tcp", "ip", "10.77.0.2", 18080, 18080, "allow")
	public := source("sample", "ipv4", "tcp", "hostname", "example.org", 443, 443, "allow")
	lease := Lease{RuleID: "sample", Hostname: "example.org", Address: netip.MustParseAddr("93.184.215.14"), Chain: []string{"example.org"}, ExpiresNS: 400}
	c, err := Compile(pilotNetwork(taskboard, public), 7, 100, 1000, []Lease{lease})
	if err != nil || c.Policy.PilotMode != 1 {
		t.Fatal("pilot policy did not compile", err)
	}
	for _, test := range []struct {
		address string
		port    uint16
		allowed bool
	}{
		{"10.77.0.2", 18080, true}, {"10.77.0.2", 443, false},
		{"10.77.0.1", 18080, false}, {"10.0.0.1", 18080, false},
		{"172.16.0.1", 18080, false}, {"127.0.0.1", 18080, false},
		{"169.254.1.1", 18080, false}, {"100.64.1.1", 18080, false},
		{"93.184.215.14", 443, true}, {"93.184.215.14", 18080, false},
		{"::1", 18080, false}, {"::a00:1", 18080, false},
		{"fc00::1", 18080, false}, {"fe80::1", 18080, false}, {"fec0::1", 18080, false},
		{"64:ff9b::a00:1", 18080, false}, {"64:ff9b:1::a00:1", 18080, false},
		{"2001::1", 18080, false}, {"2002:a00:101::1", 18080, false},
	} {
		if got := Evaluate(c.Policy, endpoint(test.address, TCP, test.port), 200).Allowed; got != test.allowed {
			t.Fatalf("%s:%d allowed=%t, want %t", test.address, test.port, got, test.allowed)
		}
	}
	lease.Address = netip.MustParseAddr("10.77.0.1")
	if _, err := Compile(pilotNetwork(taskboard, public), 7, 100, 1000, []Lease{lease}); err == nil {
		t.Fatal("a private DNS result entered the pilot policy")
	}
	v6 := source("sample-v6", "ipv6", "tcp", "hostname", "example.org", 443, 443, "allow")
	lease.RuleID = "sample-v6"
	for _, raw := range []string{"fec0::1", "64:ff9b::a00:1", "2002:a00:101::1"} {
		lease.Address = netip.MustParseAddr(raw)
		if _, err := Compile(pilotNetwork(taskboard, v6), 7, 100, 1000, []Lease{lease}); err == nil {
			t.Fatalf("transition or site-local DNS result %s entered the pilot policy", raw)
		}
	}
}

func TestPilotRejectsBroadAndPrivateAllowRules(t *testing.T) {
	taskboard := source("taskboard", "ipv4", "tcp", "ip", "10.77.0.2", 18080, 18080, "allow")
	for _, rule := range []policy.NetworkRule{
		source("direct-public", "ipv4", "tcp", "ip", "93.184.215.14", 443, 443, "allow"),
		source("public-prefix", "ipv4", "tcp", "prefix", "93.184.215.0/24", 443, 443, "allow"),
		source("lan", "ipv4", "tcp", "prefix", "192.168.0.0/16", 443, 443, "allow"),
		source("all", "ipv4", "tcp", "prefix", "0.0.0.0/0", 443, 443, "allow"),
		source("peer", "ipv4", "tcp", "ip", "10.77.0.44", 18080, 18080, "allow"),
		source("host", "ipv4", "tcp", "ip", "127.0.0.1", 443, 443, "allow"),
		source("ula", "ipv6", "tcp", "prefix", "fc00::/7", 443, 443, "allow"),
		source("bridge", "ipv4", "tcp", "ip", "172.17.0.1", 443, 443, "allow"),
	} {
		if _, err := Compile(pilotNetwork(taskboard, rule), 7, 100, 1000, nil); err == nil {
			t.Fatalf("pilot accepted %+v", rule)
		}
	}
	if _, err := Compile(pilotNetwork(), 7, 100, 1000, nil); err == nil {
		t.Fatal("pilot omitted its exact taskboard endpoint")
	}
	withoutScope := pilotNetwork(taskboard)
	withoutScope.Pilot.TaskboardTaskID = 0
	if _, err := Compile(withoutScope, 7, 100, 1000, nil); err == nil {
		t.Fatal("pilot omitted its signed taskboard task ID")
	}
}

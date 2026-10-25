// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"net/netip"
	"testing"

	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/policy"
)

func TestProbeDecisionsUseTheSignedEndpointAndLeasedPort(t *testing.T) {
	scope := policy.PilotNetwork{Mode: "ssh-coding.v1", TaskboardIP: "10.77.0.3", TaskboardPort: 65535, TaskboardTaskID: 42}
	public := netip.MustParseAddr("93.184.215.14")
	network := policy.Network{Default: "deny", Pilot: &scope,
		DNS: policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"},
		Rules: []policy.NetworkRule{
			{ID: "board", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "ip", Value: scope.TaskboardIP}, PortFrom: 65535, PortTo: 65535, Effect: "allow"},
			{ID: "web", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: "example.org"}, PortFrom: 8443, PortTo: 8443, Effect: "allow"},
		}}
	compiled, err := netrules.Compile(network, 1, 100, 1000, []netrules.Lease{{RuleID: "web", Hostname: "example.org", Address: public, Chain: []string{"example.org"}, ExpiresNS: 400}})
	if err != nil {
		t.Fatal(err)
	}
	decisions, err := pilotProbeDecisions(compiled.Policy, scope, public, 8443, 200)
	if err != nil || len(decisions) != 11 || !decisions["taskboard-exact"].Allowed || !decisions["leased-public-https"].Allowed {
		t.Fatal("the signed pilot map probes differ", decisions, err)
	}
	for name, decision := range decisions {
		if name != "taskboard-exact" && name != "leased-public-https" && decision.Allowed {
			t.Fatalf("%s escaped the private boundary", name)
		}
	}
	if _, err := pilotProbeDecisions(compiled.Policy, scope, public, 443, 200); err == nil {
		t.Fatal("a different public port gained proof")
	}
}

func TestGuardReceiptRequiresContiguousBoundedRawEvents(t *testing.T) {
	good := []event{{Sequence: 1, Generation: 1, Domain: 77, Cgroup: 77, MonoNS: 101, Version: 2}, {Sequence: 2, Generation: 1, Domain: 77, Cgroup: 77, MonoNS: 102, Version: 2}}
	count := counters{Decisions: 2}
	if !completeGuardEvents(good, count, 77, 100, 103) {
		t.Fatal("the complete raw stream was rejected")
	}
	for name, change := range map[string]func([]event, *counters){
		"missing-sequence": func(events []event, _ *counters) { events[1].Sequence++ },
		"foreign-domain":   func(events []event, _ *counters) { events[1].Cgroup++ },
		"wrong-generation": func(events []event, _ *counters) { events[1].Generation++ },
		"old-event":        func(events []event, _ *counters) { events[0].MonoNS = 99 },
		"future-event":     func(events []event, _ *counters) { events[1].MonoNS = 104 },
		"lost-event":       func(_ []event, counts *counters) { counts.Lost++ },
		"counter-mismatch": func(_ []event, counts *counters) { counts.Decisions-- },
	} {
		copyEvents := append([]event(nil), good...)
		copyCount := count
		change(copyEvents, &copyCount)
		if completeGuardEvents(copyEvents, copyCount, 77, 100, 103) {
			t.Fatalf("%s passed", name)
		}
	}
}

func TestPilotBoundaryRequiresLiveAllowDenyAndExpiry(t *testing.T) {
	const domain = 77
	makeEvent := func(sequence, when uint64, raw string, port uint32, allowed uint32) event {
		address := netip.MustParseAddr(raw)
		observed := event{Sequence: sequence, Generation: 1, Domain: domain, Cgroup: domain, MonoNS: when,
			PID: 1001, UID: 65534, Allowed: allowed, Protocol: uint32(netrules.TCP), Port: port, Version: 2}
		if address.Is4() {
			observed.Family, observed.Hook = uint32(netrules.IPv4), 1
			copy(observed.Address[:4], address.AsSlice())
		} else {
			observed.Family, observed.Hook = uint32(netrules.IPv6), 2
			observed.Address = address.As16()
		}
		return observed
	}
	board := policy.PilotNetwork{TaskboardIP: "10.77.0.2", TaskboardPort: 18080}
	public := netip.MustParseAddr("93.184.215.14")
	r := receipt{Domain: domain, StartedMonoNS: 100, DeadlineMonoNS: 200, FinishedMonoNS: 300,
		Events: []event{
			makeEvent(1, 110, "10.77.0.3", 18080, 0),
			makeEvent(2, 120, "fc00::4", 18080, 0),
			makeEvent(3, 130, "10.77.0.2", 18081, 0),
			makeEvent(4, 140, "10.77.0.2", 18080, 1),
			makeEvent(5, 150, "93.184.215.14", 443, 1),
			makeEvent(6, 210, "10.77.0.2", 18080, 0),
			makeEvent(7, 220, "93.184.215.14", 443, 0),
		}, Counters: counters{Decisions: 7}}
	if !completePilotBoundary(r, board, public, 443) {
		t.Fatal("the complete pilot raw boundary was rejected")
	}
	withDeniedUDP := r
	withDeniedUDP.Events = append([]event(nil), r.Events...)
	udp := makeEvent(1, 105, "93.184.215.14", 443, 0)
	udp.Protocol = uint32(netrules.UDP)
	withDeniedUDP.Events = append([]event{udp}, withDeniedUDP.Events...)
	for i := range withDeniedUDP.Events {
		withDeniedUDP.Events[i].Sequence = uint64(i + 1)
	}
	withDeniedUDP.Counters.Decisions++
	if !completePilotBoundary(withDeniedUDP, board, public, 443) {
		t.Fatal("a denied UDP source-address probe invalidated the TCP boundary")
	}
	withDeniedUDP.Events[0].Allowed = 1
	if completePilotBoundary(withDeniedUDP, board, public, 443) {
		t.Fatal("an allowed UDP event passed the pilot boundary")
	}
	unrelatedAllow := r
	unrelatedAllow.Events = append([]event(nil), r.Events[:5]...)
	unrelatedAllow.Events = append(unrelatedAllow.Events, makeEvent(6, 160, "203.0.113.40", 443, 1))
	unrelatedAllow.Events = append(unrelatedAllow.Events, r.Events[5:]...)
	for i := range unrelatedAllow.Events {
		unrelatedAllow.Events[i].Sequence = uint64(i + 1)
	}
	unrelatedAllow.Counters.Decisions++
	if completePilotBoundary(unrelatedAllow, board, public, 443) {
		t.Fatal("an unrelated allowed TCP peer passed the pilot boundary")
	}
	for name, change := range map[string]func(*receipt){
		"private-ipv4-allowed": func(v *receipt) { v.Events[0].Allowed = 1 },
		"private-ipv6-allowed": func(v *receipt) { v.Events[1].Allowed = 1 },
		"wrong-port-allowed":   func(v *receipt) { v.Events[2].Allowed = 1 },
		"public-after-cutoff":  func(v *receipt) { v.Events[6].Allowed = 1 },
		"foreign-uid":          func(v *receipt) { v.Events[4].UID = 0 },
		"lost-event":           func(v *receipt) { v.Counters.Lost = 1 },
	} {
		changed := r
		changed.Events = append([]event(nil), r.Events...)
		change(&changed)
		if completePilotBoundary(changed, board, public, 443) {
			t.Fatalf("%s passed", name)
		}
	}
}

func TestDiagnosticDomainRequiresRootLevelOwnedName(t *testing.T) {
	if !ownedDiagnosticDomain("/sys/fs/cgroup/ag-mvp-owned-domain") {
		t.Fatal("an owned domain was rejected")
	}
	for _, path := range []string{"/sys/fs/cgroup/other-domain", "/sys/fs/cgroup/ag-mvp-", "/sys/fs/cgroup/other/ag-mvp-owned", "/sys/fs/cgroup/ag-mvp-owned/../foreign"} {
		if ownedDiagnosticDomain(path) {
			t.Fatalf("foreign domain %s passed", path)
		}
	}
}

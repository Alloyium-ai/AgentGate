// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"

	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/policy"
)

// This ownership check belongs only to the fixed diagnostic. It cannot
// authorize a normal workload or substitute for the node's domain custody.
func ownedDiagnosticDomain(path string) bool {
	base := filepath.Base(path)
	return filepath.IsAbs(path) && filepath.Clean(path) == path &&
		filepath.Dir(path) == "/sys/fs/cgroup" && strings.HasPrefix(base, "ag-mvp-") && len(base) > len("ag-mvp-")
}

func otherPrivateAddress(pilot netip.Addr) netip.Addr {
	first, second := netip.MustParseAddr("10.77.0.3"), netip.MustParseAddr("10.77.0.4")
	if pilot.Is6() {
		first, second = netip.MustParseAddr("fc00::3"), netip.MustParseAddr("fc00::4")
	}
	if pilot == first {
		return second
	}
	return first
}

func pilotProbeDecisions(plan netrules.Policy, scope policy.PilotNetwork, public netip.Addr, publicPort uint16, now uint64) (map[string]netrules.Decision, error) {
	taskboard, err := netip.ParseAddr(scope.TaskboardIP)
	if err != nil || taskboard.String() != scope.TaskboardIP || scope.TaskboardPort < 1 || scope.TaskboardPort > 65535 || publicPort == 0 || now == 0 {
		return nil, errors.New("the diagnostic endpoint scope differs")
	}
	wrongPort := uint16(scope.TaskboardPort + 1)
	if scope.TaskboardPort == 65535 {
		wrongPort = uint16(scope.TaskboardPort - 1)
	}
	otherPublic := netip.MustParseAddr("203.0.113.10")
	if public == otherPublic {
		otherPublic = netip.MustParseAddr("203.0.113.11")
	}
	probes := map[string]netrules.Endpoint{
		"leased-public-https":  {Address: public, Protocol: netrules.TCP, Port: publicPort},
		"other-public-direct":  {Address: otherPublic, Protocol: netrules.TCP, Port: publicPort},
		"taskboard-exact":      {Address: taskboard, Protocol: netrules.TCP, Port: uint16(scope.TaskboardPort)},
		"taskboard-wrong-port": {Address: taskboard, Protocol: netrules.TCP, Port: wrongPort},
		"docker-bridge":        {Address: netip.MustParseAddr("172.18.0.1"), Protocol: netrules.TCP, Port: wrongPort},
		"private-peer":         {Address: otherPrivateAddress(taskboard), Protocol: netrules.TCP, Port: uint16(scope.TaskboardPort)},
		"ipv4-loopback":        {Address: netip.MustParseAddr("127.0.0.1"), Protocol: netrules.TCP, Port: wrongPort},
		"ipv4-link-local":      {Address: netip.MustParseAddr("169.254.1.1"), Protocol: netrules.TCP, Port: wrongPort},
		"ipv6-ula":             {Address: netip.MustParseAddr("fd00::1"), Protocol: netrules.TCP, Port: wrongPort},
		"ipv6-link-local":      {Address: netip.MustParseAddr("fe80::1"), Protocol: netrules.TCP, Port: wrongPort},
		"ipv6-mapped-private":  {Address: netip.MustParseAddr("::ffff:192.168.1.1"), Protocol: netrules.TCP, Port: wrongPort},
	}
	out := make(map[string]netrules.Decision, len(probes))
	for name, endpoint := range probes {
		decision := netrules.Evaluate(plan, endpoint, now)
		if decision.Allowed != (name == "leased-public-https" || name == "taskboard-exact") {
			return nil, fmt.Errorf("pilot map decision differs: %s", name)
		}
		out[name] = decision
	}
	return out, nil
}

func completeGuardEvents(events []event, counts counters, domain, started, finished uint64) bool {
	if domain == 0 || started == 0 || finished <= started || len(events) == 0 || len(events) > 10000 ||
		counts.Lost != 0 || counts.Decisions != uint64(len(events)) {
		return false
	}
	var previous uint64
	for i, observed := range events {
		if observed.Sequence != uint64(i+1) || observed.Generation != 1 ||
			observed.Domain != domain || observed.Cgroup != domain || observed.Version != 2 ||
			observed.MonoNS < started || observed.MonoNS > finished || observed.MonoNS < previous {
			return false
		}
		previous = observed.MonoNS
	}
	return true
}

// The raw stream must contain the live decisions made by the owned actor.
// Map evaluations alone cannot prove that the BPF hook ran on that actor.
func completePilotBoundary(r receipt, scope policy.PilotNetwork, public netip.Addr, publicPort uint16) bool {
	if !completeGuardEvents(r.Events, r.Counters, r.Domain, r.StartedMonoNS, r.FinishedMonoNS) ||
		r.DeadlineMonoNS <= r.StartedMonoNS || r.DeadlineMonoNS >= r.FinishedMonoNS {
		return false
	}
	taskboard, err := netip.ParseAddr(scope.TaskboardIP)
	if err != nil || publicPort == 0 || scope.TaskboardPort < 1 || scope.TaskboardPort > 65535 {
		return false
	}
	var boardAllow, boardWrongPort, publicAllow, privateV4Deny, privateV6Deny, boardExpired, publicExpired bool
	for _, observed := range r.Events {
		if observed.Hook != 1 && observed.Hook != 2 {
			continue
		}
		if observed.PID == 0 || observed.UID != 65534 {
			return false
		}
		address := netip.AddrFrom16(observed.Address)
		if observed.Family == uint32(netrules.IPv4) {
			var v4 [4]byte
			copy(v4[:], observed.Address[:4])
			address = netip.AddrFrom4(v4)
		} else if observed.Family != uint32(netrules.IPv6) {
			return false
		}
		// libc can connect a UDP socket while it selects a source address for
		// getaddrinfo. Count that raw decision, but never let it satisfy a TCP
		// allow, deny, or expiry requirement. The pilot policy denies UDP.
		if observed.Protocol == uint32(netrules.UDP) {
			if observed.Allowed != 0 {
				return false
			}
			continue
		}
		if observed.Protocol != uint32(netrules.TCP) || observed.Allowed > 1 {
			return false
		}
		before := observed.MonoNS < r.DeadlineMonoNS
		if observed.Allowed == 1 && (!before ||
			!(address == taskboard && observed.Port == uint32(scope.TaskboardPort) ||
				address == public && observed.Port == uint32(publicPort))) {
			return false
		}
		if address == taskboard && observed.Port == uint32(scope.TaskboardPort) {
			boardAllow = boardAllow || before && observed.Allowed == 1
			boardExpired = boardExpired || !before && observed.Allowed == 0
		} else if address == taskboard && observed.Port != uint32(scope.TaskboardPort) {
			boardWrongPort = boardWrongPort || before && observed.Allowed == 0
		} else if address == public && observed.Port == uint32(publicPort) {
			publicAllow = publicAllow || before && observed.Allowed == 1
			publicExpired = publicExpired || !before && observed.Allowed == 0
		} else if before && observed.Allowed == 0 && (address.IsPrivate() || address.IsLinkLocalUnicast()) {
			privateV4Deny = privateV4Deny || address.Is4()
			privateV6Deny = privateV6Deny || address.Is6()
		}
	}
	return boardAllow && boardWrongPort && publicAllow && privateV4Deny && privateV6Deny && boardExpired && publicExpired
}

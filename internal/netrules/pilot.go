// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package netrules

import (
	"errors"
	"net/netip"

	"alloyium.local/kernel-poc/internal/policy"
)

var pilotExcluded = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/32"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("fec0::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func pilotPrivate(address netip.Addr) bool {
	if !supportedAddress(address) {
		return true
	}
	for _, excluded := range pilotExcluded {
		if excluded.Contains(address) {
			return true
		}
	}
	return false
}

func configurePilot(out *Policy, config policy.PilotNetwork) error {
	address, err := netip.ParseAddr(config.TaskboardIP)
	if config.Mode != "ssh-coding.v1" || err != nil || address.String() != config.TaskboardIP ||
		!address.IsPrivate() || !supportedAddress(address) || config.TaskboardPort < 1 || config.TaskboardPort > 65535 ||
		config.TaskboardTaskID < 1 {
		return errors.New("pilot requires a canonical private taskboard endpoint")
	}
	out.PilotAddress = addressBytes(address)
	out.PilotPort = uint16(config.TaskboardPort)
	out.PilotFamily = IPv6
	if address.Is4() {
		out.PilotFamily = IPv4
	}
	out.PilotMode = 1
	return nil
}

func pilotTaskboardRule(rule policy.NetworkRule, compiled Policy) bool {
	if rule.Protocol != "tcp" || rule.Destination.Kind != "ip" || rule.PortFrom != int(compiled.PilotPort) || rule.PortTo != int(compiled.PilotPort) {
		return false
	}
	address, err := netip.ParseAddr(rule.Destination.Value)
	return err == nil && addressBytes(address) == compiled.PilotAddress &&
		((address.Is4() && compiled.PilotFamily == IPv4 && rule.Family == "ipv4") ||
			(address.Is6() && compiled.PilotFamily == IPv6 && rule.Family == "ipv6"))
}

func pilotPublicRule(rule policy.NetworkRule) bool {
	// Every external allowance must come from the trusted resolver and its
	// bounded lease. A literal public IP would bypass the named destination.
	return false
}

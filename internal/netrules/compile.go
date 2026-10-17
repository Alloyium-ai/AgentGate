// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package netrules

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"alloyium.local/kernel-poc/internal/policy"
)

// Compile validates the endpoint subset independently of the schema inspector.
// A hostname rule requires a live trusted lease. Failed refresh must install deny.
func Compile(network policy.Network, generation, nowNS, expiresNS uint64, leases []Lease) (Compiled, error) {
	var out Compiled
	if err := policy.ValidateNetworkSection(network); err != nil {
		return out, err
	}
	if network.Default != "deny" || generation == 0 || nowNS >= expiresNS {
		return out, fmt.Errorf("network requires deny default, generation, and future deadline")
	}
	if network.DNS != (policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"}) {
		return out, fmt.Errorf("unsupported DNS contract")
	}
	if len(network.Rules) > MaxRules {
		return out, fmt.Errorf("network source rule limit is %d", MaxRules)
	}
	rules := append([]policy.NetworkRule(nil), network.Rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	out.Policy = Policy{Generation: generation, ExpiresNS: expiresNS}
	usedLeases := make([]bool, len(leases))
	for _, source := range rules {
		if !ruleID(source.ID) || (len(out.RuleIDs) > 0 && source.ID == out.RuleIDs[len(out.RuleIDs)-1]) {
			return Compiled{}, fmt.Errorf("network rule IDs must be canonical and unique")
		}
		rule, err := compileRule(source, expiresNS)
		if err != nil {
			return Compiled{}, fmt.Errorf("network rule %s: %w", source.ID, err)
		}
		out.RuleIDs = append(out.RuleIDs, source.ID)
		rule.Index = uint32(len(out.RuleIDs))
		if source.Destination.Kind != "hostname" {
			if err := out.append(rule); err != nil {
				return Compiled{}, err
			}
			continue
		}
		count := 0
		for i, lease := range leases {
			if lease.RuleID != source.ID {
				continue
			}
			usedLeases[i] = true
			resolved, err := resolveRule(source, rule, lease, nowNS, expiresNS)
			if err != nil {
				return Compiled{}, fmt.Errorf("network lease %s: %w", source.ID, err)
			}
			if err := out.append(resolved); err != nil {
				return Compiled{}, err
			}
			count++
		}
		if count == 0 {
			return Compiled{}, fmt.Errorf("hostname rule %s requires a live trusted lease", source.ID)
		}
	}
	for i, used := range usedLeases {
		if !used {
			return Compiled{}, fmt.Errorf("lease %d does not match a hostname rule", i)
		}
	}
	sort.Slice(out.Policy.Rules[:out.Policy.Count], func(i, j int) bool {
		a, b := out.Policy.Rules[i], out.Policy.Rules[j]
		if a.Index != b.Index {
			return a.Index < b.Index
		}
		if a.Address != b.Address {
			return string(a.Address[:]) < string(b.Address[:])
		}
		return a.ExpiresNS < b.ExpiresNS
	})
	return out, nil
}

func (c *Compiled) append(rule Rule) error {
	if c.Policy.Count == MaxRules {
		return fmt.Errorf("expanded network rule limit is %d", MaxRules)
	}
	for _, previous := range c.Policy.Rules[:c.Policy.Count] {
		if previous == rule {
			return nil
		}
	}
	c.Policy.Rules[c.Policy.Count] = rule
	c.Policy.Count++
	return nil
}

func compileRule(source policy.NetworkRule, deadline uint64) (Rule, error) {
	rule := Rule{ExpiresNS: deadline}
	switch source.Family {
	case "ipv4":
		rule.Family = IPv4
	case "ipv6":
		rule.Family = IPv6
	default:
		return rule, fmt.Errorf("unsupported address family %q", source.Family)
	}
	switch source.Protocol {
	case "tcp":
		rule.Protocol = TCP
	case "udp":
		rule.Protocol = UDP
	default:
		return rule, fmt.Errorf("unsupported transport %q", source.Protocol)
	}
	if source.PortFrom < 1 || source.PortTo > 65535 || source.PortFrom > source.PortTo {
		return rule, fmt.Errorf("invalid destination port range")
	}
	rule.PortFrom, rule.PortTo = uint16(source.PortFrom), uint16(source.PortTo)
	switch source.Effect {
	case "deny":
		rule.Effect = Deny
	case "allow":
		rule.Effect = Allow
	default:
		return rule, fmt.Errorf("unsupported effect %q", source.Effect)
	}
	destination := source.Destination
	if destination.Kind == "hostname" {
		if !hostname(destination.Value) {
			return rule, fmt.Errorf("hostname must use canonical lower-case DNS labels")
		}
		return rule, nil
	}
	var prefix netip.Prefix
	switch destination.Kind {
	case "ip":
		address, err := netip.ParseAddr(destination.Value)
		if err != nil || address.String() != destination.Value || !supportedAddress(address) {
			return rule, fmt.Errorf("unsupported literal destination")
		}
		prefix = netip.PrefixFrom(address, address.BitLen())
	case "prefix":
		parsed, err := netip.ParsePrefix(destination.Value)
		if err != nil || parsed.Masked().String() != destination.Value || parsed.Addr().Zone() != "" || parsed.Addr().Is4In6() {
			return rule, fmt.Errorf("prefix must use canonical masked CIDR notation")
		}
		prefix = parsed
	default:
		return rule, fmt.Errorf("unsupported destination kind %q", destination.Kind)
	}
	if prefix.Addr().Is4() != (rule.Family == IPv4) {
		return rule, fmt.Errorf("destination and address family differ")
	}
	if prefix.Addr().IsMulticast() || prefix.Addr() == netip.MustParseAddr("255.255.255.255") {
		return rule, fmt.Errorf("multicast and limited-broadcast prefixes are unsupported")
	}
	rule.Address = addressBytes(prefix.Addr())
	rule.PrefixBits = uint16(prefix.Bits())
	return rule, nil
}

func resolveRule(source policy.NetworkRule, rule Rule, lease Lease, now, deadline uint64) (Rule, error) {
	if lease.Hostname != source.Destination.Value || !supportedAddress(lease.Address) || lease.Address.Is4() != (rule.Family == IPv4) {
		return rule, fmt.Errorf("lease name or address differs from the rule")
	}
	if lease.ExpiresNS <= now || lease.ExpiresNS > deadline {
		return rule, fmt.Errorf("lease requires a live deadline within the grant")
	}
	if len(lease.Chain) < 1 || len(lease.Chain) > 9 || lease.Chain[0] != lease.Hostname {
		return rule, fmt.Errorf("lease requires a bounded complete CNAME chain")
	}
	seen := map[string]bool{}
	for _, name := range lease.Chain {
		if !hostname(name) || seen[name] {
			return rule, fmt.Errorf("invalid or cyclic CNAME chain")
		}
		seen[name] = true
	}
	rule.Address = addressBytes(lease.Address)
	rule.PrefixBits = uint16(lease.Address.BitLen())
	rule.ExpiresNS = lease.ExpiresNS
	return rule, nil
}

func hostname(value string) bool {
	if len(value) == 0 || len(value) > 253 || value != strings.ToLower(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	_, err := netip.ParseAddr(value)
	return err != nil
}

func ruleID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i, ch := range value {
		letterOrDigit := (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9')
		if !letterOrDigit && (i == 0 || (ch != '_' && ch != '.' && ch != '-')) {
			return false
		}
	}
	return true
}

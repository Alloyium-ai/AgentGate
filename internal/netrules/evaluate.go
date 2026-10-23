// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package netrules

import "net/netip"

// Evaluate mirrors the BPF decision. The most specific prefix wins, followed by
// the narrowest port range. Deny wins a tie. Expired DNS denies remain effective
// until replacement, so expiry cannot expose a less specific allowance.
func Evaluate(p Policy, endpoint Endpoint, nowNS uint64) Decision {
	result := Decision{Reason: "unmatched"}
	if p.Generation == 0 || p.Count > MaxRules || nowNS >= p.ExpiresNS {
		result.Reason = "missing-invalid-or-expired-policy"
		return result
	}
	if !supportedAddress(endpoint.Address) || endpoint.Port == 0 || (endpoint.Protocol != TCP && endpoint.Protocol != UDP) {
		result.Reason = "unsupported-endpoint"
		return result
	}
	if p.PilotMode > 1 || (p.PilotMode == 1 && pilotPrivate(endpoint.Address) &&
		!(addressBytes(endpoint.Address) == p.PilotAddress && endpoint.Port == p.PilotPort && endpoint.Protocol == TCP &&
			((endpoint.Address.Is4() && p.PilotFamily == IPv4) || (endpoint.Address.Is6() && p.PilotFamily == IPv6)))) {
		result.Reason = "pilot-lan-boundary"
		return result
	}
	family := uint8(IPv6)
	if endpoint.Address.Is4() {
		family = IPv4
	}
	address := addressBytes(endpoint.Address)
	bestBits, bestWidth := -1, 65536
	for _, rule := range p.Rules[:p.Count] {
		if !validRule(rule) {
			return Decision{Reason: "invalid-rule"}
		}
		if rule.Family != family || rule.Protocol != endpoint.Protocol || endpoint.Port < rule.PortFrom || endpoint.Port > rule.PortTo {
			continue
		}
		if !prefixMatch(address, rule.Address, int(rule.PrefixBits)) {
			continue
		}
		if rule.Effect == Allow && nowNS >= rule.ExpiresNS {
			continue
		}
		width := int(rule.PortTo - rule.PortFrom)
		bits := int(rule.PrefixBits)
		if bits < bestBits || (bits == bestBits && width > bestWidth) {
			continue
		}
		if bits == bestBits && width == bestWidth && !result.Allowed {
			continue
		}
		if bits == bestBits && width == bestWidth && rule.Effect == Allow && result.RuleIndex < rule.Index {
			continue
		}
		bestBits, bestWidth = bits, width
		result = Decision{Allowed: rule.Effect == Allow, RuleIndex: rule.Index, Reason: "rule"}
	}
	return result
}

func validRule(rule Rule) bool {
	bits := uint16(128)
	if rule.Family == IPv4 {
		bits = 32
	} else if rule.Family != IPv6 {
		return false
	}
	return rule.PrefixBits <= bits && (rule.Protocol == TCP || rule.Protocol == UDP) && rule.PortFrom > 0 && rule.PortFrom <= rule.PortTo && rule.Effect <= Allow && rule.Index > 0 && rule.ExpiresNS > 0
}

func prefixMatch(address, prefix [16]byte, bits int) bool {
	for i := 0; i < bits/8; i++ {
		if address[i] != prefix[i] {
			return false
		}
	}
	if bits%8 != 0 {
		mask := byte(0xff << (8 - bits%8))
		return address[bits/8]&mask == prefix[bits/8]&mask
	}
	return true
}

func supportedAddress(address netip.Addr) bool {
	return address.IsValid() && address.Zone() == "" && !address.Is4In6() && !address.IsUnspecified() && !address.IsMulticast() && address != netip.MustParseAddr("255.255.255.255")
}

func addressBytes(address netip.Addr) [16]byte {
	if !address.Is4() {
		return address.As16()
	}
	var out [16]byte
	v4 := address.As4()
	copy(out[:4], v4[:])
	return out
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package netrules

import (
	"fmt"
	"net/netip"
	"sort"

	"alloyium.local/kernel-poc/internal/policy"
)

// CompileSockets accepts only target-enforceable explicit operation allowances.
// The plan grants neither a peer endpoint nor ownership of a socket descriptor.
func CompileSockets(source policy.SocketPolicy, generation, now, deadline uint64) (CompiledSockets, error) {
	var out CompiledSockets
	if err := policy.ValidateSocketSection(source); err != nil {
		return out, err
	}
	if generation == 0 || now >= deadline {
		return out, fmt.Errorf("socket policy requires a generation and future deadline")
	}
	if len(source.Rules) > MaxRules {
		return out, fmt.Errorf("socket rule limit is %d", MaxRules)
	}
	rules := append([]policy.SocketRule(nil), source.Rules...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	out.Plan = SocketPlan{Generation: generation, ExpiresNS: deadline}
	for _, sourceRule := range rules {
		rule, err := compileSocketRule(sourceRule)
		if err != nil {
			return CompiledSockets{}, fmt.Errorf("socket rule %s: %w", sourceRule.ID, err)
		}
		out.RuleIDs = append(out.RuleIDs, sourceRule.ID)
		rule.Index = uint32(len(out.RuleIDs))
		out.Plan.Rules[out.Plan.Count] = rule
		out.Plan.Count++
	}
	return out, nil
}

func compileSocketRule(source policy.SocketRule) (SocketRulePlan, error) {
	var out SocketRulePlan
	out.Family = map[string]uint16{"ipv4": 2, "ipv6": 10, "unix": 1, "netlink": 16, "packet": 17}[source.Family]
	out.Protocol = map[string]uint16{"tcp": TCP, "udp": UDP, "stream": 1, "dgram": 2, "raw": 255}[source.Protocol]
	if source.Effect == "allow" {
		out.Effect = Allow
	}
	if out.Effect == Allow && ((out.Family != 2 && out.Family != 10) || (out.Protocol != TCP && out.Protocol != UDP)) {
		return out, fmt.Errorf("unsupported socket family or protocol allowance")
	}
	for _, operation := range source.Operations {
		bit := socketOperationBits[operation]
		if bit == 0 {
			return out, fmt.Errorf("unsupported socket operation %q", operation)
		}
		out.Operations |= bit
	}
	if out.Effect == Allow && out.Protocol != TCP && out.Operations&(SocketListen|SocketAccept) != 0 {
		return out, fmt.Errorf("listen and accept allowances require TCP")
	}
	if source.Local != nil {
		address, err := netip.ParseAddr(source.Local.Address)
		if err != nil || address.String() != source.Local.Address || address.Is4In6() || address.Zone() != "" || address.IsMulticast() || address == netip.MustParseAddr("255.255.255.255") || address.Is4() != (out.Family == 2) || (out.Effect == Allow && address.IsLinkLocalUnicast()) {
			return out, fmt.Errorf("unsupported local address")
		}
		if source.Local.PortFrom < 0 || source.Local.PortTo > 65535 || source.Local.PortFrom > source.Local.PortTo {
			return out, fmt.Errorf("invalid local port range")
		}
		out.Address = addressBytes(address)
		out.PortFrom = uint16(source.Local.PortFrom)
		out.PortTo = uint16(source.Local.PortTo)
		out.HasLocal = 1
		if out.Effect == Allow && out.Operations&SocketCreate != 0 {
			return out, fmt.Errorf("a create allowance cannot use a local selector")
		}
	}
	if out.Effect == Allow && out.HasLocal == 0 && out.Operations&(SocketBind|SocketListen|SocketAccept) != 0 {
		return out, fmt.Errorf("bind, listen, and accept allowances require a local selector")
	}
	if len(source.Options) > MaxSocketOptions {
		return out, fmt.Errorf("socket option limit is %d", MaxSocketOptions)
	}
	if len(source.Options) > 0 && out.Operations&(SocketSetOption|SocketGetOption) == 0 {
		return out, fmt.Errorf("option pairs require an option operation")
	}
	for _, option := range source.Options {
		pair := SocketOptionPlan{Level: uint16(option.Level), Name: uint16(option.Name)}
		if out.Effect == Allow && !supportedSocketOption(out.Family, out.Protocol, out.Operations, pair) {
			return out, fmt.Errorf("unsupported socket option allowance %d/%d", option.Level, option.Name)
		}
		out.Options[out.OptionCount] = pair
		out.OptionCount++
	}
	if out.Effect == Allow && out.Operations&(SocketSetOption|SocketGetOption) != 0 && out.OptionCount == 0 {
		return out, fmt.Errorf("an option allowance requires explicit level/name pairs")
	}
	sort.Slice(out.Options[:out.OptionCount], func(i, j int) bool {
		a, b := out.Options[i], out.Options[j]
		if a.Level != b.Level {
			return a.Level < b.Level
		}
		return a.Name < b.Name
	})
	return out, nil
}

func supportedSocketOption(family, protocol uint16, operations uint32, option SocketOptionPlan) bool {
	if option.Level == 1 {
		switch option.Name {
		case 2, 7, 8, 9, 13:
			return true // Reuse address, buffers, keepalive, and linger.
		case 3, 4:
			return operations&SocketSetOption == 0 // Socket type and pending error are getters only.
		}
	}
	if option.Level == 6 && option.Name == 1 {
		return protocol == TCP
	}
	return option.Level == 41 && option.Name == 26 && family == 10
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"errors"
	"fmt"
	"net/netip"
)

type SocketPolicy struct {
	Default string       `json:"default"`
	Rules   []SocketRule `json:"rules"`
}
type SocketRule struct {
	ID         string         `json:"id"`
	Family     string         `json:"family"`
	Protocol   string         `json:"protocol"`
	Operations []string       `json:"operations"`
	Effect     string         `json:"effect"`
	Local      *SocketLocal   `json:"local,omitempty"`
	Options    []SocketOption `json:"options,omitempty"`
}
type SocketLocal struct {
	Address  string `json:"address"`
	PortFrom int    `json:"port_from"`
	PortTo   int    `json:"port_to"`
}
type SocketOption struct {
	Level int `json:"level"`
	Name  int `json:"name"`
}

func validateSockets(sockets SocketPolicy, ids map[string]bool) error {
	for _, rule := range sockets.Rules {
		if err := uniqueRule(rule.ID, ids); err != nil {
			return err
		}
		if (rule.Family == "ipv4" || rule.Family == "ipv6") && rule.Protocol != "tcp" && rule.Protocol != "udp" && rule.Protocol != "raw" {
			return fmt.Errorf("socket rule %s: address family and protocol differ", rule.ID)
		}
		if rule.Family == "unix" && rule.Protocol != "stream" && rule.Protocol != "dgram" {
			return fmt.Errorf("socket rule %s: UNIX protocol must be stream or dgram", rule.ID)
		}
		if rule.Local != nil {
			address, err := netip.ParseAddr(rule.Local.Address)
			if err != nil || address.String() != rule.Local.Address || address.Zone() != "" || address.Is4In6() || address.IsMulticast() || address == netip.MustParseAddr("255.255.255.255") || address.Is4() != (rule.Family == "ipv4") || rule.Family != "ipv4" && rule.Family != "ipv6" || rule.Local.PortFrom > rule.Local.PortTo {
				return fmt.Errorf("socket rule %s: invalid canonical local selector", rule.ID)
			}
		}
		seen := map[SocketOption]bool{}
		for _, option := range rule.Options {
			if seen[option] {
				return errors.New("socket option pairs must be unique")
			}
			seen[option] = true
		}
		if rule.Effect != "allow" {
			continue
		}
		for _, operation := range rule.Operations {
			if (operation == "bind" || operation == "listen" || operation == "accept") && rule.Local == nil {
				return fmt.Errorf("socket rule %s: %s requires an explicit local selector", rule.ID, operation)
			}
			if (operation == "get_option" || operation == "set_option") && len(rule.Options) == 0 {
				return fmt.Errorf("socket rule %s: %s requires explicit option pairs", rule.ID, operation)
			}
		}
	}
	return nil
}

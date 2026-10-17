// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package netrules compiles outbound endpoint rules. It does not admit a job.
package netrules

import "net/netip"

const (
	MaxRules = 128
	IPv4     = 4
	IPv6     = 6
	TCP      = 6
	UDP      = 17
	Deny     = 0
	Allow    = 1
)

// Rule is the 40-byte network_policy.bpf.c map ABI. Addresses use network order.
// Port numbers and all other scalar fields use native host byte order.
type Rule struct {
	Address    [16]byte
	ExpiresNS  uint64
	PrefixBits uint16
	Family     uint8
	Protocol   uint8
	PortFrom   uint16
	PortTo     uint16
	Effect     uint8
	Reserved   [3]byte
	Index      uint32
}

// Policy is one atomic map value. A zero value denies every endpoint.
// The trusted manager binds the map key to one prepared root-level job cgroup.
type Policy struct {
	Generation uint64
	ExpiresNS  uint64
	Count      uint32
	Reserved   uint32 // Kernel DNS lease revision; zero for ordinary literal plans.
	Rules      [MaxRules]Rule
}

// Lease comes only from a trusted resolver, never from an agent policy document.
// Chain contains the question name, each CNAME target, and the final owner name.
// ExpiresNS is the minimum remaining TTL deadline across that complete chain.
type Lease struct {
	RuleID    string
	Hostname  string
	Address   netip.Addr
	Chain     []string
	ExpiresNS uint64
}

type Decision struct {
	Allowed   bool
	RuleIndex uint32
	Reason    string
}

// Compiled retains the source rule IDs for event attribution.
type Compiled struct {
	Policy  Policy
	RuleIDs []string
}

// Endpoint is an outbound remote address and destination port.
type Endpoint struct {
	Address  netip.Addr
	Protocol uint8
	Port     uint16
}

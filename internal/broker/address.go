// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import "net/netip"

// Non-public IPv4 ranges (IANA special-purpose registry plus multicast and
// reserved space). Every resolved upstream address is checked against these.
var deniedIPv4 = mustPrefixes(
	"0.0.0.0/8",       // this network
	"10.0.0.0/8",      // RFC 1918
	"100.64.0.0/10",   // CGNAT, RFC 6598
	"127.0.0.0/8",     // loopback
	"169.254.0.0/16",  // link-local, includes cloud metadata 169.254.169.254
	"172.16.0.0/12",   // RFC 1918
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.31.196.0/24", // AS112-v4
	"192.52.193.0/24", // AMT
	"192.88.99.0/24",  // deprecated 6to4 relay anycast
	"192.168.0.0/16",  // RFC 1918
	"192.175.48.0/24", // direct delegation AS112
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // multicast
	"240.0.0.0/4",     // reserved, includes limited broadcast
)

// Non-public IPv6 ranges inside 2000::/3. Anything outside 2000::/3 is
// rejected outright, except the well-known NAT64 prefix handled below.
var deniedIPv6 = mustPrefixes(
	"2001::/23",     // IETF protocol assignments: Teredo, benchmarking, ORCHID, AMT, AS112
	"2001:db8::/32", // documentation
	"2002::/16",     // 6to4 embeds an IPv4 address; refused in every form
	"3fff::/20",     // documentation, RFC 9637
	"2620:4f:8000::/48",
)

var (
	globalUnicast6 = netip.MustParsePrefix("2000::/3")
	nat64WellKnown = netip.MustParsePrefix("64:ff9b::/96")
)

func mustPrefixes(list ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(list))
	for i, s := range list {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

// AddressClass names why an address is not a public upstream, or "public".
type AddressClass string

const (
	ClassPublic      AddressClass = "public"
	ClassInvalid     AddressClass = "invalid"
	ClassZoned       AddressClass = "zoned"
	ClassUnspecified AddressClass = "unspecified"
	ClassLoopback    AddressClass = "loopback"
	ClassPrivate     AddressClass = "private"
	ClassLinkLocal   AddressClass = "link-local"
	ClassMulticast   AddressClass = "multicast"
	ClassReserved    AddressClass = "reserved"
	ClassEmbedded    AddressClass = "embedded-ipv4"
	ClassLocal       AddressClass = "local-network"
	ClassUnlisted    AddressClass = "not-a-listed-private-address"
)

// ClassifyAddress decides whether a is a public unicast destination. IPv4
// addresses mapped into IPv6 are judged as the IPv4 address they carry; the
// caller dials the unmapped form. Every other IPv6 transition form (6to4,
// Teredo, IPv4-compatible, local NAT64) is refused. The well-known NAT64
// prefix is allowed only when the embedded IPv4 address is itself public.
func ClassifyAddress(a netip.Addr) AddressClass {
	if !a.IsValid() {
		return ClassInvalid
	}
	if a.Zone() != "" {
		return ClassZoned
	}
	if a.Is4In6() {
		a = a.Unmap()
	}
	if a.Is4() {
		return classify4(a)
	}
	switch {
	case a.IsUnspecified():
		return ClassUnspecified
	case a.IsLoopback():
		return ClassLoopback
	case a.IsMulticast():
		return ClassMulticast
	case a.IsLinkLocalUnicast():
		return ClassLinkLocal
	case a.IsPrivate():
		return ClassPrivate
	}
	if nat64WellKnown.Contains(a) {
		b := a.As16()
		if classify4(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})) != ClassPublic {
			return ClassEmbedded
		}
		return ClassPublic
	}
	if !globalUnicast6.Contains(a) {
		// ::/96 IPv4-compatible, 64:ff9b:1::/48 local NAT64, 100::/64 discard,
		// fec0::/10 site-local, 5f00::/16 SRv6 and all unallocated space.
		return ClassReserved
	}
	for _, p := range deniedIPv6 {
		if p.Contains(a) {
			if p.Bits() == 16 || p.Bits() == 23 {
				return ClassEmbedded
			}
			return ClassReserved
		}
	}
	return ClassPublic
}

func classify4(a netip.Addr) AddressClass {
	switch {
	case a.IsUnspecified():
		return ClassUnspecified
	case a.IsLoopback():
		return ClassLoopback
	case a.IsMulticast():
		return ClassMulticast
	case a.IsLinkLocalUnicast():
		return ClassLinkLocal
	case a.IsPrivate():
		return ClassPrivate
	}
	for _, p := range deniedIPv4 {
		if p.Contains(a) {
			return ClassReserved
		}
	}
	return ClassPublic
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// CheckProxyTrust refuses a trusted_proxies network that holds more than one
// address and contains a gateway of this machine's networks. On a Docker
// bridge every local process reaches the service through the bridge gateway,
// so trusting a range around it lets any of them name its own client address
// in X-Forwarded-For (a fresh password bucket per guess, a forged audit
// source). Trusting exactly a gateway address (a proxy that really runs on
// the host side of the bridge) is reported as a warning: every local process
// shares that trust. gateways is what LocalGateways found; an empty list
// checks nothing.
func CheckProxyTrust(trusted []netip.Prefix, gateways []netip.Addr) (warnings []string, err error) {
	for _, p := range trusted {
		for _, g := range gateways {
			if !p.Contains(g) {
				continue
			}
			if p.IsSingleIP() {
				warnings = append(warnings, fmt.Sprintf("trusted_proxies trusts %s, a gateway of this machine's networks: every local process that connects through it can choose the client address the service limits and audits by", p))
				continue
			}
			return warnings, fmt.Errorf("trusted_proxies network %s contains %s, a gateway of this machine's networks: every local process connecting through it could choose the client address the service limits and audits by; trust only the proxy's own address (for the shipped compose.yaml, 10.231.207.2/32)", p, g)
		}
	}
	return warnings, nil
}

// LocalGateways lists, best effort, the gateways this machine (inside a
// container: this container) routes through: every IPv4 gateway in
// /proc/net/route, and the first address of each IPv4 network on its
// interfaces, which is where Docker puts a bridge gateway.
func LocalGateways() []netip.Addr {
	seen := map[netip.Addr]bool{}
	var out []netip.Addr
	add := func(a netip.Addr) {
		if a.IsValid() && !a.IsUnspecified() && !seen[a] {
			seen[a] = true
			out = append(out, a)
		}
	}
	if f, err := os.Open("/proc/net/route"); err == nil {
		for _, a := range routeGateways(f) {
			add(a)
		}
		f.Close()
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip, ok := netip.AddrFromSlice(n.IP)
			ones, bits := n.Mask.Size()
			if !ok || !ip.Unmap().Is4() || bits != 32 || ones > 30 || ip.IsLoopback() {
				continue
			}
			first := netip.PrefixFrom(ip.Unmap(), ones).Masked().Addr().Next()
			add(first)
		}
	}
	return out
}

// routeGateways parses /proc/net/route: the Gateway column of every route
// with RTF_GATEWAY (0x2), little-endian hex.
func routeGateways(r io.Reader) []netip.Addr {
	var out []netip.Addr
	scan := bufio.NewScanner(r)
	first := true
	for scan.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(scan.Text())
		if len(fields) < 4 {
			continue
		}
		flags, err := strconv.ParseUint(fields[3], 16, 32)
		raw, herr := hex.DecodeString(fields[2])
		if err != nil || herr != nil || len(raw) != 4 || flags&0x2 == 0 {
			continue
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], binary.LittleEndian.Uint32(raw))
		out = append(out, netip.AddrFrom4(b))
	}
	return out
}

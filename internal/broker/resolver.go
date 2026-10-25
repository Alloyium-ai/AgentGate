// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Resolver resolves an upstream name. *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc connects to one already validated address.
type DialFunc func(ctx context.Context, addr netip.AddrPort) (net.Conn, error)

// upstreamError classifies a failure without carrying addresses, names or
// response content; its text is safe for stats and logs.
type upstreamError struct{ kind string }

func (e *upstreamError) Error() string { return "upstream " + e.kind }

const (
	errKindResolve       = "resolve"
	errKindAddressDenied = "address_denied"
	errKindConnect       = "connect"
)

const maxResolvedAddresses = 16
const maxDialAttempts = 4

// addressGuard is the SSRF and rebinding boundary for one upstream. It resolves
// the name itself, refuses the whole answer if any address is not public or is
// one of the host's own, and dials only a validated address. It re-validates on
// every new connection and never reuses an answer beyond the cache bound.
type addressGuard struct {
	host     string
	port     uint16
	resolver Resolver
	ttl      time.Duration
	denied   []netip.Prefix
	// exact, when non-empty, is the private-by-design allowlist: every
	// address must be one of these and nothing else is acceptable.
	exact map[netip.Addr]bool
	dial  DialFunc
	now   func() time.Time

	mu      sync.Mutex
	cached  []netip.Addr
	expires time.Time
}

// check returns ClassPublic for an acceptable destination.
func (g *addressGuard) check(a netip.Addr) AddressClass {
	if !a.IsValid() || a.Zone() != "" {
		return ClassInvalid
	}
	u := a.Unmap()
	for _, p := range g.denied {
		if p.Contains(u) {
			return ClassLocal
		}
	}
	if len(g.exact) > 0 {
		if g.exact[u] && ClassifyAddress(u) == ClassPrivate {
			return ClassPublic
		}
		return ClassUnlisted
	}
	return ClassifyAddress(a)
}

func (g *addressGuard) resolve(ctx context.Context) ([]netip.Addr, error) {
	g.mu.Lock()
	if g.cached != nil && g.now().Before(g.expires) {
		out := slices.Clone(g.cached)
		g.mu.Unlock()
		return out, nil
	}
	g.mu.Unlock()
	answer, err := g.resolver.LookupNetIP(ctx, "ip", g.host)
	if err != nil || len(answer) == 0 {
		return nil, &upstreamError{errKindResolve}
	}
	if len(answer) > maxResolvedAddresses {
		answer = answer[:maxResolvedAddresses]
	}
	out := make([]netip.Addr, 0, len(answer))
	for _, a := range answer {
		// A mixed answer is treated as hostile: one non-public address refuses
		// the whole resolution rather than silently using the others.
		if g.check(a) != ClassPublic {
			return nil, &upstreamError{errKindAddressDenied}
		}
		out = append(out, a.Unmap())
	}
	// Prefer IPv4: the broker's egress network is usually IPv4 only.
	slices.SortStableFunc(out, func(x, y netip.Addr) int {
		switch {
		case x.Is4() && !y.Is4():
			return -1
		case !x.Is4() && y.Is4():
			return 1
		}
		return 0
	})
	if g.ttl > 0 {
		g.mu.Lock()
		g.cached = slices.Clone(out)
		g.expires = g.now().Add(g.ttl)
		g.mu.Unlock()
	}
	return out, nil
}

// DialContext is the transport dialer. The transport only ever asks for the
// route's own host and port; anything else is refused.
func (g *addressGuard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, &upstreamError{errKindAddressDenied}
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil || host != g.host || port != strconv.Itoa(int(g.port)) {
		return nil, &upstreamError{errKindAddressDenied}
	}
	addrs, err := g.resolve(ctx)
	if err != nil {
		return nil, err
	}
	var last error = &upstreamError{errKindConnect}
	for i, a := range addrs {
		if i >= maxDialAttempts {
			break
		}
		if g.check(a) != ClassPublic {
			return nil, &upstreamError{errKindAddressDenied}
		}
		target := netip.AddrPortFrom(a, g.port)
		conn, err := g.dial(ctx, target)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var ue *upstreamError
			if errors.As(err, &ue) {
				return nil, err
			}
			last = &upstreamError{errKindConnect}
			continue
		}
		return conn, nil
	}
	return nil, last
}

// systemDial connects with a socket-level re-check: the Control hook sees the
// exact address passed to connect(2) and refuses it if it is not public.
func systemDial(timeout time.Duration, guard func(netip.Addr) AddressClass) DialFunc {
	d := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil || guard(ap.Addr()) != ClassPublic {
				return &upstreamError{errKindAddressDenied}
			}
			return nil
		},
	}
	return func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
		network := "tcp4"
		if !addr.Addr().Is4() {
			network = "tcp6"
		}
		return d.DialContext(ctx, network, addr.String())
	}
}

// localDenied lists the host's own addresses and the broker network so an
// upstream can never resolve back to the broker or the machine it runs on.
func localDenied(listenSubnet string, addrs func() ([]net.Addr, error)) []netip.Prefix {
	var out []netip.Prefix
	if p, err := netip.ParsePrefix(listenSubnet); err == nil {
		out = append(out, p)
	}
	if addrs == nil {
		addrs = net.InterfaceAddrs
	}
	list, err := addrs()
	if err != nil {
		return out
	}
	for _, a := range list {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				ip = ip.Unmap()
				out = append(out, netip.PrefixFrom(ip, ip.BitLen()))
			}
		}
	}
	return out
}

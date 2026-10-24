// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func TestAddressClassTable(t *testing.T) {
	denied := []string{
		// IPv4 special-purpose space
		"0.0.0.0", "0.1.2.3", "10.0.0.1", "10.255.255.255", "100.64.0.1", "100.127.255.254", "127.0.0.1", "127.255.0.1",
		"169.254.169.254", "169.254.0.1", "172.16.0.1", "172.31.255.255", "192.0.0.1", "192.0.0.8", "192.0.2.10",
		"192.31.196.1", "192.52.193.1", "192.88.99.1", "192.168.1.1", "192.175.48.1", "198.18.0.1", "198.19.255.255",
		"198.51.100.7", "203.0.113.9", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		// IPv6 special-purpose space
		"::", "::1", "fe80::1", "fec0::1", "fc00::1", "fd12:3456::1", "ff02::1", "ff0e::1", "100::1", "2001:db8::1",
		"3fff::1", "2001::1", "2001:0:4136:e378:8000:63bf:3fff:fdd2", "2001:2::1", "2001:10::1", "2001:20::1",
		"2002:c0a8:0101::1", "2002:0808:0808::1", "5f00::1", "2620:4f:8000::1",
		// IPv4 carried in IPv6
		"::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "::ffff:192.168.0.1", "::127.0.0.1", "::10.0.0.1",
		"64:ff9b::127.0.0.1", "64:ff9b::a00:1", "64:ff9b::169.254.169.254", "64:ff9b:1::8.8.8.8",
		// zoned
		"fe80::1%eth0",
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "93.184.215.14", "151.101.1.1", "1.2.3.4", "2606:4700::1111",
		"2a00:1450:4001::200e", "::ffff:1.1.1.1", "64:ff9b::1.1.1.1", "100.63.255.255", "100.128.0.0", "172.32.0.1",
		"172.15.255.255", "192.169.0.1", "198.20.0.1", "223.255.255.254"}
	for _, s := range denied {
		a, err := netip.ParseAddr(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if got := ClassifyAddress(a); got == ClassPublic {
			t.Errorf("%s classified public", s)
		}
	}
	for _, s := range allowed {
		if got := ClassifyAddress(netip.MustParseAddr(s)); got != ClassPublic {
			t.Errorf("%s classified %s", s, got)
		}
	}
	if ClassifyAddress(netip.Addr{}) != ClassInvalid {
		t.Error("zero address accepted")
	}
}

type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr // successive answers; the last repeats
	calls   map[string]int
}

func newFakeResolver() *fakeResolver {
	return &fakeResolver{answers: map[string][][]netip.Addr{}, calls: map[string]int{}}
}

func (f *fakeResolver) set(host string, answers ...[]string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.answers[host] = nil
	for _, a := range answers {
		var list []netip.Addr
		for _, s := range a {
			list = append(list, netip.MustParseAddr(s))
		}
		f.answers[host] = append(f.answers[host], list)
	}
}

func (f *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	list := f.answers[host]
	if len(list) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	i := f.calls[host]
	f.calls[host]++
	if i >= len(list) {
		i = len(list) - 1
	}
	return append([]netip.Addr(nil), list[i]...), nil
}

func (f *fakeResolver) count(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[host]
}

type recordingDial struct {
	mu     sync.Mutex
	dialed []netip.AddrPort
}

func (r *recordingDial) dial(_ context.Context, addr netip.AddrPort) (net.Conn, error) {
	r.mu.Lock()
	r.dialed = append(r.dialed, addr)
	r.mu.Unlock()
	c1, c2 := net.Pipe()
	go func() { c2.Close() }()
	return c1, nil
}

func newGuard(res Resolver, d DialFunc, ttl time.Duration, clock *time.Time) *addressGuard {
	return &addressGuard{host: "api.example.test", port: 443, resolver: res, ttl: ttl, dial: d,
		denied: localDenied("10.99.0.0/29", func() ([]net.Addr, error) {
			return []net.Addr{&net.IPNet{IP: net.ParseIP("203.0.113.50").To4(), Mask: net.CIDRMask(24, 32)},
				&net.IPNet{IP: net.ParseIP("5.6.7.8").To4(), Mask: net.CIDRMask(24, 32)}}, nil
		}),
		now: func() time.Time { return *clock }}
}

func kindOf(err error) string {
	var ue *upstreamError
	if errors.As(err, &ue) {
		return ue.kind
	}
	return ""
}

func TestGuardRefusesEveryNonPublicAnswer(t *testing.T) {
	clock := time.Now()
	for _, answer := range [][]string{{"127.0.0.1"}, {"169.254.169.254"}, {"10.0.0.5"}, {"::1"}, {"::ffff:10.0.0.1"},
		{"64:ff9b::a9fe:a9fe"}, {"2002:a00:1::1"}, {"fd00::1"}, {"1.1.1.1", "192.168.0.1"}, {"10.99.0.3"}, {"5.6.7.8"}} {
		res := newFakeResolver()
		res.set("api.example.test", answer)
		rec := &recordingDial{}
		g := newGuard(res, rec.dial, time.Minute, &clock)
		if _, err := g.DialContext(context.Background(), "tcp", "api.example.test:443"); kindOf(err) != errKindAddressDenied {
			t.Errorf("%v: err %v", answer, err)
		}
		if len(rec.dialed) != 0 {
			t.Errorf("%v: dialed %v", answer, rec.dialed)
		}
	}
}

func TestGuardRefusesOtherDestinationsFromTheTransport(t *testing.T) {
	clock := time.Now()
	res := newFakeResolver()
	res.set("api.example.test", []string{"1.2.3.4"})
	rec := &recordingDial{}
	g := newGuard(res, rec.dial, time.Minute, &clock)
	for _, addr := range []string{"evil.example:443", "api.example.test:80", "1.2.3.4:443", "api.example.test"} {
		if _, err := g.DialContext(context.Background(), "tcp", addr); kindOf(err) != errKindAddressDenied {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if _, err := g.DialContext(context.Background(), "udp", "api.example.test:443"); kindOf(err) != errKindAddressDenied {
		t.Error("udp accepted")
	}
	if len(rec.dialed) != 0 {
		t.Fatal(rec.dialed)
	}
}

func TestGuardDefeatsDNSRebinding(t *testing.T) {
	clock := time.Now()
	res := newFakeResolver()
	// First answer public, every later answer points at the metadata service.
	res.set("api.example.test", []string{"1.2.3.4"}, []string{"169.254.169.254"})
	rec := &recordingDial{}
	g := newGuard(res, rec.dial, 30*time.Second, &clock)
	c, err := g.DialContext(context.Background(), "tcp", "api.example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	// Within the cache bound the validated answer is reused without a lookup.
	clock = clock.Add(10 * time.Second)
	if c, err = g.DialContext(context.Background(), "tcp", "api.example.test:443"); err != nil {
		t.Fatal(err)
	}
	c.Close()
	if res.count("api.example.test") != 1 {
		t.Fatalf("lookups %d", res.count("api.example.test"))
	}
	// After the bound the name is resolved again and the rebound answer refused.
	clock = clock.Add(31 * time.Second)
	if _, err = g.DialContext(context.Background(), "tcp", "api.example.test:443"); kindOf(err) != errKindAddressDenied {
		t.Fatalf("rebinding accepted: %v", err)
	}
	for _, a := range rec.dialed {
		if a.Addr() != netip.MustParseAddr("1.2.3.4") || a.Port() != 443 {
			t.Fatalf("dialed %v", a)
		}
	}
	if len(rec.dialed) != 2 {
		t.Fatalf("dialed %v", rec.dialed)
	}
}

func TestGuardWithoutCacheResolvesEveryConnection(t *testing.T) {
	clock := time.Now()
	res := newFakeResolver()
	res.set("api.example.test", []string{"1.2.3.4"}, []string{"1.2.3.4"}, []string{"127.0.0.1"})
	rec := &recordingDial{}
	g := newGuard(res, rec.dial, 0, &clock)
	for i := 0; i < 2; i++ {
		c, err := g.DialContext(context.Background(), "tcp", "api.example.test:443")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	if _, err := g.DialContext(context.Background(), "tcp", "api.example.test:443"); kindOf(err) != errKindAddressDenied {
		t.Fatal(err)
	}
	if res.count("api.example.test") != 3 {
		t.Fatal(res.count("api.example.test"))
	}
}

func TestGuardPrefersIPv4AndUnmapsAnswers(t *testing.T) {
	clock := time.Now()
	res := newFakeResolver()
	res.set("api.example.test", []string{"2606:4700::1111", "::ffff:1.2.3.4"})
	rec := &recordingDial{}
	g := newGuard(res, rec.dial, time.Minute, &clock)
	c, err := g.DialContext(context.Background(), "tcp", "api.example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if len(rec.dialed) != 1 || rec.dialed[0] != netip.MustParseAddrPort("1.2.3.4:443") {
		t.Fatal(rec.dialed)
	}
}

func TestGuardResolveFailureAndSocketCheck(t *testing.T) {
	clock := time.Now()
	g := newGuard(newFakeResolver(), (&recordingDial{}).dial, time.Minute, &clock)
	if _, err := g.DialContext(context.Background(), "tcp", "api.example.test:443"); kindOf(err) != errKindResolve {
		t.Fatal(err)
	}
	// The socket-level Control hook refuses a non-public address even if a
	// caller bypassed the resolver check.
	dial := systemDial(time.Second, ClassifyAddress)
	if _, err := dial(context.Background(), netip.MustParseAddrPort("127.0.0.1:9")); kindOf(err) != errKindAddressDenied {
		t.Fatalf("socket check: %v", err)
	}
}

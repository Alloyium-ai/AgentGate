// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// Regression for the second review's TestReviewLimiterKeyTableExhaustion:
// one table of 2048 buckets held every family and refused every new key
// while full, so one request from each of 2048 client keys a minute locked
// every other client out of the API and of sign-in.
func TestALimiterFloodNeverLocksOutNewClients(t *testing.T) {
	f := newProv(t)
	f.srv.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	if code := f.send("GET", "/api/v1/launches", "198.51.100.9", nil); code != 401 {
		t.Fatalf("baseline: %d", code)
	}
	// The review's flood: 2048 IPv6 /64s.
	for i := 0; i < 2048; i++ {
		f.send("GET", "/api/v1/launches", fmt.Sprintf("2001:db8:%x:%x::1", i>>8, i&0xff), nil)
	}
	// A wider one: more distinct clients than the API and sign-in tables
	// hold (TestRateTableEvictsTheLeastRecentlyUsedBucket and
	// TestOneIPv6Slash48HoldsAtMostSixteenBuckets cover /56 and /48 keys).
	for i := 0; i < rateFamilies["ip"].size+100; i++ {
		f.send("GET", "/api/v1/launches", fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff), nil)
	}
	for i := 0; i < rateFamilies["password"].size+100; i++ {
		f.send("POST", "/auth/local/login", fmt.Sprintf("10.200.%d.%d", i>>8&0xff, i&0xff), []byte(`{}`))
	}
	if got := f.send("GET", "/api/v1/launches", "198.51.100.77", nil); got == 429 {
		t.Fatalf("a new client after the flood: API %d", got)
	}
	if got := f.send("POST", "/auth/local/login", "198.51.100.78", []byte(`{}`)); got == 429 {
		t.Fatalf("a new client after the flood: sign-in %d", got)
	}
	f.srv.mu.Lock()
	for family, table := range f.srv.limits {
		if table.len() > rateFamilies[family].size {
			t.Errorf("%s holds %d buckets, above its %d", family, table.len(), rateFamilies[family].size)
		}
	}
	f.srv.mu.Unlock()
	// A client that was flooding is still limited: the flood evicted idle
	// buckets, not the busy one.
	for i := 0; i < 1201; i++ {
		f.send("GET", "/api/v1/launches", "203.0.113.50", nil)
	}
	if got := f.send("GET", "/api/v1/launches", "203.0.113.50", nil); got != 429 {
		t.Fatalf("the busy client escaped its limit: %d", got)
	}
}

// An honest host's signed resync and polls keep working through an
// enrollment and forged-host flood from every address.
func TestHostBucketsSurviveAddressFloods(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	f.srv.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	for i := 0; i < 3000; i++ {
		client := fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff)
		f.send("POST", "/api/v1/hostd/enroll", client, []byte(`{}`))
		f.send("POST", "/api/v1/hostd/poll", client, []byte(`{"domain":"x","key_id":"x","payload":"e30","signature":"AA"}`))
	}
	rs := hostproto.ResyncRequest{HostID: h.id, Nonce: nonce(), TimestampMS: f.now().UnixMilli(), Reason: "counter-lost"}
	if code := f.send("POST", "/api/v1/hostd/resync", "10.0.0.1", h.seal(hostproto.DomainResync, rs)); code != 200 {
		t.Fatalf("the honest host's resync after the flood: %d", code)
	}
	h.seq = 0
	if code := f.send("POST", "/api/v1/hostd/poll", "10.0.0.1", h.pollRaw()); code != 200 {
		t.Fatalf("the honest host's poll after the flood: %d", code)
	}
	// Its own resync bucket is tight and its own.
	limited := false
	for i := 0; i < 12; i++ {
		rs := hostproto.ResyncRequest{HostID: h.id, Nonce: nonce(), TimestampMS: f.now().UnixMilli(), Reason: "counter-lost"}
		if f.send("POST", "/api/v1/hostd/resync", fmt.Sprintf("10.9.0.%d", i), h.seal(hostproto.DomainResync, rs)) == 429 {
			limited = true
		}
	}
	if !limited {
		t.Fatal("eleven resyncs of one host in a minute, from different addresses, were not limited")
	}
}

func TestRateTableEvictsTheLeastRecentlyUsedBucket(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	tb := newRateTable(3)
	for _, k := range []string{"a", "b", "c"} {
		tb.take(k, "", 2, now)
	}
	tb.take("a", "", 2, now) // a is now the most recent; b the least
	tb.take("d", "", 2, now)
	if _, ok := tb.byKey["b"]; ok || tb.len() != 3 {
		t.Fatalf("expected b evicted: %v", tb.byKey)
	}
	// a's count survived (2 of 2); one more is over the ceiling.
	if !tb.take("a", "", 2, now) {
		t.Fatal("a's count was lost")
	}
	// An evicted key starts a fresh window.
	if tb.take("b", "", 2, now) {
		t.Fatal("an evicted key is limited")
	}
	// The window resets after a minute.
	if tb.take("a", "", 2, now.Add(rateWindow+time.Second)) {
		t.Fatal("a's window did not reset")
	}
	// A new key is never refused for want of room.
	for i := 0; i < 100; i++ {
		if tb.take(fmt.Sprintf("n%d", i), "", 2, now) {
			t.Fatal("a new key was refused")
		}
		if tb.len() > 3 {
			t.Fatal("the table grew past its size")
		}
	}
}

func TestOneIPv6Slash48HoldsAtMostSixteenBuckets(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	tb := newRateTable(1024)
	group := ""
	for i := 0; i < 256; i++ {
		key := clientKey(netip.MustParseAddr(fmt.Sprintf("2001:db8:1:%x00::1", i)))
		if group = addressGroup(key); group != "2001:db8:1::/48" {
			t.Fatalf("group of %s: %q", key, group)
		}
		tb.take(key, group, 10, now)
	}
	if tb.len() != rateGroupLimit+1 || tb.groups[group] != rateGroupLimit {
		t.Fatalf("one /48 holds %d buckets (%d grouped)", tb.len(), tb.groups[group])
	}
	// The other /56s share one bucket, which is over its ceiling now.
	if !tb.take(clientKey(netip.MustParseAddr("2001:db8:1:ff00::2")), group, 10, now) {
		t.Fatal("the shared bucket of the /48 is not limited")
	}
	// Keys inside one /56 are one client.
	if clientKey(netip.MustParseAddr("2001:db8:1:200::1")) != clientKey(netip.MustParseAddr("2001:db8:1:2ff:ffff::9")) {
		t.Fatal("two addresses of one /56 have different keys")
	}
	if addressGroup("203.0.113.1") != "" || addressGroup("local:ada") != "" {
		t.Fatal("an IPv4 or subject key was grouped")
	}
}

// Many goroutines over overlapping keys: no race, and every table stays
// within its size. Run with -race.
func TestRateLimiterIsSafeUnderConcurrency(t *testing.T) {
	s := &Server{limits: map[string]*rateTable{}, hostLimits: newRateTable(hostTableSize)}
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			r := rand.New(rand.NewSource(seed))
			for i := 0; i < 3000; i++ {
				client := fmt.Sprintf("10.0.%d.%d", r.Intn(64), r.Intn(256))
				if r.Intn(2) == 0 {
					client = clientKey(netip.MustParseAddr(fmt.Sprintf("2001:db8:%x:%x00::1", r.Intn(8), r.Intn(256))))
				}
				for _, family := range []string{"ip", "auth", "password", "hostfail", "enroll", "actor"} {
					s.limited(family, client)
				}
				s.limitedHost("host", fmt.Sprintf("%032x", r.Intn(4096)))
			}
		}(int64(g))
	}
	wg.Wait()
	for family, table := range s.limits {
		if table.len() > rateFamilies[family].size {
			t.Errorf("%s: %d buckets", family, table.len())
		}
	}
	if s.hostLimits.len() > hostTableSize {
		t.Errorf("host table: %d buckets", s.hostLimits.len())
	}
	if !s.limited("no-such-family", "x") || !s.limitedHost("no-such-family", "x") {
		t.Fatal("an unknown family is not limited")
	}
}

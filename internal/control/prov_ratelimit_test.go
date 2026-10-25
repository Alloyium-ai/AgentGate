// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bytes"
	"net/http"
	"net/netip"
	"testing"
	"time"
)

func (f *provFixture) send(method, path, xff string, body []byte) int {
	f.t.Helper()
	r, _ := http.NewRequest(method, f.http.URL+path, bytes.NewReader(body))
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	resp, err := f.http.Client().Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func (f *provFixture) auditRows() int {
	var n int
	f.s.DB.QueryRow("SELECT count(*) FROM audit").Scan(&n)
	return n
}

// Regression for the review repro TestReviewUnauthenticatedFloodStarvesHostPolls:
// behind the TLS front every request had one RemoteAddr, so an
// unauthenticated flood filled the one shared bucket, the honest host's
// signed poll was refused (its running launches then fail lost_host), and
// every denial wrote an append-only audit row.
func TestAnUnauthenticatedFloodNeitherStarvesHostPollsNorGrowsTheAudit(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	f.profile("dev", false)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	jobs := h.poll()
	e1 := ev(1, f, "state")
	e1.State = "running"
	must(h.events(jobs[0].ID, e1))

	before := f.auditRows()
	limited := 0
	for i := 0; i < 1300; i++ {
		if f.send("GET", "/api/v1/launches", "", nil) == 429 {
			limited++
		}
	}
	if limited == 0 {
		t.Fatal("the flood was never limited")
	}
	// Forged host requests from the same address are refused and sampled too.
	for i := 0; i < 200; i++ {
		f.send("POST", "/api/v1/hostd/poll", "", []byte(`{"domain":"x","key_id":"x","payload":"e30","signature":"AA"}`))
	}
	added := f.auditRows() - before
	if added > 2*anonymousDenialsPerMinute+2 {
		t.Fatalf("1500 anonymous requests added %d audit rows", added)
	}
	// The honest host's signed poll, over HTTP from the same address, works.
	if code := f.send("POST", "/api/v1/hostd/poll", "", h.pollRaw(l.ID)); code != 200 {
		t.Fatalf("the honest host's poll after the flood: HTTP %d", code)
	}
	f.advance(25 * time.Second)
	must(f.s.Sweep())
	if got := f.state(l.ID); got.State != StateRunning {
		t.Fatalf("the launch is %s (%s)", got.State, got.EvidenceMissing)
	}
	// Once the minute is over, one row says how many denials were left out.
	f.advance(time.Minute)
	must(f.s.Sweep())
	var suppressed int
	f.s.DB.QueryRow("SELECT coalesce(sum(json_extract(after_json,'$.suppressed')),0) FROM audit WHERE action='audit.denials.suppressed'").Scan(&suppressed)
	if suppressed < 1300-anonymousDenialsPerMinute {
		t.Fatalf("the suppression rows count %d denials", suppressed)
	}
}

// Behind a trusted proxy the service limits by the client address the proxy
// forwarded: one client's flood does not limit another client, a spoofed
// left part of X-Forwarded-For does not escape the limit, and a request from
// the proxy without a well-formed X-Forwarded-For is refused.
func TestBehindATrustedProxyLimitsAreKeyedByTheForwardedClient(t *testing.T) {
	f := newProv(t)
	f.srv.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	for i := 0; i < 1210; i++ {
		f.send("GET", "/api/v1/launches", "203.0.113.7", nil)
	}
	if code := f.send("GET", "/api/v1/launches", "203.0.113.7", nil); code != 429 {
		t.Fatalf("the flooding client: %d", code)
	}
	if code := f.send("GET", "/api/v1/launches", "198.51.100.9", nil); code != 401 {
		t.Fatalf("another client behind the same proxy: %d", code)
	}
	if code := f.send("GET", "/api/v1/launches", "198.51.100.9, 203.0.113.7", nil); code != 429 {
		t.Fatalf("a spoofed left entry escaped the limit: %d", code)
	}
	for _, bad := range []string{"", "not-an-ip", "203.0.113.7, ", "fe80::1%eth0"} {
		if code := f.send("GET", "/api/v1/launches", bad, nil); code != 400 {
			t.Errorf("X-Forwarded-For %q: %d", bad, code)
		}
	}
	// A client that is not a trusted proxy cannot choose its address.
	f.srv.TrustedProxies = nil
	if code := f.send("GET", "/api/v1/launches", "198.51.100.10", nil); code != 401 {
		t.Fatalf("without trusted proxies the header is ignored: %d", code)
	}
	// Password sign-in is limited per forwarded client too.
	f.srv.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	for i := 0; i < 11; i++ {
		f.send("POST", "/auth/local/login", "203.0.113.20", []byte(`{}`))
	}
	if code := f.send("POST", "/auth/local/login", "203.0.113.20", []byte(`{}`)); code != 429 {
		t.Fatalf("the twelfth sign-in from one client: %d", code)
	}
	if code := f.send("POST", "/auth/local/login", "203.0.113.21", []byte(`{}`)); code == 429 {
		t.Fatal("another client's sign-in was limited")
	}
}

func TestTrustedProxySettingIsCanonicalCIDR(t *testing.T) {
	if _, err := ParseTrustedProxies([]string{"10.231.207.0/28", "fd00::/64"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"10.231.207.1/28", "10.0.0.1", "nonsense", "10.0.0.0/8 "} {
		if _, err := ParseTrustedProxies([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestEachRouteUsesOnlyItsOwnSecretAndOrigin(t *testing.T) {
	e := newEnv(t, withSecondRoute(), withRules(allRule()))
	for i := 0; i < 3; i++ {
		e.text(e.do("POST", "/anthropic/v1/messages", strings.NewReader("{}")))
		e.text(e.do("GET", "/beta/repos/o/r", nil, "Authorization", "Bearer agent-supplied"))
	}
	alpha, beta := 0, 0
	for _, r := range e.requests() {
		auth := r.Header.Get("Authorization")
		key := r.Header.Get("X-Api-Key")
		switch r.Host {
		case "api.example.test":
			alpha++
			if r.SNI != "api.example.test" || key != testSecret || auth != "" || strings.Contains(r.Header.Get("Anthropic-Version"), betaSecret) {
				t.Fatalf("alpha request carried the wrong credential or name: %+v", r)
			}
		case "beta.example.test":
			beta++
			if r.SNI != "beta.example.test" || auth != "Bearer "+betaSecret || key != "" || r.Path != "/repos/o/r" {
				t.Fatalf("beta request carried the wrong credential or name: %+v", r)
			}
		default:
			t.Fatalf("unexpected upstream host %q", r.Host)
		}
		for _, vv := range r.Header {
			for _, v := range vv {
				if (r.Host == "api.example.test" && strings.Contains(v, betaSecret)) ||
					(r.Host == "beta.example.test" && strings.Contains(v, testSecret)) {
					t.Fatal("a secret reached another route's upstream")
				}
			}
		}
	}
	if alpha != 3 || beta != 3 {
		t.Fatal(alpha, beta)
	}
	// Each route's transport can dial only its own origin.
	for _, pair := range [][2]string{{"anthropic", "beta.example.test:443"}, {"beta", "api.example.test:443"}} {
		if _, err := e.srv.routes[pair[0]].guard.DialContext(context.Background(), "tcp", pair[1]); kindOf(err) != errKindAddressDenied {
			t.Fatalf("route %s dialed %s: %v", pair[0], pair[1], err)
		}
	}
	st := e.stats()
	if st.Routes["anthropic"].Forwarded != 3 || st.Routes["beta"].Forwarded != 3 || st.Routes["beta"].Upstream != "beta.example.test:443" {
		t.Fatalf("%+v %+v", st.Routes["anthropic"], st.Routes["beta"])
	}
	mustNotContainSecret(t, "stats", e.logs.String())
}

func TestPrivateByDesignUpstreamIsPinnedToItsExactAddress(t *testing.T) {
	clock := time.Now()
	for answer, want := range map[string]string{
		"10.10.10.10":     "",
		"10.10.10.11":     errKindAddressDenied,
		"1.2.3.4":         errKindAddressDenied,
		"127.0.0.1":       errKindAddressDenied,
		"169.254.169.254": errKindAddressDenied,
		"10.99.0.3":       errKindAddressDenied, // broker network
	} {
		res := newFakeResolver()
		res.set("api.example.test", []string{answer})
		rec := &recordingDial{}
		g := newGuard(res, rec.dial, time.Minute, &clock)
		g.exact = map[netip.Addr]bool{netip.MustParseAddr("10.10.10.10"): true, netip.MustParseAddr("10.99.0.3"): true}
		c, err := g.DialContext(context.Background(), "tcp", "api.example.test:443")
		if c != nil {
			c.Close()
		}
		if kindOf(err) != want || (want == "" && err != nil) {
			t.Errorf("%s: %v", answer, err)
		}
	}
	// Configuration refuses non-private, loopback, link-local and broker-network entries.
	for _, bad := range []string{"127.0.0.1", "169.254.169.254", "8.8.8.8", "10.99.0.3", "::ffff:10.0.0.1", "fe80::1", "010.0.0.1"} {
		m := validConfigJSON()
		m["routes"].([]any)[0].(map[string]any)["upstream"].(map[string]any)["private_addresses"] = []any{bad}
		cfg, err := ParseConfig(encode(t, m))
		if err == nil {
			_, err = cfg.Validate(testNow)
		}
		if err == nil {
			t.Errorf("private_addresses %s accepted", bad)
		}
	}
	m := validConfigJSON()
	m["routes"].([]any)[0].(map[string]any)["upstream"].(map[string]any)["private_addresses"] = []any{"10.10.10.10", "fd00::5"}
	cfg, err := ParseConfig(encode(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Validate(testNow); err != nil {
		t.Fatal(err)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package pocpolicy

import (
	"alloyium.local/kernel-poc/internal/netrules"
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) Document {
	t.Helper()
	raw, err := os.ReadFile("../../poc/ssh-diagnostic/policy.example.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func TestCompiledBoundary(t *testing.T) {
	d := fixture(t)
	c, err := d.Compile(1, 100)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		ip      string
		proto   uint8
		port    uint16
		allowed bool
	}{
		{"1.1.1.1", netrules.UDP, 53, true}, {"1.1.1.1", netrules.TCP, 53, true}, {"8.8.8.8", netrules.UDP, 53, false},
		{"93.184.215.14", netrules.TCP, 80, true}, {"93.184.215.14", netrules.TCP, 443, true}, {"93.184.215.14", netrules.UDP, 443, true}, {"93.184.215.14", netrules.TCP, 22, false}, {"93.184.215.14", netrules.UDP, 80, false},
		{"10.10.10.10", netrules.TCP, 8080, true}, {"10.10.10.10", netrules.UDP, 8080, false}, {"10.10.10.10", netrules.TCP, 443, false},
		{"10.10.10.11", netrules.TCP, 80, false}, {"172.18.0.1", netrules.TCP, 443, false}, {"127.0.0.1", netrules.TCP, 443, false}, {"169.254.1.1", netrules.UDP, 443, false}, {"100.64.0.1", netrules.TCP, 443, false},
		{"::1", netrules.TCP, 443, false}, {"2606:4700::1111", netrules.TCP, 443, false}, {"::ffff:10.1.1.1", netrules.TCP, 443, false}, {"192.0.2.1", netrules.TCP, 443, false},
	}
	for _, v := range cases {
		e := netrules.Endpoint{Address: netip.MustParseAddr(v.ip), Protocol: v.proto, Port: v.port}
		if got := netrules.Evaluate(c.Policy, e, 2); got.Allowed != v.allowed {
			t.Errorf("%+v: %+v", v, got)
		}
		if got := netrules.Evaluate(c.Policy, e, 100); got.Allowed {
			t.Errorf("expired allow: %+v", v)
		}
	}
}
func TestEditChangesNextCompilation(t *testing.T) {
	d := fixture(t)
	old := d.Digest()
	d.Web.Rules = []WebRule{{Protocol: "tcp", Port: 443}}
	if old == d.Digest() {
		t.Fatal("digest did not change")
	}
	c, err := d.Compile(1, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []WebRule{{"tcp", 80}, {"udp", 443}} {
		proto := uint8(netrules.TCP)
		if v.Protocol == "udp" {
			proto = netrules.UDP
		}
		if netrules.Evaluate(c.Policy, netrules.Endpoint{netip.MustParseAddr("1.1.1.1"), proto, uint16(v.Port)}, 2).Allowed {
			t.Fatal("removed allowance remains")
		}
	}
}
func TestInvalidPolicyFailsClosed(t *testing.T) {
	d := fixture(t)
	raw, _ := json.Marshal(d)
	for _, bad := range []string{`{`, string(raw) + ` {}`, strings.Replace(string(raw), `"default":"deny"`, `"default":"allow"`, 1), strings.Replace(string(raw), `"default":"deny"`, `"default":"deny","default":"deny"`, 1), strings.Replace(string(raw), `"port":53`, `"port":5353`, 1), strings.Replace(string(raw), `"1.1.1.1"`, `"127.0.0.11"`, 1), strings.Replace(string(raw), `"ipv6":"deny"`, `"ipv6":"allow"`, 1), strings.Replace(string(raw), `"duration_seconds":25`, `"duration_seconds":31`, 1)} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	d.DNS.Resolvers = []string{"10.0.0.1"}
	if _, err := d.Compile(1, 100); err == nil {
		t.Fatal("accepted private resolver")
	}
}

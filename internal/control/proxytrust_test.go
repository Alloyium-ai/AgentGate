// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"net/netip"
	"strings"
	"testing"
)

func TestProxyTrustRefusesARangeHoldingAGateway(t *testing.T) {
	gw := []netip.Addr{netip.MustParseAddr("10.231.207.1")}
	cases := []struct {
		trusted string
		refuse  bool
		warn    bool
	}{
		{"10.231.207.0/28", true, false},
		{"10.0.0.0/8", true, false},
		{"10.231.207.2/32", false, false},
		{"10.231.207.1/32", false, true},
		{"192.0.2.0/24", false, false},
	}
	for _, c := range cases {
		warnings, err := CheckProxyTrust([]netip.Prefix{netip.MustParsePrefix(c.trusted)}, gw)
		if (err != nil) != c.refuse || (len(warnings) > 0) != c.warn {
			t.Errorf("%s: err %v warnings %v", c.trusted, err, warnings)
		}
		if err != nil && !strings.Contains(err.Error(), "10.231.207.2/32") {
			t.Errorf("%s: the refusal does not name the fix: %v", c.trusted, err)
		}
	}
	if w, err := CheckProxyTrust([]netip.Prefix{netip.MustParsePrefix("10.231.207.0/28")}, nil); err != nil || len(w) != 0 {
		t.Fatal("with no gateway found nothing is refused")
	}
}

func TestRouteGatewaysParsesProcNetRoute(t *testing.T) {
	table := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t00000000\t01CFE70A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n" +
		"eth0\t00CFE70A\t00000000\t0001\t0\t0\t0\tF0FFFFFF\t0\t0\t0\n" +
		"bad\n"
	got := routeGateways(strings.NewReader(table))
	if len(got) != 1 || got[0] != netip.MustParseAddr("10.231.207.1") {
		t.Fatalf("gateways %v", got)
	}
	// On this machine the call works and returns only usable addresses.
	for _, a := range LocalGateways() {
		if !a.IsValid() || a.IsUnspecified() {
			t.Fatalf("local gateway %v", a)
		}
	}
}

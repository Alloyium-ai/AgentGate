// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package deploy

import (
	"encoding/json"
	"net/netip"
	"os"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/control"
	"go.yaml.in/yaml/v3"
)

// Regression for the second review's finding that the shipped settings
// trusted the whole compose subnet, bridge gateway included: any local
// process connecting through the gateway could choose the client address
// the service limits and audits by. The shipped files trust exactly the TLS
// front's fixed address, and nothing else can take that address.
func TestShippedProxyTrustIsExactlyTheTLSFront(t *testing.T) {
	var settings struct {
		TrustedProxies []string `json:"trusted_proxies"`
	}
	raw, err := os.ReadFile("../settings.json")
	if err != nil || json.Unmarshal(raw, &settings) != nil {
		t.Fatalf("settings.json: %v", err)
	}
	if len(settings.TrustedProxies) != 1 {
		t.Fatalf("settings.json trusts %v; exactly the TLS front's address is wanted", settings.TrustedProxies)
	}
	trusted, err := control.ParseTrustedProxies(settings.TrustedProxies)
	if err != nil || len(trusted) != 1 || !trusted[0].IsSingleIP() {
		t.Fatalf("the trusted proxy is not one address: %v %v", trusted, err)
	}
	var compose struct {
		Services map[string]yaml.Node `yaml:"services"`
		Networks map[string]struct {
			Internal bool `yaml:"internal"`
			IPAM     struct {
				Config []struct {
					Subnet  string `yaml:"subnet"`
					IPRange string `yaml:"ip_range"`
					Gateway string `yaml:"gateway"`
				} `yaml:"config"`
			} `yaml:"ipam"`
		} `yaml:"networks"`
	}
	raw, err = os.ReadFile("../compose.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &compose); err != nil {
		t.Fatalf("compose.yaml: %v", err)
	}
	var front struct {
		Networks map[string]struct {
			IPv4 string `yaml:"ipv4_address"`
		} `yaml:"networks"`
	}
	node := compose.Services["tls"]
	if err := node.Decode(&front); err != nil {
		t.Fatalf("compose.yaml tls: %v", err)
	}
	tls := front.Networks["control"].IPv4
	if tls == "" || netip.MustParseAddr(tls) != trusted[0].Addr() {
		t.Fatalf("the TLS front's fixed address %q is not the trusted %s", tls, trusted[0])
	}
	if len(compose.Networks["control"].IPAM.Config) != 1 {
		t.Fatal("the control network has no single fixed subnet")
	}
	ipam := compose.Networks["control"].IPAM.Config[0]
	subnet, err1 := netip.ParsePrefix(ipam.Subnet)
	pool, err2 := netip.ParsePrefix(ipam.IPRange)
	gateway, err3 := netip.ParseAddr(ipam.Gateway)
	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("control network ipam %+v", ipam)
	}
	if !subnet.Contains(trusted[0].Addr()) || !subnet.Contains(gateway) || pool.Contains(trusted[0].Addr()) || pool.Contains(gateway) ||
		!subnet.Contains(pool.Addr()) || pool.Bits() < subnet.Bits() {
		t.Fatalf("the dynamic range %s may hand out the fixed address %s or the gateway %s", pool, tls, gateway)
	}
	// The service would refuse a trusted network holding the gateway.
	if _, err := control.CheckProxyTrust(trusted, []netip.Addr{gateway}); err != nil {
		t.Fatal(err)
	}
	if _, err := control.CheckProxyTrust([]netip.Prefix{subnet}, []netip.Addr{gateway}); err == nil {
		t.Fatal("trusting the whole subnet is not refused")
	}
	// Every TLS front replaces a client-sent X-Forwarded-For.
	for _, name := range []string{"../Caddyfile", "Caddyfile.public"} {
		raw, err := os.ReadFile(name)
		if err != nil || !strings.Contains(string(raw), "header_up X-Forwarded-For {remote_host}") {
			t.Errorf("%s does not replace X-Forwarded-For: %v", name, err)
		}
	}
	// The public override keeps the network and the address.
	raw, _ = os.ReadFile("compose.public.yaml")
	if strings.Contains(string(raw), "networks") || strings.Contains(string(raw), "ipv4_address") {
		t.Fatal("compose.public.yaml changes the TLS front's network")
	}
}

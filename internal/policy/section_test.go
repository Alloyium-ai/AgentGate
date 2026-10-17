// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import "testing"

func TestNetworkComponentUsesTheSharedSchemaAndSemanticChecks(t *testing.T) {
	fixture := func() Network { return *fullFixture().Network }
	if err := ValidateNetworkSection(fixture()); err != nil {
		t.Fatal(err)
	}
	empty := fixture()
	empty.Rules = nil
	if err := ValidateNetworkSection(empty); err != nil {
		t.Fatal("empty permissions must remain an explicit deny section", err)
	}
	for _, change := range []func(*Network){
		func(n *Network) { n.Default = "allow" },
		func(n *Network) { n.DNS.ResolverProfile = "agent-resolver" },
		func(n *Network) { n.Rules[0].PortFrom = 65536 },
		func(n *Network) { n.Rules[0].PortFrom = 444; n.Rules[0].PortTo = 443 },
		func(n *Network) { n.Rules = append(n.Rules, n.Rules[0]) },
		func(n *Network) { n.Rules[0].Destination = Destination{"ip", "127.0.0.1"} },
		func(n *Network) { n.Rules[0].Destination = Destination{"hostname", "Mixed.Example.test"} },
	} {
		network := fixture()
		change(&network)
		if err := ValidateNetworkSection(network); err == nil {
			t.Fatal("a network component bypassed the shared contract")
		}
	}
}

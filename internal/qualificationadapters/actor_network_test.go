// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"net/netip"
	"testing"

	"alloyium.local/kernel-poc/internal/policy"
)

func TestFixedActorEndpointRequiresExactSignedTaskboardException(t *testing.T) {
	network := &policy.Network{Pilot: &policy.PilotNetwork{Mode: "ssh-coding.v1", TaskboardIP: "10.77.0.2", TaskboardPort: 18080, TaskboardTaskID: 42},
		Rules: []policy.NetworkRule{{ID: "board", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "ip", Value: "10.77.0.2"}, PortFrom: 18080, PortTo: 18080, Effect: "allow"}}}
	endpoint, err := pilotActorEndpoint(network)
	if err != nil || endpoint.Family != 4 || endpoint.Port != 18080 || endpoint.Address[0] != 10 || endpoint.Address[1] != 77 || endpoint.Address[2] != 0 || endpoint.Address[3] != 2 {
		t.Fatal("the exact policy exception was not bound to the fixed actor", endpoint, err)
	}
	for name, change := range map[string]func(*policy.Network){
		"wrong port":        func(n *policy.Network) { n.Rules[0].PortTo++ },
		"wrong destination": func(n *policy.Network) { n.Rules[0].Destination.Value = "10.77.0.3" },
		"deny rule":         func(n *policy.Network) { n.Rules[0].Effect = "deny" },
		"mapped bypass":     func(n *policy.Network) { n.Pilot.TaskboardIP = "::ffff:10.77.0.2" },
	} {
		t.Run(name, func(t *testing.T) {
			copyNetwork := *network
			copyPilot := *network.Pilot
			copyNetwork.Pilot = &copyPilot
			copyNetwork.Rules = append([]policy.NetworkRule(nil), network.Rules...)
			change(&copyNetwork)
			if _, err := pilotActorEndpoint(&copyNetwork); err == nil {
				t.Fatal("an unsigned endpoint entered the fixed actor wire")
			}
		})
	}
	copyNetwork := *network
	copyPilot := *network.Pilot
	copyNetwork.Pilot = &copyPilot
	copyNetwork.Pilot.TaskboardIP = "fc00::2"
	copyNetwork.Rules = []policy.NetworkRule{{ID: "board6", Family: "ipv6", Protocol: "tcp", Destination: policy.Destination{Kind: "ip", Value: "fc00::2"}, PortFrom: 18080, PortTo: 18080, Effect: "allow"}}
	endpoint, err = pilotActorEndpoint(&copyNetwork)
	if err != nil || endpoint.Family != 6 || endpoint.Address != netip.MustParseAddr("fc00::2").As16() {
		t.Fatal("the exact IPv6 exception was not encoded", endpoint, err)
	}
	if empty, err := pilotActorEndpoint(nil); err != nil || empty != (actorEndpoint{}) {
		t.Fatal("a nonpilot candidate gained an endpoint", empty, err)
	}
}

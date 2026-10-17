// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestSocketRulesRoundTripAndRequireExplicitSelectors(t *testing.T) {
	fixture := func() SocketPolicy {
		return SocketPolicy{Default: "deny", Rules: []SocketRule{{ID: "local-tcp", Family: "ipv4", Protocol: "tcp", Operations: []string{"create", "bind", "listen", "get_option"}, Effect: "allow", Local: &SocketLocal{Address: "127.0.0.1", PortFrom: 18000, PortTo: 18010}, Options: []SocketOption{{Level: 1, Name: 4}}}}}
	}
	document := fullFixture()
	sockets := fixture()
	document.Sockets = &sockets
	document.RequiredCapabilities, _ = Requirements(document)
	raw, _ := json.Marshal(document)
	parsed, err := Parse(raw, "json")
	if err != nil || !reflect.DeepEqual(document, parsed) {
		t.Fatal("socket policy fields failed to round-trip", err)
	}
	for _, capability := range []string{"socket.rules.v1", "socket.ipv4.v1", "socket.create.v1", "socket.bind.v1", "socket.listen.v1", "socket.get_option.v1"} {
		if !hasOperation(document.RequiredCapabilities, capability) {
			t.Fatal("missing socket capability", capability)
		}
	}
	empty := SocketPolicy{Default: "deny"}
	if err = ValidateSocketSection(empty); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*SocketPolicy){
		func(s *SocketPolicy) { s.Default = "allow" },
		func(s *SocketPolicy) { s.Rules[0].Local = nil },
		func(s *SocketPolicy) { s.Rules[0].Options = nil },
		func(s *SocketPolicy) { s.Rules[0].Options = append(s.Rules[0].Options, s.Rules[0].Options[0]) },
		func(s *SocketPolicy) { s.Rules[0].Local.Address = "::1" },
		func(s *SocketPolicy) { s.Rules[0].Local.PortFrom = 19000 },
		func(s *SocketPolicy) { s.Rules[0].Operations = []string{"unknown"} },
	} {
		sockets := fixture()
		change(&sockets)
		if err = ValidateSocketSection(sockets); err == nil {
			t.Fatal("an implicit or invalid socket rule passed")
		}
	}
	document.Sockets = nil
	raw, _ = json.Marshal(document)
	if _, err = Parse(raw, "json"); err == nil {
		t.Fatal("a full document omitted its default-deny socket section")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package netrules

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"

	"alloyium.local/kernel-poc/internal/policy"
)

func socketRule(id, family, protocol, effect string, operations ...string) policy.SocketRule {
	return policy.SocketRule{ID: id, Family: family, Protocol: protocol, Effect: effect, Operations: operations}
}
func socketPolicy(rules ...policy.SocketRule) policy.SocketPolicy {
	return policy.SocketPolicy{Default: "deny", Rules: rules}
}
func socketPlan(t *testing.T, rules ...policy.SocketRule) SocketPlan {
	t.Helper()
	compiled, err := CompileSockets(socketPolicy(rules...), 7, 100, 1000)
	if err != nil {
		t.Fatal(err)
	}
	return compiled.Plan
}
func TestSocketABI(t *testing.T) {
	if SocketCreate != 1 || SocketGetOption != 1024 || binary.Size(SocketOptionPlan{}) != 4 || binary.Size(SocketRulePlan{}) != 100 || binary.Size(SocketPlan{}) != 12824 {
		t.Fatal("socket map ABI changed")
	}
}
func TestSocketDenyDefaultsAndExpiry(t *testing.T) {
	op := SocketOperation{Family: 2, Protocol: TCP, Operation: SocketCreate}
	if EvaluateSocket(socketPlan(t), op, 200).Allowed {
		t.Fatal("empty socket rules allowed create")
	}
	plan := socketPlan(t, socketRule("create", "ipv4", "tcp", "allow", "create"))
	if !EvaluateSocket(plan, op, 999).Allowed || EvaluateSocket(plan, op, 1000).Allowed {
		t.Fatal("socket expiry is not exclusive")
	}
	for _, bit := range []uint32{SocketBind, SocketListen, SocketAccept, SocketSend, SocketReceive, SocketGetLocalName, SocketGetPeerName, SocketShutdown, SocketSetOption, SocketGetOption} {
		op.Operation = bit
		if EvaluateSocket(plan, op, 200).Allowed {
			t.Fatal("create permission granted another operation", bit)
		}
	}
	op.Operation = SocketCreate
	op.Protocol = UDP
	if EvaluateSocket(plan, op, 200).Allowed {
		t.Fatal("TCP create granted UDP create")
	}
	op.Protocol = TCP
	op.Family = 1
	if EvaluateSocket(plan, op, 200).Allowed {
		t.Fatal("IPv4 create granted UNIX create")
	}
}
func TestSocketLocalPrecedenceAndDenyTies(t *testing.T) {
	broad := socketRule("broad", "ipv4", "tcp", "deny", "receive")
	allow := socketRule("local", "ipv4", "tcp", "allow", "receive")
	allow.Local = &policy.SocketLocal{Address: "127.0.0.1", PortFrom: 100, PortTo: 200}
	deny := socketRule("exact", "ipv4", "tcp", "deny", "receive")
	deny.Local = &policy.SocketLocal{Address: "127.0.0.1", PortFrom: 150, PortTo: 150}
	tie := deny
	tie.ID = "tie"
	tie.Effect = "allow"
	plan := socketPlan(t, broad, allow, deny, tie)
	op := SocketOperation{Family: 2, Protocol: TCP, Operation: SocketReceive, HasLocal: true, LocalAddress: addressBytes(netip.MustParseAddr("127.0.0.1"))}
	for _, test := range []struct {
		port  uint16
		allow bool
	}{{99, false}, {100, true}, {149, true}, {150, false}, {151, true}, {201, false}} {
		op.LocalPort = test.port
		if EvaluateSocket(plan, op, 200).Allowed != test.allow {
			t.Fatal(test)
		}
	}
	op.LocalPort = 100
	op.LocalAddress = addressBytes(netip.MustParseAddr("127.0.0.2"))
	if EvaluateSocket(plan, op, 200).Allowed {
		t.Fatal("a local selector matched another address")
	}
}
func TestSocketOptionsRequireExplicitSupportedPairs(t *testing.T) {
	rule := socketRule("options", "ipv4", "tcp", "allow", "get_option")
	rule.Options = []policy.SocketOption{{Level: 1, Name: 3}, {Level: 1, Name: 4}}
	plan := socketPlan(t, rule)
	op := SocketOperation{Family: 2, Protocol: TCP, Operation: SocketGetOption, Option: SocketOptionPlan{Level: 1, Name: 3}}
	if !EvaluateSocket(plan, op, 200).Allowed {
		t.Fatal("explicit supported getter denied")
	}
	op.Option.Name = 6
	if EvaluateSocket(plan, op, 200).Allowed {
		t.Fatal("getter allowance granted broadcast")
	}
	op.Option.Name = 3
	op.Operation = SocketSetOption
	if EvaluateSocket(plan, op, 200).Allowed {
		t.Fatal("getter granted setter")
	}
	rule.Operations = []string{"set_option"}
	if _, err := CompileSockets(socketPolicy(rule), 7, 100, 1000); err == nil {
		t.Fatal("allowed SO_TYPE setter")
	}
	rule.Options = []policy.SocketOption{{Level: 1, Name: 6}}
	if _, err := CompileSockets(socketPolicy(rule), 7, 100, 1000); err == nil {
		t.Fatal("allowed unsupported broadcast option")
	}
	rule.Options = nil
	if _, err := CompileSockets(socketPolicy(rule), 7, 100, 1000); err == nil {
		t.Fatal("allowed implicit option list")
	}
}
func TestSocketUnsupportedAllowAndRequiredLocal(t *testing.T) {
	for _, rule := range []policy.SocketRule{
		socketRule("unix", "unix", "stream", "allow", "create"), socketRule("raw", "ipv4", "raw", "allow", "create"),
		socketRule("netlink", "netlink", "raw", "allow", "create"), socketRule("packet", "packet", "raw", "allow", "create"),
		socketRule("bind", "ipv4", "tcp", "allow", "bind"), socketRule("listen", "ipv6", "tcp", "allow", "listen"), socketRule("accept", "ipv4", "tcp", "allow", "accept"),
	} {
		if _, err := CompileSockets(socketPolicy(rule), 7, 100, 1000); err == nil {
			t.Fatalf("accepted unsupported allowance %+v", rule)
		}
	}
	udp := socketRule("udp-listen", "ipv4", "udp", "allow", "listen")
	udp.Local = &policy.SocketLocal{Address: "127.0.0.1", PortFrom: 0, PortTo: 65535}
	if _, err := CompileSockets(socketPolicy(udp), 7, 100, 1000); err == nil {
		t.Fatal("allowed UDP listen")
	}
	for _, family := range []string{"unix", "netlink", "packet"} {
		protocol := "raw"
		if family == "unix" {
			protocol = "stream"
		}
		if _, err := CompileSockets(socketPolicy(socketRule("deny", family, protocol, "deny", "create")), 7, 100, 1000); err != nil {
			t.Fatal("deny-only family rejected", family, err)
		}
	}
}
func TestSocketCompilerOrderAndOptionLimit(t *testing.T) {
	a := socketRule("a", "ipv4", "tcp", "allow", "get_option")
	a.Options = []policy.SocketOption{{Level: 1, Name: 4}, {Level: 1, Name: 3}}
	b := socketRule("b", "ipv6", "udp", "allow", "create")
	first, err := CompileSockets(socketPolicy(a, b), 7, 100, 1000)
	if err != nil {
		t.Fatal(err)
	}
	a.Options[0], a.Options[1] = a.Options[1], a.Options[0]
	second, err := CompileSockets(socketPolicy(b, a), 7, 100, 1000)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("source order changed the socket plan", err)
	}
	a.Options = make([]policy.SocketOption, MaxSocketOptions+1)
	for i := range a.Options {
		a.Options[i] = policy.SocketOption{Level: 1, Name: i + 1}
	}
	if _, err := CompileSockets(socketPolicy(a), 7, 100, 1000); err == nil {
		t.Fatal("option overflow accepted")
	}
}

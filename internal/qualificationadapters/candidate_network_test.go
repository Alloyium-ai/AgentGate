// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/dnslease/fixture"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
)

func TestFixedActorUsesOnlyPinnedPilotLeases(t *testing.T) {
	address := [4]byte{93, 184, 215, 14}
	server, err := fixture.Start(func(wire []byte) ([]byte, error) {
		var query dnsmessage.Message
		if err := query.Unpack(wire); err != nil {
			return nil, err
		}
		question := query.Questions[0]
		answer := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 30}, Body: &dnsmessage.AResource{A: address}}
		response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true}, Questions: query.Questions, Answers: []dnsmessage.Resource{answer}}
		return response.Pack()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	resolver, err := dnslease.NewTLSResolver(server.Config(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	network := policy.Network{Default: "deny", DNS: policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"},
		Pilot: &policy.PilotNetwork{Mode: "ssh-coding.v1", TaskboardIP: "10.77.0.2", TaskboardPort: 18080, TaskboardTaskID: 42},
		Rules: []policy.NetworkRule{
			{ID: "task", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "ip", Value: "10.77.0.2"}, PortFrom: 18080, PortTo: 18080, Effect: "allow"},
			{ID: "web", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: "example.org"}, PortFrom: 443, PortTo: 443, Effect: "allow"},
		}}
	request := qualification.Request{Document: policy.Document{Network: &network}, Binding: qualification.Binding{PolicyDigest: strings.Repeat("a", 64), Challenge: "owned-fixed-network", ArtifactDigests: map[string]string{"resolver": noderuntime.ResolverDigest(resolver.Evidence())}}}
	now, err := kernel.MonotonicNS()
	if err != nil {
		t.Fatal(err)
	}
	deadline := now + uint64(20*time.Second)
	if _, err := (&candidateDenial{}).candidateNetwork(context.Background(), request, 42, 1, deadline); err == nil {
		t.Fatal("a hostname rule passed without the pinned resolver")
	}
	adapter := &candidateDenial{resolver: resolver}
	got, err := adapter.candidateNetwork(context.Background(), request, 42, 1, deadline)
	if err != nil || len(got.Leases) != 1 || got.SnapshotDigest == "" {
		t.Fatal("the fixed actor did not bind the trusted pilot lease", err)
	}
	receipt := candidateReceipt{Network: got, Generation: 1, DeadlineNS: deadline, HeldBefore: processSnapshot{MonoNS: got.ResolvedNS + 1}}
	if err := adapter.verifyCandidateNetwork(request, receipt); err != nil {
		t.Fatal(err)
	}
	receipt.Network.Leases[0].Address = receipt.Network.Leases[0].Address.Next()
	if err := adapter.verifyCandidateNetwork(request, receipt); err == nil {
		t.Fatal("a changed lease passed fixed actor verification")
	}
	address = [4]byte{10, 77, 0, 1}
	if _, err := adapter.candidateNetwork(context.Background(), request, 42, 1, deadline); err == nil {
		t.Fatal("a private trusted DNS answer passed the pilot compiler")
	}
}

func TestPilotDirectAddressBoundaryRequiresLiveDenialAndExactCompilerRejection(t *testing.T) {
	network := policy.Network{Default: "deny", DNS: policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"},
		Pilot: &policy.PilotNetwork{Mode: "ssh-coding.v1", TaskboardIP: "10.77.0.2", TaskboardPort: 18080, TaskboardTaskID: 42},
		Rules: []policy.NetworkRule{
			{ID: "sample", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: "example.org"}, PortFrom: 443, PortTo: 443, Effect: "allow"},
			{ID: "board", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "ip", Value: "10.77.0.2"}, PortFrom: 18080, PortTo: 18080, Effect: "allow"},
		}}
	request := qualification.Request{Document: policy.Document{Network: &network}}
	receipt := candidateReceipt{Active: processSnapshot{MonoNS: 100}}
	check := func(raw bool) bool {
		cases := map[string][]string{}
		if raw {
			cases["net.ssh-lan-boundary.v1"] = []string{"private-ipv4-denied"}
		}
		pilotDirectAddressBoundaryCases(request, receipt, cases)
		return slices.Contains(cases["net.ssh-lan-boundary.v1"], "direct-address-bypass-denied")
	}
	if !check(true) {
		t.Fatal("the raw literal denial and exact-policy compiler rejection earned no case")
	}
	if check(false) {
		t.Fatal("the missing live literal denial gained direct-address case credit")
	}
	network.Rules[0].Destination = policy.Destination{Kind: "ip", Value: "93.184.215.14"}
	if check(true) {
		t.Fatal("a literal replacement of the hostname gained direct-address case credit")
	}
	network.Rules[0].Destination = policy.Destination{Kind: "hostname", Value: "example.org"}
	network.Pilot = nil
	if check(true) {
		t.Fatal("a nonpilot policy gained direct-address case credit")
	}
}

func TestFixedNetworkCreditNeedsLiveKernelDecisionAndSameActorResult(t *testing.T) {
	network := policy.Network{Default: "deny", DNS: policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"},
		Pilot: &policy.PilotNetwork{Mode: "ssh-coding.v1", TaskboardIP: "10.77.0.2", TaskboardPort: 18080, TaskboardTaskID: 42},
		Rules: []policy.NetworkRule{{ID: "board", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "ip", Value: "10.77.0.2"}, PortFrom: 18080, PortTo: 18080, Effect: "allow"}}}
	compiled, err := netrules.Compile(network, 1, 50, 10_000, nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt := candidateReceipt{DomainID: 42, Generation: 1, DeadlineNS: 10_000,
		HeldInstalled: processSnapshot{MonoNS: 80}, Active: processSnapshot{PID: 7, MonoNS: 100},
		Before: mapSnapshot{Peers: compiled.Policy}, Streams: map[string][][]byte{}}
	peer := func(hook uint32, mono uint64) []byte {
		b := make([]byte, 96)
		binary.LittleEndian.PutUint64(b[8:], 1)
		binary.LittleEndian.PutUint64(b[16:], 42)
		binary.LittleEndian.PutUint64(b[24:], 42)
		binary.LittleEndian.PutUint64(b[32:], mono)
		if hook == 1 {
			binary.LittleEndian.PutUint32(b[40:], 7)
			binary.LittleEndian.PutUint32(b[44:], 65534)
		}
		binary.LittleEndian.PutUint32(b[48:], hook)
		binary.LittleEndian.PutUint32(b[52:], 1)
		binary.LittleEndian.PutUint32(b[56:], compiled.Policy.Rules[0].Index)
		binary.LittleEndian.PutUint32(b[60:], 4)
		binary.LittleEndian.PutUint32(b[64:], 6)
		binary.LittleEndian.PutUint32(b[68:], 18080)
		copy(b[72:], []byte{10, 77, 0, 2})
		return b
	}
	receipt.Streams["peers"] = [][]byte{peer(1, 200), peer(5, 250), peer(6, 260)}
	request := qualification.Request{Document: policy.Document{Network: &network}}
	calls := []syscallrules.Event{
		{Sequence: 1, Type: syscallrules.Result, SyscallID: unix.SYS_SECCOMP, Result: 0, MonoNS: 90},
		{Sequence: 2, Type: syscallrules.Result, SyscallID: unix.SYS_CONNECT, Result: -int64(unix.EINPROGRESS), MonoNS: 300,
			TGID: 7, TID: 7, UID: 65534, Domain: 42, Cgroup: 42, Generation: 1, BindingState: syscallrules.Live},
	}
	check := func() bool { return len(positiveNetworkCases(request, receipt, calls)["net.ssh-lan-boundary.v1"]) == 1 }
	if !check() {
		t.Fatal("the live exact endpoint and reply stream gained no fixed observation")
	}
	for name, change := range map[string]func(){
		"foreign address": func() { receipt.Streams["peers"][0][72]++ },
		"foreign rule":    func() { binary.LittleEndian.PutUint32(receipt.Streams["peers"][0][56:], 99) },
		"foreign actor":   func() { calls[1].TGID++ },
		"denied call":     func() { calls[1].Result = -int64(unix.EPERM) },
		"late call":       func() { calls[1].MonoNS = receipt.DeadlineNS },
	} {
		t.Run(name, func(t *testing.T) {
			receipt.Streams["peers"] = [][]byte{peer(1, 200), peer(5, 250), peer(6, 260)}
			calls[1].TGID = 7
			calls[1].Result = -int64(unix.EINPROGRESS)
			calls[1].MonoNS = 300
			change()
			if check() {
				t.Fatal("a changed actor, endpoint or result gained taskboard credit")
			}
		})
	}
}

func TestOwnedLoopbackDenialNeedsSameActorKernelAndSyscallProof(t *testing.T) {
	network := policy.Network{Default: "deny", DNS: policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"},
		Pilot: &policy.PilotNetwork{Mode: "ssh-coding.v1", TaskboardIP: "10.77.0.2", TaskboardPort: 18080, TaskboardTaskID: 42},
		Rules: []policy.NetworkRule{{ID: "board", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "ip", Value: "10.77.0.2"}, PortFrom: 18080, PortTo: 18080, Effect: "allow"}}}
	compiled, err := netrules.Compile(network, 1, 50, 10_000, nil)
	if err != nil {
		t.Fatal(err)
	}
	receipt := candidateReceipt{DomainID: 42, Generation: 1, DeadlineNS: 10_000,
		HeldInstalled: processSnapshot{MonoNS: 80}, Active: processSnapshot{PID: 7, MonoNS: 100},
		Before: mapSnapshot{Peers: compiled.Policy}, Streams: map[string][][]byte{}}
	peer := make([]byte, 96)
	binary.LittleEndian.PutUint64(peer[8:], 1)
	binary.LittleEndian.PutUint64(peer[16:], 42)
	binary.LittleEndian.PutUint64(peer[24:], 42)
	binary.LittleEndian.PutUint64(peer[32:], 200)
	binary.LittleEndian.PutUint32(peer[40:], 7)
	binary.LittleEndian.PutUint32(peer[44:], 65534)
	binary.LittleEndian.PutUint32(peer[48:], 1)
	binary.LittleEndian.PutUint32(peer[60:], 4)
	binary.LittleEndian.PutUint32(peer[64:], netrules.TCP)
	binary.LittleEndian.PutUint32(peer[68:], 18080)
	binary.LittleEndian.PutUint32(peer[92:], compiled.Policy.Reserved)
	copy(peer[72:], []byte{127, 0, 0, 1})
	receipt.Streams["peers"] = [][]byte{peer}
	records := map[uint32]scalarRecord{60: {ID: 60, Result: 5}, 61: {ID: 61, Result: -1, Error: uint32(unix.EPERM)}}
	calls := []syscallrules.Event{
		{Sequence: 1, Type: syscallrules.Result, SyscallID: unix.SYS_SECCOMP, Result: 0, MonoNS: 90},
		{Sequence: 2, Type: syscallrules.Result, SyscallID: unix.SYS_CONNECT, Result: -int64(unix.EPERM), MonoNS: 250,
			TGID: 7, TID: 7, UID: 65534, Domain: 42, Cgroup: 42, Generation: 1, BindingState: syscallrules.Live},
	}
	request := qualification.Request{Document: policy.Document{Network: &network}}
	check := func() bool {
		return len(ownedLoopbackDenialCases(request, receipt, calls, records)["net.ssh-lan-boundary.v1"]) == 1
	}
	if !check() {
		t.Fatal("the exact loopback denial gained no same-actor observation")
	}
	for name, change := range map[string]func(){
		"allowed peer":    func() { binary.LittleEndian.PutUint32(peer[52:], 1) },
		"foreign address": func() { peer[72]++ },
		"foreign actor":   func() { calls[1].TGID++ },
		"successful call": func() { calls[1].Result = 0 },
		"stale call":      func() { calls[1].MonoNS = receipt.DeadlineNS },
		"missing record":  func() { records[61] = scalarRecord{} },
	} {
		t.Run(name, func(t *testing.T) {
			binary.LittleEndian.PutUint32(peer[52:], 0)
			peer[72] = 127
			calls[1].TGID = 7
			calls[1].Result = -int64(unix.EPERM)
			calls[1].MonoNS = 250
			records[61] = scalarRecord{ID: 61, Result: -1, Error: uint32(unix.EPERM)}
			change()
			if check() {
				t.Fatal("a changed loopback witness gained LAN denial credit")
			}
		})
	}
}

func TestIPv6SocketFamilyDenialNeedsKernelAndSameActorSyscall(t *testing.T) {
	receipt := candidateReceipt{DomainID: 42, Generation: 1, DeadlineNS: 10_000,
		Active:  processSnapshot{PID: 7, MonoNS: 100},
		Before:  mapSnapshot{Sockets: netrules.SocketPlan{Generation: 1, ExpiresNS: 10_000}},
		Streams: map[string][][]byte{}}
	event := make([]byte, 112)
	binary.LittleEndian.PutUint64(event[8:], 1)
	binary.LittleEndian.PutUint64(event[16:], 42)
	binary.LittleEndian.PutUint64(event[24:], 42)
	binary.LittleEndian.PutUint64(event[32:], 200)
	binary.LittleEndian.PutUint32(event[48:], 7)
	binary.LittleEndian.PutUint32(event[52:], 65534)
	binary.LittleEndian.PutUint32(event[56:], netrules.SocketCreate)
	binary.LittleEndian.PutUint32(event[68:], 10)
	binary.LittleEndian.PutUint32(event[72:], netrules.TCP)
	binary.LittleEndian.PutUint32(event[88:], 1)
	receipt.Streams["sockets"] = [][]byte{event}
	records := map[uint32]scalarRecord{62: {ID: 62, Result: -1, Error: uint32(unix.EPERM)}, 63: {ID: 63, Result: -2}}
	calls := []syscallrules.Event{
		{Sequence: 1, Type: syscallrules.Result, SyscallID: unix.SYS_SECCOMP, Result: 0, MonoNS: 90},
		{Sequence: 2, Type: syscallrules.Result, SyscallID: unix.SYS_SOCKET, Result: -int64(unix.EPERM), MonoNS: 250,
			TGID: 7, TID: 7, UID: 65534, Domain: 42, Cgroup: 42, Generation: 1, BindingState: syscallrules.Live},
	}
	request := qualification.Request{Document: policy.Document{Sockets: &policy.SocketPolicy{Default: "deny"}}}
	check := func() bool {
		got := deniedIPv6SocketCases(request, receipt, calls, records)
		return len(got["socket.ipv4.v1"]) == 1 && len(got["socket.create.v1"]) == 1
	}
	if !check() {
		t.Fatal("the live IPv6 socket denial gained no fixed observation")
	}
	wholeFamily := deniedIPv6SocketCases(request, receipt, calls, records)
	pilotIPv6FamilyBoundaryCases(request, receipt, wholeFamily)
	if len(wholeFamily["net.ssh-lan-boundary.v1"]) != 0 {
		t.Fatal("a nonpilot IPv6 denial gained pilot LAN credit")
	}
	request.Document.Network = &policy.Network{Pilot: &policy.PilotNetwork{Mode: "ssh-coding.v1", TaskboardIP: "10.77.0.2", TaskboardPort: 18080, TaskboardTaskID: 42}}
	receipt.Before.Peers.PilotMode = 1
	wholeFamily = deniedIPv6SocketCases(request, receipt, calls, records)
	wholeFamily["net.ssh-lan-boundary.v1"] = []string{"taskboard-exact-endpoint-allowed"}
	pilotIPv6FamilyBoundaryCases(request, receipt, wholeFamily)
	if len(wholeFamily["net.ssh-lan-boundary.v1"]) != 2 ||
		wholeFamily["net.ssh-lan-boundary.v1"][0] != "taskboard-exact-endpoint-allowed" ||
		len(wholeFamily["net.rules.v1"]) != 0 {
		t.Fatal("the pilot whole-family denial gained wrong LAN or peer-map credit")
	}
	udpPlan, err := netrules.CompileSockets(policy.SocketPolicy{Default: "deny", Rules: []policy.SocketRule{
		{ID: "udp6", Family: "ipv6", Protocol: "udp", Effect: "allow", Operations: []string{"create"}},
	}}, 1, 50, receipt.DeadlineNS)
	if err != nil {
		t.Fatal(err)
	}
	beforeSockets := receipt.Before.Sockets
	receipt.Before.Sockets = udpPlan.Plan
	udpOpen := deniedIPv6SocketCases(request, receipt, calls, records)
	pilotIPv6FamilyBoundaryCases(request, receipt, udpOpen)
	if len(udpOpen["net.ssh-lan-boundary.v1"]) != 0 {
		t.Fatal("an allowed IPv6 UDP socket gained whole-family LAN credit")
	}
	receipt.Before.Sockets = beforeSockets
	for name, change := range map[string]func(){
		"allowed event":   func() { binary.LittleEndian.PutUint32(event[60:], 1) },
		"wrong family":    func() { binary.LittleEndian.PutUint32(event[68:], 2) },
		"foreign actor":   func() { calls[1].TGID++ },
		"successful call": func() { calls[1].Result = 0 },
		"stale event":     func() { binary.LittleEndian.PutUint64(event[32:], receipt.DeadlineNS) },
		"missing record":  func() { records[62] = scalarRecord{} },
	} {
		t.Run(name, func(t *testing.T) {
			binary.LittleEndian.PutUint32(event[60:], 0)
			binary.LittleEndian.PutUint32(event[68:], 10)
			binary.LittleEndian.PutUint64(event[32:], 200)
			calls[1].TGID = 7
			calls[1].Result = -int64(unix.EPERM)
			records[62] = scalarRecord{ID: 62, Result: -1, Error: uint32(unix.EPERM)}
			change()
			if check() {
				t.Fatal("a changed IPv6 socket witness gained denial credit")
			}
			changed := deniedIPv6SocketCases(request, receipt, calls, records)
			pilotIPv6FamilyBoundaryCases(request, receipt, changed)
			if len(changed["net.ssh-lan-boundary.v1"]) != 0 {
				t.Fatal("a changed IPv6 socket witness gained pilot LAN credit")
			}
		})
	}
}

func TestIPv4SocketOwnershipNeedsCreatePostCreateAndSyscall(t *testing.T) {
	sockets := policy.SocketPolicy{Default: "deny", Rules: []policy.SocketRule{{ID: "tcp4", Family: "ipv4", Protocol: "tcp", Effect: "allow", Operations: []string{"create"}}}}
	compiled, err := netrules.CompileSockets(sockets, 1, 50, 10_000)
	if err != nil {
		t.Fatal(err)
	}
	receipt := candidateReceipt{DomainID: 42, Generation: 1, DeadlineNS: 10_000,
		Active: processSnapshot{PID: 7, MonoNS: 100}, Before: mapSnapshot{Sockets: compiled.Plan}, Streams: map[string][][]byte{}}
	makeEvent := func(sequence uint64, source uint32, owner uint64, mono uint64) []byte {
		raw := make([]byte, 112)
		binary.LittleEndian.PutUint64(raw[0:], sequence)
		binary.LittleEndian.PutUint64(raw[8:], 1)
		binary.LittleEndian.PutUint64(raw[16:], 42)
		binary.LittleEndian.PutUint64(raw[24:], 42)
		binary.LittleEndian.PutUint64(raw[32:], mono)
		binary.LittleEndian.PutUint64(raw[40:], owner)
		binary.LittleEndian.PutUint32(raw[48:], 7)
		binary.LittleEndian.PutUint32(raw[52:], 65534)
		binary.LittleEndian.PutUint32(raw[56:], netrules.SocketCreate)
		binary.LittleEndian.PutUint32(raw[60:], 1)
		binary.LittleEndian.PutUint32(raw[64:], 1)
		binary.LittleEndian.PutUint32(raw[68:], 2)
		binary.LittleEndian.PutUint32(raw[72:], netrules.TCP)
		binary.LittleEndian.PutUint32(raw[88:], source)
		return raw
	}
	created, owned := makeEvent(1, 1, 0, 200), makeEvent(2, 5, 42, 210)
	receipt.Streams["sockets"] = [][]byte{created, owned}
	records := map[uint32]scalarRecord{60: {ID: 60, Result: 5}}
	calls := []syscallrules.Event{
		{Sequence: 1, Type: syscallrules.Result, SyscallID: unix.SYS_SECCOMP, Result: 0, MonoNS: 90},
		{Sequence: 2, Type: syscallrules.Result, SyscallID: unix.SYS_SOCKET, Result: 5, MonoNS: 250,
			TGID: 7, TID: 7, UID: 65534, Domain: 42, Cgroup: 42, Generation: 1, BindingState: syscallrules.Live},
	}
	request := qualification.Request{Document: policy.Document{Sockets: &sockets}}
	check := func() bool {
		got := allowedIPv4SocketCases(request, receipt, calls, records)
		return len(got["socket.ipv4.v1"]) == 1 && len(got["socket.create.v1"]) == 2
	}
	if !check() {
		t.Fatal("the same actor's created and owned socket gained no observation")
	}
	for name, change := range map[string]func(){
		"foreign owner":  func() { binary.LittleEndian.PutUint64(owned[40:], 43) },
		"missing post":   func() { receipt.Streams["sockets"] = [][]byte{created} },
		"wrong family":   func() { binary.LittleEndian.PutUint32(created[68:], 10) },
		"foreign actor":  func() { calls[1].TGID++ },
		"denied syscall": func() { calls[1].Result = -int64(unix.EPERM) },
	} {
		t.Run(name, func(t *testing.T) {
			binary.LittleEndian.PutUint64(owned[40:], 42)
			binary.LittleEndian.PutUint32(created[68:], 2)
			receipt.Streams["sockets"] = [][]byte{created, owned}
			calls[1].TGID = 7
			calls[1].Result = 5
			change()
			if check() {
				t.Fatal("a changed create, ownership or syscall witness gained credit")
			}
		})
	}
}

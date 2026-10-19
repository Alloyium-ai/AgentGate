// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"slices"
	"time"

	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/nodedns"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"golang.org/x/sys/unix"
)

// This receipt only permits the fixed actor to execute core controls with the
// candidate's actual endpoint map. It does not prove a positive network case.
type candidateNetworkReceipt struct {
	ResolverDigest string            `json:"resolver_digest,omitempty"`
	SnapshotDigest string            `json:"snapshot_digest,omitempty"`
	ResolvedNS     uint64            `json:"resolved_ns,string,omitempty"`
	Records        []dnslease.Record `json:"records,omitempty"`
	Leases         []netrules.Lease  `json:"leases,omitempty"`
}

func (a *candidateDenial) candidateNetwork(ctx context.Context, request qualification.Request, domain, generation, deadline uint64) (candidateNetworkReceipt, error) {
	var out candidateNetworkReceipt
	if request.Document.Network == nil || !pilotAllowedHosts(*request.Document.Network) {
		return out, nil
	}
	if a.resolver == nil || request.Binding.ArtifactDigests["resolver"] != noderuntime.ResolverDigest(a.resolver.Evidence()) {
		return out, errors.New("the fixed actor lacks the candidate's pinned resolver")
	}
	binding := dnslease.Binding{JobID: "qualification-fixed:" + request.Binding.Challenge, DomainID: domain,
		Generation: generation, DeadlineNS: deadline, PolicySHA256: request.Binding.PolicyDigest}
	coordinator, err := nodedns.New(nodedns.Config{Binding: binding, Network: *request.Document.Network,
		Resolver: a.resolver, Now: kernel.MonotonicNS})
	if err != nil {
		return out, err
	}
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	snapshot, err := coordinator.ResolveAll(bounded)
	if err != nil {
		return out, err
	}
	now, err := kernel.MonotonicNS()
	if err != nil || snapshot.Check(binding, dnslease.NetworkDigest(*request.Document.Network), a.resolver.Evidence(), 0, now) != nil {
		return out, errors.New("the fixed actor's trusted lease snapshot changed or expired")
	}
	out.ResolverDigest = noderuntime.ResolverDigest(a.resolver.Evidence())
	out.SnapshotDigest = snapshot.Digest()
	out.ResolvedNS = now
	out.Records = snapshot.Records()
	out.Leases = make([]netrules.Lease, 0, len(out.Records))
	for _, record := range out.Records {
		out.Leases = append(out.Leases, netrules.Lease{RuleID: record.RuleID, Hostname: record.Hostname,
			Address: record.Address, Chain: append([]string(nil), record.Chain...), ExpiresNS: record.ExpiresNS})
	}
	return out, nil
}

func (a *candidateDenial) verifyCandidateNetwork(request qualification.Request, receipt candidateReceipt) error {
	network := request.Document.Network
	if network == nil || !pilotAllowedHosts(*network) {
		if receipt.Network.ResolverDigest != "" || receipt.Network.SnapshotDigest != "" || receipt.Network.ResolvedNS != 0 || len(receipt.Network.Records) != 0 || len(receipt.Network.Leases) != 0 {
			return errors.New("the fixed actor introduced a network lease")
		}
		return nil
	}
	if a.resolver == nil || receipt.Network.ResolverDigest != request.Binding.ArtifactDigests["resolver"] || receipt.Network.ResolverDigest != noderuntime.ResolverDigest(a.resolver.Evidence()) ||
		receipt.Network.SnapshotDigest == "" || receipt.Network.ResolvedNS == 0 || receipt.Network.ResolvedNS >= receipt.HeldBefore.MonoNS || len(receipt.Network.Leases) != len(receipt.Network.Records) {
		return errors.New("the fixed actor's pinned network receipt differs")
	}
	for i, record := range receipt.Network.Records {
		lease := receipt.Network.Leases[i]
		if record.Resolver != a.resolver.Evidence() || record.RuleID != lease.RuleID || record.Hostname != lease.Hostname || record.Address != lease.Address || record.ExpiresNS != lease.ExpiresNS || digestJSON(record.Chain) != digestJSON(lease.Chain) || record.ExpiresNS <= receipt.Network.ResolvedNS || record.ExpiresNS > receipt.DeadlineNS || record.ReplySHA256 == "" {
			return errors.New("the fixed actor's trusted DNS record differs from its lease")
		}
	}
	if _, err := netrules.Compile(*network, receipt.Generation, receipt.Network.ResolvedNS, receipt.DeadlineNS, receipt.Network.Leases); err != nil {
		return errors.Join(errors.New("the fixed actor's endpoint map differs"), err)
	}
	return nil
}

// These facts are fixed-actor observations only. The caller has already
// verified every stream's ABI, sequence, generation, counters and zero loss.
// Neither an allowed map entry nor a successful syscall alone earns credit.
func positiveNetworkCases(request qualification.Request, receipt candidateReceipt, calls []syscallrules.Event) map[string][]string {
	out := map[string][]string{}
	if request.Document.Network == nil || request.Document.Network.Pilot == nil {
		return out
	}
	endpoint, err := pilotActorEndpoint(request.Document.Network)
	if err != nil || endpoint.Family != 4 { // This fixed actor currently exercises IPv4 only.
		return out
	}
	address := netip.AddrFrom4([4]byte(endpoint.Address[:4]))
	peerPolicy := receipt.Before.Peers
	peerDecision := netrules.Evaluate(peerPolicy, netrules.Endpoint{Address: address, Protocol: netrules.TCP, Port: endpoint.Port}, receipt.Active.MonoNS)
	if !peerDecision.Allowed || peerDecision.RuleIndex == 0 {
		return out
	}
	filterSequence := installedFilterSequence(receipt, calls)
	if filterSequence == 0 {
		return out
	}
	validTime := func(mono uint64) bool { return mono >= receipt.Active.MonoNS && mono < receipt.DeadlineNS }
	callAfter := func(mono uint64, number int64, success func(int64) bool) bool {
		for _, call := range calls {
			original, known := call.OriginalNumber()
			if !known || call.Type != syscallrules.Result || call.Sequence <= filterSequence || original != number ||
				!success(call.Result) || call.TGID != uint32(receipt.Active.PID) || call.TID != uint32(receipt.Active.PID) ||
				call.UID != 65534 || call.Domain != receipt.DomainID || call.Cgroup != receipt.DomainID ||
				call.Generation != receipt.Generation || call.BindingState != syscallrules.Live ||
				call.MonoNS < mono || call.MonoNS-mono > 1_000_000 || !validTime(call.MonoNS) ||
				call.EntryMonoNS != 0 && call.EntryMonoNS > mono {
				continue
			}
			return true
		}
		return false
	}
	connect, egress, ingress := false, false, false
	var connectNS uint64
	for _, raw := range receipt.Streams["peers"] {
		if len(raw) != 96 || binary.LittleEndian.Uint64(raw[8:]) != receipt.Generation ||
			binary.LittleEndian.Uint64(raw[16:]) != receipt.DomainID || binary.LittleEndian.Uint64(raw[24:]) != receipt.DomainID {
			continue
		}
		mono := binary.LittleEndian.Uint64(raw[32:])
		hook := binary.LittleEndian.Uint32(raw[48:])
		if !validTime(mono) || binary.LittleEndian.Uint32(raw[52:]) != 1 ||
			binary.LittleEndian.Uint32(raw[56:]) != peerDecision.RuleIndex ||
			binary.LittleEndian.Uint32(raw[60:]) != 4 || binary.LittleEndian.Uint32(raw[64:]) != netrules.TCP ||
			binary.LittleEndian.Uint32(raw[68:]) != uint32(endpoint.Port) ||
			binary.LittleEndian.Uint32(raw[92:]) != peerPolicy.Reserved {
			continue
		}
		var observed [16]byte
		copy(observed[:], raw[72:88])
		if observed != endpoint.Address {
			continue
		}
		switch hook {
		case 1:
			if binary.LittleEndian.Uint32(raw[40:]) == uint32(receipt.Active.PID) &&
				binary.LittleEndian.Uint32(raw[44:]) == 65534 &&
				callAfter(mono, unix.SYS_CONNECT, func(result int64) bool { return result == 0 || result == -int64(unix.EINPROGRESS) }) {
				connect, connectNS = true, mono
			}
		case 5:
			if binary.LittleEndian.Uint32(raw[40:]) == 0 && binary.LittleEndian.Uint32(raw[44:]) == 0 && mono >= connectNS && connect {
				egress = true
			}
		case 6:
			if binary.LittleEndian.Uint32(raw[40:]) == 0 && binary.LittleEndian.Uint32(raw[44:]) == 0 && mono >= connectNS && connect {
				ingress = true
			}
		}
	}
	if connect {
		out["net.ip.v1"] = []string{"literal-address-exact"}
		out["net.ipv4.v1"] = []string{"ipv4-connect-exact"}
		out["net.tcp.v1"] = []string{"tcp-connect-exact"}
	}
	if connect && egress && ingress {
		out["net.ipv4.v1"] = append(out["net.ipv4.v1"], "ipv4-packet-peer-exact")
		out["net.tcp.v1"] = append(out["net.tcp.v1"], "tcp-reply-peer-exact")
		out["net.ssh-lan-boundary.v1"] = []string{"taskboard-exact-endpoint-allowed"}
	}
	return out
}

// The fixed actor connects only to its own loopback addresses. Case credit
// requires the raw cgroup peer decision and the same actor's post-filter
// connect result. A socket-create denial alone is not a peer-map proof.
func ownedLoopbackDenialCases(request qualification.Request, receipt candidateReceipt, calls []syscallrules.Event, records map[uint32]scalarRecord) map[string][]string {
	out := map[string][]string{}
	if request.Document.Network == nil || request.Document.Network.Pilot == nil ||
		installedFilterSequence(receipt, calls) == 0 {
		return out
	}
	for _, probe := range []struct {
		family              uint32
		address             netip.Addr
		socketID, connectID uint32
		hook                uint32
		boundary, rules     string
	}{
		{4, netip.MustParseAddr("127.0.0.1"), 60, 61, 1, "private-ipv4-denied", "unmatched-ipv4-denied"},
		{6, netip.MustParseAddr("::1"), 62, 63, 2, "private-ipv6-denied", "unmatched-ipv6-denied"},
	} {
		if records[probe.socketID].Result < 0 || records[probe.connectID].Result != -1 ||
			records[probe.connectID].Error != uint32(unix.EPERM) {
			continue
		}
		decision := netrules.Evaluate(receipt.Before.Peers, netrules.Endpoint{Address: probe.address,
			Protocol: netrules.TCP, Port: receipt.Before.Peers.PilotPort}, receipt.Active.MonoNS)
		if decision.Allowed || decision.RuleIndex != 0 || decision.Reason != "pilot-lan-boundary" {
			continue
		}
		for _, raw := range receipt.Streams["peers"] {
			if len(raw) != 96 || binary.LittleEndian.Uint64(raw[8:]) != receipt.Generation ||
				binary.LittleEndian.Uint64(raw[16:]) != receipt.DomainID ||
				binary.LittleEndian.Uint64(raw[24:]) != receipt.DomainID ||
				binary.LittleEndian.Uint32(raw[40:]) != uint32(receipt.Active.PID) ||
				binary.LittleEndian.Uint32(raw[44:]) != 65534 ||
				binary.LittleEndian.Uint32(raw[48:]) != probe.hook ||
				binary.LittleEndian.Uint32(raw[52:]) != 0 ||
				binary.LittleEndian.Uint32(raw[56:]) != 0 ||
				binary.LittleEndian.Uint32(raw[60:]) != probe.family ||
				binary.LittleEndian.Uint32(raw[64:]) != netrules.TCP ||
				binary.LittleEndian.Uint32(raw[68:]) != uint32(receipt.Before.Peers.PilotPort) ||
				binary.LittleEndian.Uint32(raw[92:]) != receipt.Before.Peers.Reserved {
				continue
			}
			var observed [16]byte
			copy(observed[:], raw[72:88])
			var wanted [16]byte
			if probe.address.Is4() {
				copy(wanted[:4], probe.address.AsSlice())
			} else {
				wanted = probe.address.As16()
			}
			mono := binary.LittleEndian.Uint64(raw[32:])
			if observed != wanted || mono < receipt.Active.MonoNS || mono >= receipt.DeadlineNS {
				continue
			}
			for _, call := range calls {
				original, known := call.OriginalNumber()
				if !known || call.Type != syscallrules.Result || original != unix.SYS_CONNECT ||
					call.Result != -int64(unix.EPERM) || call.TGID != uint32(receipt.Active.PID) ||
					call.TID != uint32(receipt.Active.PID) || call.UID != 65534 ||
					call.Domain != receipt.DomainID || call.Cgroup != receipt.DomainID ||
					call.Generation != receipt.Generation || call.BindingState != syscallrules.Live ||
					call.Sequence <= installedFilterSequence(receipt, calls) || call.MonoNS < mono ||
					call.MonoNS-mono > 1_000_000 || call.MonoNS >= receipt.DeadlineNS {
					continue
				}
				out["net.ssh-lan-boundary.v1"] = append(out["net.ssh-lan-boundary.v1"], probe.boundary)
				out["net.rules.v1"] = append(out["net.rules.v1"], probe.rules)
				if probe.family == 4 {
					out["net.ip.v1"] = append(out["net.ip.v1"], "literal-other-address-denied")
					out["net.tcp.v1"] = append(out["net.tcp.v1"], "alternate-tcp-peer-denied")
				}
				break
			}
			if len(out["net.rules.v1"]) > 0 && out["net.rules.v1"][len(out["net.rules.v1"])-1] == probe.rules {
				break
			}
		}
	}
	return out
}

// A direct-address bypass needs both an actual denied literal connection from
// the measured actor and rejection of an IP-literal replacement for every
// allowed hostname in this exact policy. This does not prove that two names
// sharing an authorized public IP are distinguishable at the packet layer.
func pilotDirectAddressBoundaryCases(request qualification.Request, receipt candidateReceipt, cases map[string][]string) {
	if request.Document.Network == nil || request.Document.Network.Pilot == nil ||
		!slices.Contains(cases["net.ssh-lan-boundary.v1"], "private-ipv4-denied") {
		return
	}
	denials, err := pilotNetworkDenialReadback(*request.Document.Network, receipt.Active.MonoNS)
	if err != nil || denials == nil || len(denials.Hosts) == 0 {
		return
	}
	for _, host := range denials.Hosts {
		if host.HostnameRuleID == "" || host.LiteralResult == "" || host.PrivateResult == "" {
			return
		}
	}
	cases["net.ssh-lan-boundary.v1"] = append(cases["net.ssh-lan-boundary.v1"], "direct-address-bypass-denied")
}

// An IPv4-only socket policy can deny the entire IPv6 family before the peer
// hook runs. This proves the socket boundary, not an IPv6 peer-map decision.
func deniedIPv6SocketCases(request qualification.Request, receipt candidateReceipt, calls []syscallrules.Event, records map[uint32]scalarRecord) map[string][]string {
	out := map[string][]string{}
	if request.Document.Sockets == nil || records[62].Result != -1 || records[62].Error != uint32(unix.EPERM) ||
		records[63].Result != -2 || records[63].Error != 0 {
		return out
	}
	filterSequence := installedFilterSequence(receipt, calls)
	if filterSequence == 0 || netrules.EvaluateSocket(receipt.Before.Sockets, netrules.SocketOperation{
		Family: 10, Protocol: netrules.TCP, Operation: netrules.SocketCreate,
	}, receipt.Active.MonoNS).Allowed {
		return out
	}
	for _, raw := range receipt.Streams["sockets"] {
		if len(raw) != 112 || binary.LittleEndian.Uint64(raw[8:]) != receipt.Generation ||
			binary.LittleEndian.Uint64(raw[16:]) != receipt.DomainID ||
			binary.LittleEndian.Uint64(raw[24:]) != receipt.DomainID ||
			binary.LittleEndian.Uint64(raw[40:]) != 0 ||
			binary.LittleEndian.Uint32(raw[48:]) != uint32(receipt.Active.PID) ||
			binary.LittleEndian.Uint32(raw[52:]) != 65534 ||
			binary.LittleEndian.Uint32(raw[56:]) != netrules.SocketCreate ||
			binary.LittleEndian.Uint32(raw[60:]) != 0 ||
			binary.LittleEndian.Uint32(raw[64:]) != 0 ||
			binary.LittleEndian.Uint32(raw[68:]) != 10 ||
			binary.LittleEndian.Uint32(raw[72:]) != netrules.TCP ||
			binary.LittleEndian.Uint32(raw[76:]) != 0 ||
			binary.LittleEndian.Uint32(raw[88:]) != 1 ||
			binary.LittleEndian.Uint32(raw[92:]) != 0 {
			continue
		}
		mono := binary.LittleEndian.Uint64(raw[32:])
		if mono < receipt.Active.MonoNS || mono >= receipt.DeadlineNS {
			continue
		}
		for _, call := range calls {
			original, known := call.OriginalNumber()
			if !known || call.Type != syscallrules.Result || original != unix.SYS_SOCKET ||
				call.Result != -int64(unix.EPERM) || call.TGID != uint32(receipt.Active.PID) ||
				call.TID != uint32(receipt.Active.PID) || call.UID != 65534 ||
				call.Domain != receipt.DomainID || call.Cgroup != receipt.DomainID ||
				call.Generation != receipt.Generation || call.BindingState != syscallrules.Live ||
				call.Sequence <= filterSequence || call.MonoNS < mono || call.MonoNS-mono > 1_000_000 ||
				call.MonoNS >= receipt.DeadlineNS {
				continue
			}
			out["socket.ipv4.v1"] = []string{"ipv6-family-denied"}
			out["socket.create.v1"] = []string{"ungranted-create-denied"}
			return out
		}
	}
	return out
}

// An actual pilot that denies IPv6 socket creation cannot reach any private
// IPv6 endpoint through a newly created socket. This is whole-family denial,
// not evidence that the IPv6 peer map ran or that inherited sockets are safe.
func pilotIPv6FamilyBoundaryCases(request qualification.Request, receipt candidateReceipt, cases map[string][]string) {
	if request.Document.Network == nil || request.Document.Network.Pilot == nil ||
		len(cases["socket.ipv4.v1"]) != 1 || cases["socket.ipv4.v1"][0] != "ipv6-family-denied" ||
		receipt.Before.Peers.PilotMode != 1 ||
		netrules.EvaluateSocket(receipt.Before.Sockets, netrules.SocketOperation{Family: 10, Protocol: netrules.UDP,
			Operation: netrules.SocketCreate}, receipt.Active.MonoNS).Allowed {
		return
	}
	cases["net.ssh-lan-boundary.v1"] = append(cases["net.ssh-lan-boundary.v1"], "private-ipv6-denied")
}

// Creation and post-creation must both be observed for the same actor and
// rule. The post-create socket domain is the kernel ownership readback.
func allowedIPv4SocketCases(request qualification.Request, receipt candidateReceipt, calls []syscallrules.Event, records map[uint32]scalarRecord) map[string][]string {
	out := map[string][]string{}
	if request.Document.Sockets == nil || records[60].Result < 0 || records[60].Error != 0 {
		return out
	}
	filterSequence := installedFilterSequence(receipt, calls)
	decision := netrules.EvaluateSocket(receipt.Before.Sockets, netrules.SocketOperation{
		Family: 2, Protocol: netrules.TCP, Operation: netrules.SocketCreate,
	}, receipt.Active.MonoNS)
	if filterSequence == 0 || !decision.Allowed || decision.RuleIndex == 0 {
		return out
	}
	match := func(raw []byte, source uint32, owner uint64) bool {
		return len(raw) == 112 && binary.LittleEndian.Uint64(raw[8:]) == receipt.Generation &&
			binary.LittleEndian.Uint64(raw[16:]) == receipt.DomainID &&
			binary.LittleEndian.Uint64(raw[24:]) == receipt.DomainID &&
			binary.LittleEndian.Uint64(raw[40:]) == owner &&
			binary.LittleEndian.Uint32(raw[48:]) == uint32(receipt.Active.PID) &&
			binary.LittleEndian.Uint32(raw[52:]) == 65534 &&
			binary.LittleEndian.Uint32(raw[56:]) == netrules.SocketCreate &&
			binary.LittleEndian.Uint32(raw[60:]) == 1 &&
			binary.LittleEndian.Uint32(raw[64:]) == decision.RuleIndex &&
			binary.LittleEndian.Uint32(raw[68:]) == 2 &&
			binary.LittleEndian.Uint32(raw[72:]) == netrules.TCP &&
			binary.LittleEndian.Uint32(raw[76:]) == 0 &&
			binary.LittleEndian.Uint32(raw[88:]) == source
	}
	stream := receipt.Streams["sockets"]
	for i, created := range stream {
		if !match(created, 1, 0) {
			continue
		}
		createdNS := binary.LittleEndian.Uint64(created[32:])
		if createdNS < receipt.Active.MonoNS || createdNS >= receipt.DeadlineNS {
			continue
		}
		for _, owned := range stream[i+1:] {
			if !match(owned, 5, receipt.DomainID) ||
				binary.LittleEndian.Uint64(owned[0:]) != binary.LittleEndian.Uint64(created[0:])+1 {
				continue
			}
			ownedNS := binary.LittleEndian.Uint64(owned[32:])
			if ownedNS < createdNS || ownedNS-createdNS > 1_000_000 || ownedNS >= receipt.DeadlineNS {
				continue
			}
			for _, call := range calls {
				original, known := call.OriginalNumber()
				if !known || call.Type != syscallrules.Result || original != unix.SYS_SOCKET ||
					call.Result != records[60].Result || call.TGID != uint32(receipt.Active.PID) ||
					call.TID != uint32(receipt.Active.PID) || call.UID != 65534 ||
					call.Domain != receipt.DomainID || call.Cgroup != receipt.DomainID ||
					call.Generation != receipt.Generation || call.BindingState != syscallrules.Live ||
					call.Sequence <= filterSequence || call.MonoNS < ownedNS ||
					call.MonoNS-ownedNS > 1_000_000 || call.MonoNS >= receipt.DeadlineNS {
					continue
				}
				out["socket.ipv4.v1"] = []string{"ipv4-family-exact"}
				out["socket.create.v1"] = []string{"create-exact-family-protocol", "created-socket-owned"}
				return out
			}
		}
	}
	return out
}

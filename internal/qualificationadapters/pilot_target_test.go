// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/dnslease/fixture"
	"alloyium.local/kernel-poc/internal/dockerplacement"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
	"context"
	"errors"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPilotNegativeCompilerReadback(t *testing.T) {
	network := policy.Network{
		Default: "deny",
		DNS:     policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"},
		Pilot:   &policy.PilotNetwork{Mode: "ssh-coding.v1", TaskboardIP: "10.77.0.2", TaskboardPort: 18080, TaskboardTaskID: 42},
		Rules: []policy.NetworkRule{
			{ID: "sample", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: "example.org"}, PortFrom: 443, PortTo: 443, Effect: "allow"},
			{ID: "taskboard", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "ip", Value: "10.77.0.2"}, PortFrom: 18080, PortTo: 18080, Effect: "allow"},
		},
	}
	receipt, err := pilotNetworkDenialReadback(network, 100)
	if err != nil || len(receipt.Hosts) != 1 || receipt.Hosts[0].HostnameRuleID != "sample" || receipt.Hosts[0].PrivateResult == "" || receipt.Hosts[0].LiteralResult == "" {
		t.Fatal("the exact pilot compiler rejections are absent", receipt, err)
	}
	if network.Rules[0].Destination.Kind != "hostname" {
		t.Fatal("the negative fixture changed the candidate document")
	}
	network.Rules[0].Family = "ipv6"
	if v6, err := pilotNetworkDenialReadback(network, 100); err != nil || len(v6.Hosts) != 1 || v6.Hosts[0].HostnameRuleID != "sample" {
		t.Fatal("the IPv6 hostname bypass was not rejected", v6, err)
	}
	network.Rules = append(network.Rules, policy.NetworkRule{ID: "second", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: "example.net"}, PortFrom: 443, PortTo: 443, Effect: "allow"})
	if multiple, err := pilotNetworkDenialReadback(network, 100); err != nil || len(multiple.Hosts) != 2 || multiple.Hosts[0].HostnameRuleID != "sample" || multiple.Hosts[1].HostnameRuleID != "second" {
		t.Fatal("the second hostname lacks its own private and literal bypass proof", multiple, err)
	}
	network.Rules = append(network.Rules, policy.NetworkRule{ID: "blocked", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: "blocked.example"}, PortFrom: 443, PortTo: 443, Effect: "deny"})
	if multiple, err := pilotNetworkDenialReadback(network, 100); err != nil || len(multiple.Hosts) != 2 {
		t.Fatal("an unrelated denied hostname masked the allowed hostname checks", multiple, err)
	}
	network.Rules[2].ID = "sample"
	if _, err := pilotNetworkDenialReadback(network, 100); err == nil {
		t.Fatal("duplicate hostname rules gained negative proof")
	}
}

func TestPilotDockerSocketAbsent(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "run"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("run", filepath.Join(root, "var")); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := pilotDockerSocketAbsent(fd); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "run/docker.sock"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := pilotDockerSocketAbsent(fd); err == nil {
		t.Fatal("Docker socket path was accepted")
	}
	if err := os.Remove(filepath.Join(root, "run/docker.sock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "var")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/outside", filepath.Join(root, "var")); err != nil {
		t.Fatal(err)
	}
	if err := pilotDockerSocketAbsent(fd); err != nil && !errors.Is(err, unix.ENOENT) {
		t.Fatal(err)
	}
}

func TestPilotTargetAdapterCannotQualifyANonpilotPolicy(t *testing.T) {
	request := adapterRequest(t)
	adapter := &pilotTargetAdapter{}
	result, err := adapter.Run(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	coverage, err := adapter.Verify(request, result)
	if err != nil || len(coverage) != 0 {
		t.Fatal("a nonpilot policy gained Docker target coverage", err, coverage)
	}
	forged := pilotTargetReceipt{Protocol: pilotTargetReceiptVersion, Binding: request.Binding, Applicable: true}
	result.Raw = serviceJSON(forged)
	if _, err := adapter.Verify(request, result); err == nil {
		t.Fatal("a caller supplied applicable target receipt passed without a pilot policy")
	}
}

func TestPilotHostReadbackUsesPinnedResolverAndMeasuredRoot(t *testing.T) {
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
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "etc"), 0755); err != nil {
		t.Fatal(err)
	}
	hosts := filepath.Join(root, "etc", "hosts")
	if err := os.WriteFile(hosts, []byte("93.184.215.14 example.org\n"), 0644); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	handles := &dockerplacement.Handles{Root: dir, Measurement: dockerplacement.Measurement{WorkspaceInode: 42}}
	network := policy.Network{Default: "deny", DNS: policy.DNS{ResolverProfile: "trusted-forwarder.v1", CNAME: "validate-chain", Expiry: "remove-expired-authorization"},
		Pilot: &policy.PilotNetwork{Mode: "ssh-coding.v1", TaskboardIP: "10.77.0.2", TaskboardPort: 18080, TaskboardTaskID: 42},
		Rules: []policy.NetworkRule{
			{ID: "task", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "ip", Value: "10.77.0.2"}, PortFrom: 18080, PortTo: 18080, Effect: "allow"},
			{ID: "web", Family: "ipv4", Protocol: "tcp", Destination: policy.Destination{Kind: "hostname", Value: "example.org"}, PortFrom: 443, PortTo: 443, Effect: "allow"},
		}}
	request := qualification.Request{Document: policy.Document{Network: &network}, Binding: qualification.Binding{PolicyDigest: strings.Repeat("a", 64), Challenge: "owned-host-readback", ArtifactDigests: map[string]string{"resolver": noderuntime.ResolverDigest(resolver.Evidence())}}}
	readback, err := pilotResolveHosts(context.Background(), request, resolver, handles)
	if err != nil || readback == nil || len(readback.Aliases) != 1 || readback.SnapshotDigest == "" {
		t.Fatal("the pinned resolver and target hosts did not match", readback, err)
	}
	if err := os.WriteFile(hosts, []byte("93.184.215.15 example.org\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := pilotResolveHosts(context.Background(), request, resolver, handles); err == nil {
		t.Fatal("a changed target hosts mapping passed")
	}
	if err := os.WriteFile(hosts, []byte("93.184.215.14 example.org\n"), 0644); err != nil {
		t.Fatal(err)
	}
	address = [4]byte{10, 77, 0, 1}
	if _, err := pilotResolveHosts(context.Background(), request, resolver, handles); err == nil {
		t.Fatal("a private trusted-DNS result passed")
	}
}

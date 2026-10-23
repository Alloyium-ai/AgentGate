// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"alloyium.local/kernel-poc/internal/buildinfo"
	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/dockerplacement"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"net/netip"
	"reflect"
	"time"
)

const pilotTargetReceiptVersion = "agentgate.pilot-target-readback.v2"

// pilotTargetAdapter checks target custody, two compiler rejections, and the
// pinned hostname mapping when a resolver artifact is bound. It does not
// place a process or upgrade a fixed fixture to normal admission.
type pilotTargetAdapter struct {
	target   dockerplacement.Target
	resolver dnslease.Resolver
}

func (*pilotTargetAdapter) ID() string { return "agentgate.pilot-target-readback-adapter.v1" }

type pilotTargetReceipt struct {
	Protocol           string                       `json:"protocol"`
	Binding            qualification.Binding        `json:"binding"`
	Applicable         bool                         `json:"applicable"`
	TargetSHA256       string                       `json:"target_sha256,omitempty"`
	Measurement        *dockerplacement.Measurement `json:"measurement,omitempty"`
	Bridge             *pilotBridgeReadback         `json:"bridge,omitempty"`
	DockerSocketAbsent bool                         `json:"docker_socket_absent,omitempty"`
	ForeignContainerID string                       `json:"foreign_container_id,omitempty"`
	ForeignRejection   string                       `json:"foreign_rejection,omitempty"`
	NetworkDenials     *pilotNetworkDenials         `json:"network_denials,omitempty"`
	Hosts              *pilotHostReadback           `json:"hosts,omitempty"`
}

type pilotNetworkDenials struct {
	Hosts []pilotHostDenial `json:"hosts"`
}

type pilotHostDenial struct {
	HostnameRuleID string `json:"hostname_rule_id"`
	PrivateResult  string `json:"private_result"`
	LiteralResult  string `json:"literal_result"`
}

// These are compiler rejection witnesses. Live LAN denial still requires
// separate raw BPF decisions from an owned process in the measured job domain.
func pilotNetworkDenialReadback(network policy.Network, now uint64) (*pilotNetworkDenials, error) {
	if network.Pilot == nil || now == 0 || now > ^uint64(0)-uint64(time.Second) {
		return nil, errors.New("the pilot negative compiler scope differs")
	}
	indices := []int{}
	leases := []netrules.Lease{}
	deadline := now + uint64(time.Second)
	for i, rule := range network.Rules {
		if rule.Destination.Kind == "hostname" {
			address := "93.184.215.14"
			if rule.Family == "ipv6" {
				address = "2606:4700::1111"
			}
			leases = append(leases, netrules.Lease{RuleID: rule.ID, Hostname: rule.Destination.Value,
				Address: netip.MustParseAddr(address), Chain: []string{rule.Destination.Value}, ExpiresNS: deadline})
			if rule.Effect == "allow" {
				indices = append(indices, i)
			}
		}
	}
	if len(indices) == 0 {
		return nil, errors.New("the pilot policy lacks an allowed hostname")
	}
	if _, err := netrules.Compile(network, 1, now, deadline, leases); err != nil {
		return nil, errors.Join(errors.New("the exact pilot policy lacks a complete baseline lease set"), err)
	}
	result := &pilotNetworkDenials{Hosts: make([]pilotHostDenial, 0, len(indices))}
	for _, index := range indices {
		rule := network.Rules[index]
		private, literal := "10.77.0.1", "93.184.215.14"
		if rule.Family == "ipv6" {
			private, literal = "fc00::1", "2606:4700::1111"
		}
		privateLeases := append([]netrules.Lease(nil), leases...)
		for i := range privateLeases {
			if privateLeases[i].RuleID == rule.ID {
				privateLeases[i].Address = netip.MustParseAddr(private)
			}
		}
		_, privateErr := netrules.Compile(network, 1, now, deadline, privateLeases)
		wantPrivate := "pilot hostname " + rule.ID + " resolved to a private destination"
		if privateErr == nil || privateErr.Error() != wantPrivate {
			return nil, errors.Join(errors.New("the private hostname lease was not specifically rejected"), privateErr)
		}
		changed := network
		changed.Rules = append([]policy.NetworkRule(nil), network.Rules...)
		changed.Rules[index].Destination = policy.Destination{Kind: "ip", Value: literal}
		remaining := make([]netrules.Lease, 0, len(leases)-1)
		for _, lease := range leases {
			if lease.RuleID != rule.ID {
				remaining = append(remaining, lease)
			}
		}
		_, literalErr := netrules.Compile(changed, 1, now, deadline, remaining)
		wantLiteral := "pilot rule " + rule.ID + " grants a private or broad destination"
		if literalErr == nil || literalErr.Error() != wantLiteral {
			return nil, errors.Join(errors.New("the public literal bypass was not specifically rejected"), literalErr)
		}
		result.Hosts = append(result.Hosts, pilotHostDenial{rule.ID, privateErr.Error(), literalErr.Error()})
	}
	return result, nil
}

// The measured bridge is a live, separate Docker container. Requiring the
// target reader to reject that exact container tests a foreign placement
// without creating a second workload or changing the admitted target.
func pilotRejectForeignBridge(ctx context.Context, target dockerplacement.Target) (string, error) {
	if target.BridgeContainerID == "" {
		return "", errors.New("the pilot foreign container is absent")
	}
	foreign := target
	foreign.ContainerID, foreign.BridgeContainerID = target.BridgeContainerID, target.ContainerID
	if err := foreign.Validate(); err != nil {
		return "", err
	}
	handles, err := dockerplacement.Open(ctx, foreign)
	if handles != nil {
		return "", errors.Join(errors.New("the foreign bridge was accepted as the coding target"), handles.Close())
	}
	const rejected = "the running Docker target identity differs"
	if err == nil || err.Error() != rejected {
		return "", errors.Join(errors.New("the live foreign bridge was not rejected by target identity"), err)
	}
	return rejected, nil
}

func pilotDockerSocketAbsent(root int) error {
	for _, path := range []string{"run/docker.sock", "var/run/docker.sock"} {
		fd, err := unix.Openat2(root, path, &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS})
		if err == nil {
			_ = unix.Close(fd)
			return fmt.Errorf("the Docker target exposes %s", path)
		}
		if !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("the Docker target socket path cannot be measured: %s: %w", path, err)
		}
	}
	return nil
}

func (a *pilotTargetAdapter) Run(ctx context.Context, request qualification.Request) (out qualification.Result, err error) {
	if err = validateRequest(request); err != nil {
		return out, err
	}
	out.Binding = request.Binding
	if out.StartedMonoNS, err = kernel.MonotonicNS(); err != nil {
		return out, err
	}
	receipt := pilotTargetReceipt{Protocol: pilotTargetReceiptVersion, Binding: request.Binding}
	defer func() { out.FinishedMonoNS, _ = kernel.MonotonicNS(); out.Raw = serviceJSON(receipt) }()
	if request.Document.Network == nil || request.Document.Network.Pilot == nil {
		return out, nil
	}
	if !a.target.MatchesPilot(request.Document.Network.Pilot.TaskboardTaskID, request.Document.Network.Pilot.TaskboardIP, request.Document.Network.Pilot.TaskboardPort) {
		return out, errors.New("the pilot target task differs from the signed policy")
	}
	if buildinfo.SourceRevision == "" || buildinfo.SourceRevision != request.Binding.SourceRevision {
		return out, errors.New("the pilot target adapter source differs")
	}
	if err = sourceBootMatches(request); err != nil {
		return out, err
	}
	if err = jobartifacts.VerifyRunningExecutable(request.Binding.ArtifactDigests["qualification"]); err != nil {
		return out, err
	}
	handles, openErr := dockerplacement.Open(ctx, a.target)
	if openErr != nil {
		return out, openErr
	}
	if handles.Measurement.ImageSourceRevision != request.Binding.SourceRevision {
		return out, errors.Join(errors.New("the pilot target image source differs"), handles.Close())
	}
	receipt.Applicable = true
	receipt.TargetSHA256 = digestJSON(a.target)
	receipt.Measurement = &handles.Measurement
	if err = pilotDockerSocketAbsent(int(handles.Root.Fd())); err != nil {
		return out, errors.Join(err, handles.Close())
	}
	receipt.DockerSocketAbsent = true
	receipt.NetworkDenials, err = pilotNetworkDenialReadback(*request.Document.Network, out.StartedMonoNS)
	if err != nil {
		return out, errors.Join(err, handles.Close())
	}
	if a.resolver != nil && request.Binding.ArtifactDigests["resolver"] != "" {
		receipt.Hosts, err = pilotResolveHosts(ctx, request, a.resolver, handles)
		if err != nil {
			return out, errors.Join(err, handles.Close())
		}
	}
	if a.target.BridgePath != "" {
		receipt.Bridge, err = probePilotBridge(ctx, a.target, handles)
		if err != nil {
			return out, errors.Join(err, handles.Close())
		}
		receipt.ForeignRejection, err = pilotRejectForeignBridge(ctx, a.target)
		if err != nil {
			return out, errors.Join(err, handles.Close())
		}
		receipt.ForeignContainerID = a.target.BridgeContainerID
	}
	return out, handles.Close()
}

func (a *pilotTargetAdapter) Verify(request qualification.Request, result qualification.Result) ([]qualification.Coverage, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	if len(result.Raw) == 0 || len(result.Raw) > 16384 || uniqueJSON(result.Raw) != nil ||
		!reflect.DeepEqual(result.Binding, request.Binding) || result.StartedMonoNS == 0 || result.FinishedMonoNS <= result.StartedMonoNS {
		return nil, errors.New("the pilot target receipt encoding or binding differs")
	}
	var receipt pilotTargetReceipt
	decoder := json.NewDecoder(bytes.NewReader(result.Raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return nil, err
	}
	if receipt.Protocol != pilotTargetReceiptVersion || !reflect.DeepEqual(receipt.Binding, request.Binding) {
		return nil, errors.New("the pilot target receipt scope differs")
	}
	pilot := request.Document.Network != nil && request.Document.Network.Pilot != nil
	if !pilot {
		if receipt.Applicable || receipt.TargetSHA256 != "" || receipt.Measurement != nil || receipt.DockerSocketAbsent || receipt.ForeignContainerID != "" || receipt.ForeignRejection != "" || receipt.NetworkDenials != nil || receipt.Hosts != nil {
			return nil, errors.New("a nonpilot document has a target receipt")
		}
		return nil, nil
	}
	if !receipt.Applicable || !receipt.DockerSocketAbsent || receipt.TargetSHA256 != digestJSON(a.target) || receipt.Measurement == nil ||
		buildinfo.SourceRevision == "" || buildinfo.SourceRevision != request.Binding.SourceRevision ||
		!a.target.MatchesPilot(request.Document.Network.Pilot.TaskboardTaskID, request.Document.Network.Pilot.TaskboardIP, request.Document.Network.Pilot.TaskboardPort) ||
		receipt.Measurement.ContainerID != a.target.ContainerID || receipt.Measurement.ImageDigest != a.target.ImageDigest ||
		receipt.Measurement.ImageSourceRevision != request.Binding.SourceRevision ||
		receipt.Measurement.HostPID <= 1 || receipt.Measurement.WorkspaceInode == 0 || receipt.Measurement.WorkspaceDevice == 0 {
		return nil, errors.New("the pilot target measurement differs")
	}
	if (a.target.BridgePath == "") != (receipt.Bridge == nil) {
		return nil, errors.New("the pilot bridge receipt scope differs")
	}
	if receipt.Bridge == nil && (receipt.ForeignContainerID != "" || receipt.ForeignRejection != "") {
		return nil, errors.New("a bridge-free target has a foreign-container observation")
	}
	if err := sourceBootMatches(request); err != nil {
		return nil, err
	}
	if err := jobartifacts.VerifyRunningExecutable(request.Binding.ArtifactDigests["qualification"]); err != nil {
		return nil, err
	}
	denials, err := pilotNetworkDenialReadback(*request.Document.Network, result.StartedMonoNS)
	if err != nil || !reflect.DeepEqual(denials, receipt.NetworkDenials) {
		return nil, errors.Join(errors.New("the pilot negative compiler readback differs"), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	handles, err := dockerplacement.Open(ctx, a.target)
	if err != nil {
		return nil, err
	}
	defer handles.Close()
	measured := handles.Measurement
	if err = pilotDockerSocketAbsent(int(handles.Root.Fd())); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(measured, *receipt.Measurement) {
		return nil, errors.New("the pilot target changed after its receipt")
	}
	wantHosts := pilotAllowedHosts(*request.Document.Network) && a.resolver != nil && request.Binding.ArtifactDigests["resolver"] != ""
	if wantHosts != (receipt.Hosts != nil) {
		return nil, errors.New("the pilot hostname receipt scope differs")
	}
	if receipt.Hosts != nil {
		fresh, resolveErr := pilotResolveHosts(ctx, request, a.resolver, handles)
		if resolveErr != nil || fresh == nil || receipt.Hosts.ResolverDigest != fresh.ResolverDigest ||
			len(receipt.Hosts.SnapshotDigest) != 64 || !reflect.DeepEqual(receipt.Hosts.Aliases, fresh.Aliases) {
			return nil, errors.Join(errors.New("the pilot hostname lease or target mapping changed"), resolveErr)
		}
		if _, decodeErr := hex.DecodeString(receipt.Hosts.SnapshotDigest); decodeErr != nil {
			return nil, errors.New("the pilot hostname snapshot digest is invalid")
		}
	}
	if err = sourceBootMatches(request); err != nil {
		return nil, err
	}
	coverage := []qualification.Coverage{{CapabilityID: "runtime.docker-target.v1", ContractVersion: qualification.ContractVersion,
		Cases:         []string{"pinned-image-running-readback", "private-pid-net-mount-root-readback", "workspace-volume-inode-uid-readback", "docker-socket-unavailable-to-workload"},
		ReceiptSHA256: digestBytes(result.Raw)}}
	coverage = append(coverage, qualification.Coverage{CapabilityID: "net.ssh-lan-boundary.v1", ContractVersion: qualification.ContractVersion,
		Cases: []string{"private-hostname-lease-denied"}, ReceiptSHA256: digestBytes(result.Raw)})
	if receipt.Hosts != nil {
		coverage[1].Cases = append(coverage[1].Cases, "target-hosts-match-trusted-lease")
	}
	if receipt.Bridge != nil {
		if receipt.Measurement.BridgeContainerID != a.target.BridgeContainerID ||
			receipt.Measurement.BridgeImageDigest != a.target.BridgeImageDigest ||
			receipt.Measurement.BridgeImageSourceRevision != request.Binding.SourceRevision ||
			!receipt.Measurement.BridgeTokenIsolated {
			return nil, errors.New("the trusted bridge image or bearer custody differs")
		}
		observed, probeErr := probePilotBridge(ctx, a.target, handles)
		if probeErr != nil || !samePilotBridge(*receipt.Bridge, *observed, a.target.BridgeTaskID) {
			return nil, errors.Join(errors.New("the live pilot bridge changed or denied the task"), probeErr)
		}
		rejection, probeErr := pilotRejectForeignBridge(ctx, a.target)
		if probeErr != nil || receipt.ForeignContainerID != a.target.BridgeContainerID || receipt.ForeignRejection != rejection {
			return nil, errors.Join(errors.New("the live foreign target rejection differs"), probeErr)
		}
		coverage[0].Cases = append(coverage[0].Cases, "foreign-target-rejected")
		coverage = append(coverage, qualification.Coverage{CapabilityID: "identity.taskboard-bridge.v1", ContractVersion: qualification.ContractVersion,
			Cases: []string{"read-only-volume-inode-readback", "signed-task-id-match", "foreign-task-denied", "token-path-absent-in-target", "bridge-bearer-outside-target", "exact-authenticated-task-read"}, ReceiptSHA256: digestBytes(result.Raw)})
	}
	if err = handles.Close(); err != nil {
		return nil, err
	}
	return coverage, nil
}

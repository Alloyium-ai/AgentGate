// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"errors"
	"slices"
	"time"

	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/dockerplacement"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/nodebackend"
	"alloyium.local/kernel-poc/internal/nodedns"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
)

type pilotHostReadback struct {
	ResolverDigest string                      `json:"resolver_digest"`
	SnapshotDigest string                      `json:"snapshot_digest"`
	Aliases        []dockerplacement.HostAlias `json:"aliases"`
}

func pilotAllowedHosts(network policy.Network) bool {
	for _, rule := range network.Rules {
		if rule.Effect == "allow" && rule.Destination.Kind == "hostname" {
			return true
		}
	}
	return false
}

// A fresh diagnostic DNS binding uses the node's pinned resolver. It grants
// no workload operation. Both the actor and its verifier measure target hosts.
func pilotResolveHosts(ctx context.Context, request qualification.Request, resolver dnslease.Resolver, handles *dockerplacement.Handles) (*pilotHostReadback, error) {
	if request.Document.Network == nil || !pilotAllowedHosts(*request.Document.Network) {
		return nil, nil
	}
	if resolver == nil || handles == nil || handles.Root == nil || handles.Measurement.WorkspaceInode == 0 {
		return nil, errors.New("the pilot host qualifier lacks the pinned resolver or measured target")
	}
	resolverDigest := noderuntime.ResolverDigest(resolver.Evidence())
	if request.Binding.ArtifactDigests["resolver"] != resolverDigest {
		return nil, errors.New("the pilot host resolver differs from the measured artifact")
	}
	now, err := kernel.MonotonicNS()
	if err != nil || now > ^uint64(0)-uint64(time.Minute) {
		return nil, errors.New("the pilot host qualification clock is unavailable")
	}
	binding := dnslease.Binding{JobID: "pilot-host-qualification:" + request.Binding.Challenge,
		DomainID: handles.Measurement.WorkspaceInode, Generation: 1, DeadlineNS: now + uint64(time.Minute),
		PolicySHA256: request.Binding.PolicyDigest}
	coordinator, err := nodedns.New(nodedns.Config{Binding: binding, Network: *request.Document.Network,
		Resolver: resolver, Now: kernel.MonotonicNS})
	if err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	snapshot, err := coordinator.ResolveAll(bounded)
	if err != nil {
		return nil, err
	}
	now, err = kernel.MonotonicNS()
	if err != nil || snapshot.Check(binding, dnslease.NetworkDigest(*request.Document.Network), resolver.Evidence(), 0, now) != nil {
		return nil, errors.New("the pilot host resolver snapshot is stale or changed")
	}
	aliases, err := nodebackend.PilotHostAliases(*request.Document.Network, snapshot.Records(), now)
	if err != nil || len(aliases) == 0 {
		return nil, errors.Join(errors.New("the pilot host snapshot lacks every allowed lease"), err)
	}
	if err := dockerplacement.VerifyHostAliases(handles.Root, aliases); err != nil {
		return nil, err
	}
	slices.SortFunc(aliases, func(a, b dockerplacement.HostAlias) int {
		if a.Name < b.Name {
			return -1
		}
		if a.Name > b.Name {
			return 1
		}
		return a.Address.Compare(b.Address)
	})
	return &pilotHostReadback{ResolverDigest: resolverDigest, SnapshotDigest: snapshot.Digest(), Aliases: aliases}, nil
}

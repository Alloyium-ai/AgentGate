// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"context"
	"errors"

	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/dockerplacement"
	"alloyium.local/kernel-poc/internal/nodedns"
	"alloyium.local/kernel-poc/internal/policy"
)

// verifyPilotHosts binds ordinary target lookup to the trusted initial lease.
func (b *Backend) verifyPilotHosts(ctx context.Context, r *run) error {
	return b.verifyPilotHostsSnapshot(ctx, r, r.dnsInitial)
}

func (b *Backend) verifyPilotHostsSnapshot(ctx context.Context, r *run, snapshot dnslease.Snapshot) error {
	if r.document.Network == nil || r.document.Network.Pilot == nil {
		return nil
	}
	if b.config.PilotTarget == nil || r.dns == nil {
		return errors.New("the SSH pilot hostname target is absent")
	}
	now, err := b.config.Clock.NowNS()
	if err != nil {
		return err
	}
	aliases, err := PilotHostAliases(*r.document.Network, snapshot.Records(), now)
	if err != nil {
		return err
	}
	if len(aliases) == 0 {
		return nil
	}
	handles, err := dockerplacement.Open(ctx, *b.config.PilotTarget)
	if err != nil {
		return err
	}
	defer handles.Close()
	return dockerplacement.VerifyHostAliases(handles.Root, aliases)
}

// PilotHostAliases requires a live lease of the signed address family for
// every allowed hostname. The qualifier uses the same check as the node.
// A partial refresh must stop the job before a reduced map is published.
func PilotHostAliases(network policy.Network, records []dnslease.Record, now uint64) ([]dockerplacement.HostAlias, error) {
	allowed := make(map[string]policy.NetworkRule)
	for _, rule := range network.Rules {
		if rule.Effect == "allow" && rule.Destination.Kind == "hostname" {
			allowed[rule.ID] = rule
		}
	}
	if len(allowed) == 0 {
		return nil, nil
	}
	seen := make(map[string]bool)
	aliases := make([]dockerplacement.HostAlias, 0, len(records))
	for _, record := range records {
		rule, ok := allowed[record.RuleID]
		if !ok {
			continue
		}
		if record.Hostname != rule.Destination.Value || record.ExpiresNS <= now ||
			!record.Address.IsValid() || record.Address.Is4In6() ||
			(record.Address.Is4() && rule.Family != "ipv4") ||
			(record.Address.Is6() && rule.Family != "ipv6") {
			return nil, errors.New("the target hostname lease differs from the signed rule")
		}
		seen[record.RuleID] = true
		aliases = append(aliases, dockerplacement.HostAlias{Name: record.Hostname, Address: record.Address})
	}
	if len(seen) != len(allowed) {
		return nil, errors.New("the target hostname has no trusted lease for every allowed rule")
	}
	return aliases, nil
}

// A refreshed endpoint map may only be published while the target's ordinary
// lookup still names the same trusted addresses. A changed lease stops the
// whole job through the coordinator instead of leaving a stale alias running.
type pilotHostPublisher struct {
	inner  nodedns.Publisher
	verify func(context.Context, dnslease.Snapshot) error
}

func (p pilotHostPublisher) Activate(ctx context.Context, binding dnslease.Binding, snapshot dnslease.Snapshot) error {
	return p.inner.Activate(ctx, binding, snapshot)
}

func (p pilotHostPublisher) Publish(ctx context.Context, binding dnslease.Binding, snapshot dnslease.Snapshot) error {
	if err := p.verify(ctx, snapshot); err != nil {
		return err
	}
	return p.inner.Publish(ctx, binding, snapshot)
}

func (p pilotHostPublisher) Stop(ctx context.Context, binding dnslease.Binding, reason string) error {
	return p.inner.Stop(ctx, binding, reason)
}

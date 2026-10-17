// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"encoding/hex"
	"errors"
	"strings"
)

type InstalledReadback struct {
	Protocol           string               `json:"protocol"`
	PlanDigest         string               `json:"plan_digest"`
	VerificationDigest string               `json:"verification_digest"`
	Resources          ResourceReadbackWire `json:"resources"`
}

// ReadInstalled retains actual immutable resource bytes under the update lock.
// VerifyInstalled also compares every referenced file selector to the plan.
func (g *Group) ReadInstalled(p Plan) (InstalledReadback, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out InstalledReadback
	digest, err := g.verifyInstalledLocked(p)
	if err != nil {
		return out, err
	}
	q, err := g.readResourcesLocked()
	if err != nil {
		return out, err
	}
	wire, err := q.Wire()
	if err != nil {
		return out, err
	}
	out = InstalledReadback{Protocol: "agentgate.installed-resource-readback.v1", PlanDigest: p.Digest(), VerificationDigest: digest, Resources: wire}
	return out, nil
}
func (p InstalledReadback) Validate(domain, generation, deadline uint64) error {
	q, err := p.Resources.Tables()
	if err != nil {
		return err
	}
	validHash := func(s string) bool {
		raw, err := hex.DecodeString(s)
		return err == nil && len(raw) == 32 && strings.ToLower(s) == s
	}
	if p.Protocol != "agentgate.installed-resource-readback.v1" || !validHash(p.PlanDigest) || !validHash(p.VerificationDigest) || generation == 0 || deadline == 0 || q.Domain != domain {
		return errors.New("the installed readback binding differs")
	}
	if err = q.validateIdentities(); err != nil {
		return err
	}
	if q.Files.Generation != generation || q.Files.ExpiresNS != deadline || q.Peers.Generation != generation || q.Peers.ExpiresNS != deadline || q.Sockets.Generation != generation || q.Sockets.ExpiresNS != deadline || q.Custody != [2]uint64{generation, deadline} || q.Process.Generation != generation || q.Process.ExpiresNS != deadline {
		return errors.New("the installed readback lifetime differs")
	}
	return nil
}

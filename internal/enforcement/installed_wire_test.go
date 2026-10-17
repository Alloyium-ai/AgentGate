// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"strings"
	"testing"
)

func TestInstalledWireBindsAllResourceLifetimesAndOwnership(t *testing.T) {
	q := quarantineFixture()
	q.Files.Generation, q.Files.ExpiresNS = 3, 500
	q.Peers.Generation, q.Peers.ExpiresNS = 3, 500
	q.Sockets.Generation, q.Sockets.ExpiresNS = 3, 500
	q.Custody = [2]uint64{3, 500}
	q.Process.Generation, q.Process.ExpiresNS = 3, 500
	wire, err := q.Wire()
	if err != nil {
		t.Fatal(err)
	}
	p := InstalledReadback{Protocol: "agentgate.installed-resource-readback.v1", PlanDigest: strings.Repeat("a", 64), VerificationDigest: strings.Repeat("b", 64), Resources: wire}
	if p.Validate(42, 3, 500) != nil {
		t.Fatal("valid installed tables rejected")
	}
	if p.Validate(42, 3, 499) == nil || p.Validate(41, 3, 500) == nil {
		t.Fatal("changed installed binding accepted")
	}
	p.Resources.Process[0]++
	if p.Validate(42, 3, 500) == nil {
		t.Fatal("changed process generation accepted")
	}
	p.Resources = wire
	p.Resources.MapIDs = copyIDs(wire.MapIDs)
	delete(p.Resources.MapIDs, "files/owned")
	if p.Validate(42, 3, 500) == nil {
		t.Fatal("missing ownership map accepted")
	}
}

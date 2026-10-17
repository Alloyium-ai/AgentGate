// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodecontrol

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestEmptyDomainControlRetainsRawPopulationAndDigest(t *testing.T) {
	b, _ := boundFixture()
	raw := []byte("populated 0\nfrozen 0\n")
	sum := sha256.Sum256(append([]byte("agentgate-domain-empty-v1\n"), raw...))
	p := DomainEmpty{Events: raw, ReadbackDigest: hex.EncodeToString(sum[:]), ObservedMonoNS: 45}
	if _, err := Encode(b, "domain_empty_readback", p); err != nil {
		t.Fatal(err)
	}
	for _, events := range []string{"populated 1\n", "populated 0\npopulated 0\n", "frozen 0\n", "populated 0\nunknown 1\n"} {
		p.Events = []byte(events)
		if _, err := Encode(b, "domain_empty_readback", p); err == nil {
			t.Fatal("invalid raw empty proof accepted", events)
		}
	}
	p.Events = raw
	p.ObservedMonoNS = 0
	if p.Validate() == nil {
		t.Fatal("missing observation time accepted")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestAgentKeyCannotForgeAnotherTrustRole(t *testing.T) {
	agent := ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
	seed := make([]byte, 32)
	seed[0] = 1
	node := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	encoded := base64.RawURLEncoding.EncodeToString(agent)
	if separateAgentKey(encoded, map[string]ed25519.PublicKey{"node/key": node}, map[string]ed25519.PublicKey{}) != nil {
		t.Fatal("separate keys were rejected")
	}
	for _, registries := range [][2]map[string]ed25519.PublicKey{{{"node/key": agent}, {}}, {{}, {"authority/key": agent}}} {
		if separateAgentKey(encoded, registries[0], registries[1]) == nil {
			t.Fatal("an agent shared a trusted signing role")
		}
	}
}

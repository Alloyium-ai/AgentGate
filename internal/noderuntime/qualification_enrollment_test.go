// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestQualificationEnrollmentRetainsKeyRoleSeparation(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	agent := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	seed[0] = 1
	node := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	seed[0] = 2
	authority := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	encode := base64.RawURLEncoding.EncodeToString
	nodes := map[string]ed25519.PublicKey{"node/one": node}
	authorities := map[string]ed25519.PublicKey{"authority/one": authority}
	if err := VerifyAgentKeyRoles(encode(agent), nodes, authorities); err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]ed25519.PublicKey{"node": node, "authority": authority} {
		t.Run(name, func(t *testing.T) {
			if err := VerifyAgentKeyRoles(encode(key), nodes, authorities); err == nil {
				t.Fatal("an agent key reused a signing role")
			}
		})
	}
	if err := VerifyAgentKeyRoles("invalid", nodes, authorities); err == nil {
		t.Fatal("an invalid agent key passed")
	}
}

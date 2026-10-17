// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestAuthorityRejectsKeyReuseAcrossEveryTrustRole(t *testing.T) {
	cases := map[string]struct {
		change func(*testFixture)
		code   string
	}{
		"agent-equals-authority": {func(f *testFixture) {
			f.config.Subjects["agent-one"] = ProofSubject{"agent", f.config.SigningKey.Public().(ed25519.PublicKey)}
		}, "authority_subject_invalid"},
		"agent-equals-pinned-node": {func(f *testFixture) {
			f.config.NodeKeys["node-one/node-key"] = f.agent.Public().(ed25519.PublicKey)
		}, "authority_node_agent_keys_overlap"},
		"agent-equals-another-pinned-node": {func(f *testFixture) {
			other := ed25519.NewKeyFromSeed([]byte(strings.Repeat("z", 32)))
			f.config.Subjects["node-two"] = ProofSubject{"node", other.Public().(ed25519.PublicKey)}
			f.config.NodeKeys["node-two/rotated-key"] = f.agent.Public().(ed25519.PublicKey)
		}, "authority_node_agent_keys_overlap"},
		"agent-equals-node-proof": {func(f *testFixture) {
			f.config.Subjects["node-one"] = ProofSubject{"node", f.agent.Public().(ed25519.PublicKey)}
		}, "authority_subject_roles_overlap"},
		"pinned-node-equals-authority": {func(f *testFixture) {
			f.config.NodeKeys["node-one/rotated-key"] = f.config.SigningKey.Public().(ed25519.PublicKey)
		}, "authority_node_key_invalid"},
		"node-proof-equals-authority": {func(f *testFixture) {
			f.config.Subjects["node-one"] = ProofSubject{"node", f.config.SigningKey.Public().(ed25519.PublicKey)}
		}, "authority_subject_invalid"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			c.change(f)
			server, err := New(f.config)
			if server != nil || err == nil || err.Error() != c.code {
				t.Fatalf("reused trust key accepted or rejection differs: %v", err)
			}
		})
	}
}

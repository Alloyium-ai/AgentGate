// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import "crypto/ed25519"

// VerifyAgentKeyRoles executes the same key separation check that NewSources
// applies before it accepts an enrolled agent. It grants no runtime permission.
func VerifyAgentKeyRoles(encoded string, nodes, authorities map[string]ed25519.PublicKey) error {
	return separateAgentKey(encoded, nodes, authorities)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package fsrules

import (
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/openrules"
	"errors"
)

// VerifyAccess compares the complete immutable forest with its live kernel maps.
func VerifyAccess(r *kernel.Runtime, p Plan) error {
	if r == nil || r.Collection == nil || r.ID != p.domain || p.digest == "" || p.digest != planDigest(p) {
		return errors.New("the file readback binding differs")
	}
	var marker uint32
	if r.Collection.Maps["owned"] == nil || r.Collection.Maps["owned"].Lookup(r.ID, &marker) != nil || marker != 1 {
		return errors.New("the file ownership readback differs")
	}
	var state State
	if r.Collection.Maps["policies"] == nil || r.Collection.Maps["policies"].Lookup(r.ID, &state) != nil || state != p.state {
		return errors.New("the file policy readback differs")
	}
	nodes := r.Collection.Maps["nodes"]
	if nodes == nil {
		return errors.New("the file rule map is absent")
	}
	for _, entry := range p.entries {
		var got openrules.Node
		if nodes.Lookup(entry.Key, &got) != nil || got != entry.Node {
			return errors.New("the file rule readback differs")
		}
	}
	return nil
}

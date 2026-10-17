// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Canonical returns the exact validated document bytes used for grant binding.
// Array order remains part of the signed document content.
func (d Document) Canonical() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if err := d.CheckDeclaredRequirements(); err != nil {
		return nil, err
	}
	return json.Marshal(d)
}
func (d Document) Digest() (string, error) {
	raw, err := d.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

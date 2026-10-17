// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
)

// verifiedAuthority checks the seed and the embedded public key together.
func verifiedAuthority(key []byte) (ed25519.PrivateKey, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("authority key size differs")
	}
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	if subtle.ConstantTimeCompare(key, derived) != 1 {
		return nil, errors.New("authority seed and public key differ")
	}
	return derived, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobgrant

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"alloyium.local/kernel-poc/internal/lifecycle"
)

func TestVersionGrantCannotBorrowTheNormalSigningDomain(t *testing.T) {
	f := setup(t)
	e := f.e
	e.Protocol = QualificationVersionProtocol
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.key, qualificationVersionSigningBytes(e)))
	keys := map[string]ed25519.PublicKey{"authority-one/key-one": f.key.Public().(ed25519.PublicKey)}
	if _, err := VerifyQualificationVersionSigned(e, keys, f.d); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySigned(e, keys, f.d); err == nil {
		t.Fatal("a version signature entered normal grant verification")
	}
	raw, _ := json.Marshal(e)
	if _, err := Decode(string(raw)); err == nil {
		t.Fatal("a version envelope entered normal grant decoding")
	}
	f.a.Grant = string(raw)
	if f.v.Verify(context.Background(), f.a) == nil {
		t.Fatal("a version envelope entered normal admission")
	}
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.key, signingBytes(e)))
	if _, err := VerifyQualificationVersionSigned(e, keys, f.d); err == nil {
		t.Fatal("the normal signing domain entered version verification")
	}
	normalRaw, _ := Encode(f.e)
	if _, err := DecodeQualificationVersion(normalRaw); err == nil {
		t.Fatal("a normal grant entered version decoding")
	}
}

func TestVersionAuthorityRequiresAnExactPinnedPermitScope(t *testing.T) {
	f := setup(t)
	if _, err := SignQualificationVersion("authority-one", "key-one", f.key, f.c, f.d, lifecycle.QualificationVersionSpec{}); err == nil {
		t.Fatal("an unspecified command obtained a version grant")
	}
	if _, err := NewQualificationVersionVerifier(Config{}, &lifecycle.QualificationFixturePermit{}); err == nil {
		t.Fatal("the fixed or empty permit entered the version verifier")
	}
}

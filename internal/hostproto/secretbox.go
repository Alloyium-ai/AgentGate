// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"bytes"
	"encoding/json"
	"errors"
	"regexp"
)

// Sealed secrets. A client seals a value with internal/secretseal (RFC 9180
// HPKE: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305) to the
// seal key the target host published in a record signed by its enrolled
// Ed25519 key, which the client checks against a pinned fingerprint. The
// associated data binds the format, suite, target, secret name, version and a
// fresh nonce, so the host refuses a replayed or rolled-back envelope. The
// wire form is secretseal.Envelope.Encode(): unpadded base64url of the
// envelope's canonical JSON. The service relays it and cannot open it.
//
// hostproto depends on the standard library only, so it checks the public
// shape of an envelope here; the host opens it with internal/secretseal. The
// earlier hostproto.SealSecret format (AES-GCM whose associated data bound
// only the target and name, to an unsigned key) is retired: it allowed a
// relayed old ciphertext to roll a rotated secret back.
const (
	// SealedFormat is secretseal.EnvelopeFormat.
	SealedFormat = "agentgate.secretseal.v1"
	// SecretReceiptFormat is secretseal.ReceiptFormat.
	SecretReceiptFormat = "agentgate.secretseal.receipt.v1"
	// MaxSealedValueBytes is secretseal.MaxValueBytes; the broker itself
	// injects at most MaxSecretBytes.
	MaxSealedValueBytes = 16 << 10
	// MaxSealedBytes bounds one decoded envelope.
	MaxSealedBytes = 32 << 10
	// sealedOverhead is the HPKE encapsulated key and the AEAD tag.
	sealedOverhead = 32 + 16
)

var (
	sealTargetPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	sealKeyIDPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	sealNoncePattern  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	fingerprintRule   = regexp.MustCompile(`^sfp1_[0-9a-f]{32}$`)
)

// SealedEnvelope is the public shape of a secretseal envelope: ciphertext
// and the context its associated data binds.
type SealedEnvelope struct {
	Format   string `json:"format"`
	TargetID string `json:"target_id"`
	Name     string `json:"name"`
	// Version is the sealing time in Unix milliseconds; the host accepts only
	// a version newer than the one it stores for the name.
	Version uint64 `json:"version"`
	KeyID   string `json:"key_id"`
	Nonce   string `json:"nonce"`
	Sealed  string `json:"sealed"`
}

// ParseSealed strictly decodes the JSON of one envelope and checks its shape.
// It accepts only the canonical encoding (encoding/json field order, no
// whitespace), which is what secretseal and the UI produce, so one envelope
// has exactly one byte form and one ciphertext_sha256.
func ParseSealed(raw []byte) (SealedEnvelope, error) {
	var e SealedEnvelope
	if len(raw) == 0 || len(raw) > MaxSealedBytes {
		return e, errors.New("hostproto: sealed envelope size invalid")
	}
	if err := DecodeStrict(raw, &e); err != nil {
		return e, errors.New("hostproto: sealed envelope is not a secretseal envelope")
	}
	canonical, err := json.Marshal(e)
	if err != nil || !bytes.Equal(canonical, raw) {
		return e, errors.New("hostproto: sealed envelope is not in its canonical encoding")
	}
	if e.Format != SealedFormat || !sealTargetPattern.MatchString(e.TargetID) || !NamePattern.MatchString(e.Name) ||
		e.Version == 0 || e.Version > 1<<62 || !sealKeyIDPattern.MatchString(e.KeyID) || !sealNoncePattern.MatchString(e.Nonce) {
		return e, errors.New("hostproto: sealed envelope context invalid")
	}
	sealed, err := b64.DecodeString(e.Sealed)
	if err != nil || len(sealed) <= sealedOverhead || len(sealed) > MaxSealedValueBytes+sealedOverhead || b64.EncodeToString(sealed) != e.Sealed {
		return e, errors.New("hostproto: sealed envelope ciphertext invalid")
	}
	return e, nil
}

// CheckSealed validates the shape of one decoded envelope without opening it.
func CheckSealed(raw []byte) error {
	_, err := ParseSealed(raw)
	return err
}

// EncodeSealed is the wire form of decoded envelope bytes: unpadded base64url.
func EncodeSealed(raw []byte) string { return b64.EncodeToString(raw) }

// DecodeSealed decodes the wire form (secretseal.Envelope.Encode()) and
// checks the envelope's shape. ciphertext_sha256 is the SHA-256 of the bytes
// it returns.
func DecodeSealed(value string) ([]byte, error) {
	if len(value) == 0 || len(value) > (MaxSealedBytes*4+2)/3 {
		return nil, errors.New("hostproto: sealed envelope too large or empty")
	}
	raw, err := b64.DecodeString(value)
	if err != nil {
		return nil, errors.New("hostproto: sealed envelope encoding invalid")
	}
	return raw, CheckSealed(raw)
}

// SecretReceipt is the host's answer to a secret-put: secretseal.Receipt. The
// fingerprint is a keyed hash under a key that never leaves the host; the tag
// is keyed by the HPKE exporter secret only the sealing client shares with
// the host, so the client, not the service, can verify it.
type SecretReceipt struct {
	Format      string `json:"format"`
	TargetID    string `json:"target_id"`
	Name        string `json:"name"`
	Version     uint64 `json:"version"`
	KeyID       string `json:"key_id"`
	Nonce       string `json:"nonce"`
	Fingerprint string `json:"fingerprint"`
	Tag         string `json:"tag"`
}

// Check validates the receipt's shape.
func (r SecretReceipt) Check() error {
	if r.Format != SecretReceiptFormat || !sealTargetPattern.MatchString(r.TargetID) || !NamePattern.MatchString(r.Name) ||
		r.Version == 0 || r.Version > 1<<62 || !sealKeyIDPattern.MatchString(r.KeyID) || !sealNoncePattern.MatchString(r.Nonce) ||
		!fingerprintRule.MatchString(r.Fingerprint) {
		return errors.New("hostproto: secret receipt invalid")
	}
	tag, err := b64.DecodeString(r.Tag)
	if err != nil || len(tag) != 32 {
		return errors.New("hostproto: secret receipt tag invalid")
	}
	return nil
}

// Answers reports whether the receipt names exactly this envelope's context.
func (r SecretReceipt) Answers(e SealedEnvelope) bool {
	return r.TargetID == e.TargetID && r.Name == e.Name && r.Version == e.Version && r.KeyID == e.KeyID && r.Nonce == e.Nonce
}

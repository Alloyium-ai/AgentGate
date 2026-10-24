// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package secretseal

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"
)

// KeyRecordFormat identifies a published seal key.
const KeyRecordFormat = "agentgate.sealkey.v1"

// MaxKeyLifetime bounds a published seal key.
const MaxKeyLifetime = 90 * 24 * time.Hour

var (
	ErrKeyRecord   = errors.New("secretseal: seal key record is invalid")
	ErrSignature   = errors.New("secretseal: seal key record is not signed by the pinned host key")
	ErrFingerprint = errors.New("secretseal: host key does not match the pinned fingerprint")
)

// KeyRecord is the host's public seal key and its context.
type KeyRecord struct {
	Format    string `json:"format"`
	TargetID  string `json:"target_id"`
	KeyID     string `json:"key_id"`
	Suite     string `json:"suite"`
	PublicKey string `json:"public_key"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`
	// HostKey is the fingerprint of the Ed25519 enrollment key that signs
	// this record; see HostKeyFingerprint.
	HostKey string `json:"host_key"`
}

// SignedKeyRecord is what the host publishes and the service relays.
type SignedKeyRecord struct {
	Record    KeyRecord `json:"record"`
	Signature string    `json:"signature"`
}

func (r *KeyRecord) signingInput() []byte {
	return lp([]byte(KeyRecordFormat), []byte(r.TargetID), []byte(r.KeyID), []byte(r.Suite), []byte(r.PublicKey),
		[]byte(r.NotBefore), []byte(r.NotAfter), []byte(r.HostKey))
}

// HostKeyFingerprint names an Ed25519 host key as "SHA256:" and the unpadded
// base64 SHA-256 of the key, in the style of OpenSSH. Operators compare it
// out of band (for example the value agentgate-hostd prints at enrollment).
func HostKeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

func keyID(pub []byte) string {
	sum := sha256.Sum256(append([]byte(KeyRecordFormat+"\x00"), pub...))
	return hex.EncodeToString(sum[:])
}

// HostKey is the host's private seal key and its signed record. Keep it in a
// root-owned 0600 file; never send it anywhere.
type HostKey struct {
	priv   hpke.PrivateKey
	raw    []byte
	record KeyRecord
	signed SignedKeyRecord
}

// GenerateHostKey creates a seal key for targetID valid from now for lifetime,
// and signs its record with the host's enrolled Ed25519 key.
func GenerateHostKey(targetID string, signer crypto.Signer, now time.Time, lifetime time.Duration) (*HostKey, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return newHostKey(targetID, priv.Bytes(), signer, now, lifetime)
}

func newHostKey(targetID string, raw []byte, signer crypto.Signer, now time.Time, lifetime time.Duration) (*HostKey, error) {
	if !targetPattern.MatchString(targetID) || lifetime <= 0 || lifetime > MaxKeyLifetime || signer == nil {
		return nil, ErrKeyRecord
	}
	edPub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, ErrKeyRecord
	}
	k, err := hostKeyFromBytes(raw)
	if err != nil {
		return nil, err
	}
	pub := k.priv.PublicKey().Bytes()
	k.record = KeyRecord{Format: KeyRecordFormat, TargetID: targetID, KeyID: keyID(pub), Suite: Suite,
		PublicKey: base64.RawURLEncoding.EncodeToString(pub), NotBefore: now.UTC().Format(time.RFC3339),
		NotAfter: now.Add(lifetime).UTC().Format(time.RFC3339), HostKey: HostKeyFingerprint(edPub)}
	sig, err := signer.Sign(rand.Reader, k.record.signingInput(), crypto.Hash(0))
	if err != nil {
		return nil, err
	}
	k.signed = SignedKeyRecord{Record: k.record, Signature: base64.RawURLEncoding.EncodeToString(sig)}
	return k, nil
}

func hostKeyFromBytes(raw []byte) (*HostKey, error) {
	if len(raw) != 32 {
		return nil, ErrKeyRecord
	}
	ex, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, ErrKeyRecord
	}
	priv, err := hpke.NewDHKEMPrivateKey(ex)
	if err != nil {
		return nil, ErrKeyRecord
	}
	return &HostKey{priv: priv, raw: append([]byte(nil), raw...)}, nil
}

// Published is the signed record to publish through the service.
func (k *HostKey) Published() SignedKeyRecord { return k.signed }

// Record is the key's record.
func (k *HostKey) Record() KeyRecord { return k.record }

func (k *HostKey) validAt(now time.Time) bool {
	nb, err1 := time.Parse(time.RFC3339, k.record.NotBefore)
	na, err2 := time.Parse(time.RFC3339, k.record.NotAfter)
	return err1 == nil && err2 == nil && !now.Before(nb.Add(-MaxSkew)) && now.Before(na)
}

// Wipe clears the private key bytes this value holds.
func (k *HostKey) Wipe() { clear(k.raw) }

type storedHostKey struct {
	Format  string          `json:"format"`
	Private string          `json:"private"`
	Signed  SignedKeyRecord `json:"signed"`
}

// MarshalPrivate serializes the private key and its signed record for a
// root-owned 0600 file.
func (k *HostKey) MarshalPrivate() ([]byte, error) {
	return json.Marshal(storedHostKey{Format: KeyRecordFormat + ".private", Private: base64.RawURLEncoding.EncodeToString(k.raw),
		Signed: k.signed})
}

// ParseHostKey restores a key written by MarshalPrivate and checks that the
// record still matches the private key and is signed by hostPub.
func ParseHostKey(raw []byte, hostPub ed25519.PublicKey) (*HostKey, error) {
	var s storedHostKey
	if err := strictDecode(raw, &s); err != nil || s.Format != KeyRecordFormat+".private" {
		return nil, ErrKeyRecord
	}
	priv, err := base64.RawURLEncoding.Strict().DecodeString(s.Private)
	if err != nil {
		return nil, ErrKeyRecord
	}
	defer clear(priv)
	k, err := hostKeyFromBytes(priv)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(&s.Signed, hostPub); err != nil {
		return nil, err
	}
	pub := k.priv.PublicKey().Bytes()
	if s.Signed.Record.PublicKey != base64.RawURLEncoding.EncodeToString(pub) || s.Signed.Record.KeyID != keyID(pub) {
		return nil, ErrKeyRecord
	}
	k.record, k.signed = s.Signed.Record, s.Signed
	return k, nil
}

func verifySignature(s *SignedKeyRecord, hostPub ed25519.PublicKey) error {
	if len(hostPub) != ed25519.PublicKeySize {
		return ErrSignature
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(s.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(hostPub, s.Record.signingInput(), sig) {
		return ErrSignature
	}
	if s.Record.HostKey != HostKeyFingerprint(hostPub) {
		return ErrSignature
	}
	return nil
}

// PublicKey is a verified seal key for one target.
type PublicKey struct {
	pk       hpke.PublicKey
	keyID    string
	targetID string
}

// KeyID names the key.
func (p *PublicKey) KeyID() string { return p.keyID }

// VerifyKeyRecord is the client's check before sealing. hostPub is the target's
// Ed25519 enrollment key as reported by the service; pinnedFingerprint is the
// fingerprint the operator obtained out of band (or pinned on first use). The
// service cannot pass this check with a key of its own: it would need either a
// signature from the pinned host key or a host key with the pinned fingerprint.
func VerifyKeyRecord(s *SignedKeyRecord, hostPub ed25519.PublicKey, pinnedFingerprint, targetID string, now time.Time) (*PublicKey, error) {
	if s == nil || len(hostPub) != ed25519.PublicKeySize {
		return nil, ErrKeyRecord
	}
	if pinnedFingerprint == "" || HostKeyFingerprint(hostPub) != pinnedFingerprint {
		return nil, ErrFingerprint
	}
	if err := verifySignature(s, hostPub); err != nil {
		return nil, err
	}
	r := &s.Record
	if r.Format != KeyRecordFormat || r.Suite != Suite || r.TargetID != targetID || !targetPattern.MatchString(targetID) {
		return nil, ErrKeyRecord
	}
	nb, err1 := time.Parse(time.RFC3339, r.NotBefore)
	na, err2 := time.Parse(time.RFC3339, r.NotAfter)
	if err1 != nil || err2 != nil || !na.After(nb) || na.Sub(nb) > MaxKeyLifetime || now.Before(nb.Add(-MaxSkew)) || !now.Before(na) {
		return nil, ErrKeyRecord
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(r.PublicKey)
	if err != nil || len(raw) != 32 || r.KeyID != keyID(raw) {
		return nil, ErrKeyRecord
	}
	pk, err := hpke.DHKEM(ecdh.X25519()).NewPublicKey(raw)
	if err != nil {
		return nil, ErrKeyRecord
	}
	return &PublicKey{pk: pk, keyID: r.KeyID, targetID: targetID}, nil
}

// ParseSignedKeyRecord strictly decodes a published record.
func ParseSignedKeyRecord(raw []byte) (*SignedKeyRecord, error) {
	var s SignedKeyRecord
	if err := strictDecode(raw, &s); err != nil {
		return nil, ErrKeyRecord
	}
	return &s, nil
}

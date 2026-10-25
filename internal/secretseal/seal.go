// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Package secretseal moves a secret value from an operator's client to one
// target host through a service that relays it but cannot read it.
//
// The host publishes an X25519 key in a record signed by its enrolled Ed25519
// key. The client verifies that signature against a host key fingerprint it
// obtained out of band and pinned, then seals the value with RFC 9180 HPKE
// (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, base mode) from
// the Go standard library. The associated data binds the target, the secret
// name, a version, a fresh nonce and the digest of the secret's injection
// policy (hostproto.SecretPolicy: where and how the host's broker may use the
// value), which the client computes from what the operator intended. The host
// opens the envelope only with the policy whose digest it seals, commits the
// value and that digest together as one root-owned 0600 record and returns a
// receipt: the policy digest, a keyed
// fingerprint of the value and a tag derived from the HPKE exporter secret,
// which only the sealing client can verify. A service that substitutes the
// host key fails the signature check; one that substitutes the ciphertext or
// the policy cannot produce a receipt the client accepts, and the host refuses
// to store or use the value under any other policy.
package secretseal

import (
	"bytes"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

// Format names and limits.
const (
	EnvelopeFormat = "agentgate.secretseal.v2"
	ReceiptFormat  = "agentgate.secretseal.receipt.v2"
	Suite          = "hpke-base-x25519-hkdfsha256-hkdfsha256-chacha20poly1305"

	MaxValueBytes    = 16 << 10
	MaxEnvelopeBytes = 64 << 10
	// MaxAge bounds how long an envelope may wait in the relay; a captured
	// envelope cannot be replayed later even for a name never set before.
	MaxAge = 24 * time.Hour
	// MaxSkew bounds a client clock ahead of the host.
	MaxSkew = 5 * time.Minute

	exportReceipt = "agentgate.secretseal.v2 receipt"
)

var (
	namePattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	targetPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	noncePattern  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	keyIDPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func suite() (hpke.KDF, hpke.AEAD) { return hpke.HKDFSHA256(), hpke.ChaCha20Poly1305() }

// Errors never include a value, a key or plaintext.
var (
	ErrContext  = errors.New("secretseal: envelope context is invalid for this host")
	ErrReplay   = errors.New("secretseal: envelope version is not newer than the stored version")
	ErrStale    = errors.New("secretseal: envelope is outside its validity window")
	ErrOpen     = errors.New("secretseal: envelope does not authenticate")
	ErrReceipt  = errors.New("secretseal: receipt does not authenticate")
	ErrValue    = errors.New("secretseal: value is empty or too large")
	ErrEnvelope = errors.New("secretseal: envelope is malformed")
)

// Envelope is what the client sends and the service relays. It holds only
// ciphertext and public context.
type Envelope struct {
	Format   string `json:"format"`
	TargetID string `json:"target_id"`
	Name     string `json:"name"`
	// Version is the sealing time in Unix milliseconds. The host accepts only
	// a version newer than the one it stores for this name.
	Version uint64 `json:"version"`
	KeyID   string `json:"key_id"`
	Nonce   string `json:"nonce"`
	// PolicyDigest is the hex SHA-256 of the canonical injection policy
	// (hostproto.SecretPolicy.Digest) the value may be used under.
	PolicyDigest string `json:"policy_digest"`
	// Sealed is base64url(enc || ciphertext) without padding.
	Sealed string `json:"sealed"`
}

// Receipt is the host's answer. The fingerprint is a keyed hash, so a
// low-entropy value cannot be recovered by guessing without the host's key.
type Receipt struct {
	Format   string `json:"format"`
	TargetID string `json:"target_id"`
	Name     string `json:"name"`
	Version  uint64 `json:"version"`
	KeyID    string `json:"key_id"`
	Nonce    string `json:"nonce"`
	// PolicyDigest is the policy the host stored with the value.
	PolicyDigest string `json:"policy_digest"`
	Fingerprint  string `json:"fingerprint"`
	Tag          string `json:"tag"`
}

// lp appends length-prefixed fields: an unambiguous encoding for AAD,
// signatures and MAC input.
func lp(fields ...[]byte) []byte {
	var b bytes.Buffer
	for _, f := range fields {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		b.Write(n[:])
		b.Write(f)
	}
	return b.Bytes()
}

func u64(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}

func (e *Envelope) aad() []byte {
	return lp([]byte(EnvelopeFormat), []byte(Suite), []byte(e.TargetID), []byte(e.Name), u64(e.Version), []byte(e.KeyID), []byte(e.Nonce),
		[]byte(e.PolicyDigest))
}

func info(keyID, targetID string) []byte {
	return lp([]byte(EnvelopeFormat), []byte(Suite), []byte(keyID), []byte(targetID))
}

func (e *Envelope) validShape() error {
	if e.Format != EnvelopeFormat || !targetPattern.MatchString(e.TargetID) || !namePattern.MatchString(e.Name) ||
		e.Version == 0 || !keyIDPattern.MatchString(e.KeyID) || !noncePattern.MatchString(e.Nonce) || !keyIDPattern.MatchString(e.PolicyDigest) ||
		len(e.Sealed) == 0 || len(e.Sealed) > MaxEnvelopeBytes {
		return ErrEnvelope
	}
	return nil
}

// Sealed is a client's sealed value plus the secret it needs to check the
// host's receipt. Keep it in memory until the receipt arrives; it is never
// sent anywhere.
type Sealed struct {
	Envelope Envelope
	confirm  []byte
}

// Seal encrypts value for one target, to be used only under the injection
// policy whose digest is policyDigest, with the current time as its version.
func Seal(pub *PublicKey, targetID, name, policyDigest string, value []byte) (*Sealed, error) {
	return SealAt(pub, targetID, name, policyDigest, value, time.Now())
}

// SealAt is Seal with an explicit clock.
func SealAt(pub *PublicKey, targetID, name, policyDigest string, value []byte, now time.Time) (*Sealed, error) {
	if pub == nil || pub.targetID != targetID || !namePattern.MatchString(name) || !targetPattern.MatchString(targetID) || !keyIDPattern.MatchString(policyDigest) {
		return nil, ErrContext
	}
	if len(value) == 0 || len(value) > MaxValueBytes {
		return nil, ErrValue
	}
	var nonce [16]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return nil, err
	}
	return seal(pub, targetID, name, policyDigest, uint64(now.UnixMilli()), hex.EncodeToString(nonce[:]), value)
}

func seal(pub *PublicKey, targetID, name, policyDigest string, version uint64, nonce string, value []byte) (*Sealed, error) {
	env := Envelope{Format: EnvelopeFormat, TargetID: targetID, Name: name, Version: version, KeyID: pub.keyID, Nonce: nonce, PolicyDigest: policyDigest}
	kdf, aead := suite()
	enc, sender, err := hpke.NewSender(pub.pk, kdf, aead, info(pub.keyID, targetID))
	if err != nil {
		return nil, err
	}
	ct, err := sender.Seal(env.aad(), value)
	if err != nil {
		return nil, err
	}
	confirm, err := sender.Export(exportReceipt, 32)
	if err != nil {
		return nil, err
	}
	env.Sealed = base64.RawURLEncoding.EncodeToString(append(enc, ct...))
	return &Sealed{Envelope: env, confirm: confirm}, nil
}

// VerifyReceipt checks that the host opened exactly this envelope and stored
// it under exactly the policy this client sealed, and returns the fingerprint
// it reported. The tag comparison is constant time.
func (s *Sealed) VerifyReceipt(r *Receipt) (string, error) {
	e := &s.Envelope
	if r == nil || r.Format != ReceiptFormat || r.TargetID != e.TargetID || r.Name != e.Name || r.Version != e.Version ||
		r.KeyID != e.KeyID || r.Nonce != e.Nonce || r.PolicyDigest != e.PolicyDigest || !validFingerprint(r.Fingerprint) {
		return "", ErrReceipt
	}
	tag, err := base64.RawURLEncoding.DecodeString(r.Tag)
	if err != nil || !hmac.Equal(tag, receiptTag(s.confirm, r)) {
		return "", ErrReceipt
	}
	return r.Fingerprint, nil
}

// Wipe clears the receipt secret.
func (s *Sealed) Wipe() { clear(s.confirm) }

func receiptTag(confirm []byte, r *Receipt) []byte {
	m := hmac.New(sha256.New, confirm)
	m.Write(lp([]byte(ReceiptFormat), []byte(r.TargetID), []byte(r.Name), u64(r.Version), []byte(r.KeyID), []byte(r.Nonce),
		[]byte(r.PolicyDigest), []byte(r.Fingerprint)))
	return m.Sum(nil)
}

// Opened is a decrypted envelope on the host.
type Opened struct {
	Value    []byte
	envelope Envelope
	confirm  []byte
}

// Open authenticates and decrypts env with the host's key. It enforces the
// target, the key id, the validity window and a version strictly newer than
// lastVersion (0 when the name has never been set).
func Open(key *HostKey, env *Envelope, lastVersion uint64, now time.Time) (*Opened, error) {
	if key == nil || env == nil {
		return nil, ErrContext
	}
	if err := env.validShape(); err != nil {
		return nil, err
	}
	if env.TargetID != key.record.TargetID || env.KeyID != key.record.KeyID {
		return nil, ErrContext
	}
	if !key.validAt(now) {
		return nil, ErrStale
	}
	sealedAt := time.UnixMilli(int64(env.Version))
	if env.Version > uint64(1<<62) || sealedAt.After(now.Add(MaxSkew)) || sealedAt.Before(now.Add(-MaxAge)) {
		return nil, ErrStale
	}
	if env.Version <= lastVersion {
		return nil, ErrReplay
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(env.Sealed)
	if err != nil || len(raw) < 32+16 {
		return nil, ErrEnvelope
	}
	kdf, aead := suite()
	recipient, err := hpke.NewRecipient(raw[:32], key.priv, kdf, aead, info(env.KeyID, env.TargetID))
	if err != nil {
		return nil, ErrOpen
	}
	value, err := recipient.Open(env.aad(), raw[32:])
	if err != nil {
		return nil, ErrOpen
	}
	if len(value) == 0 || len(value) > MaxValueBytes {
		clear(value)
		return nil, ErrValue
	}
	confirm, err := recipient.Export(exportReceipt, 32)
	if err != nil {
		clear(value)
		return nil, ErrOpen
	}
	return &Opened{Value: value, envelope: *env, confirm: confirm}, nil
}

// Receipt builds the authenticated receipt for a fingerprint.
func (o *Opened) Receipt(fingerprint string) *Receipt {
	e := &o.envelope
	r := &Receipt{Format: ReceiptFormat, TargetID: e.TargetID, Name: e.Name, Version: e.Version, KeyID: e.KeyID, Nonce: e.Nonce,
		PolicyDigest: e.PolicyDigest, Fingerprint: fingerprint}
	r.Tag = base64.RawURLEncoding.EncodeToString(receiptTag(o.confirm, r))
	return r
}

// Wipe clears the plaintext and the receipt secret.
func (o *Opened) Wipe() {
	clear(o.Value)
	clear(o.confirm)
}

// Fingerprint is HMAC-SHA256 under a host-held random key over the target,
// name and value, truncated to 128 bits. Without the key a fingerprint reveals
// nothing about the value, so a short or guessable secret cannot be brute
// forced from it; with the same key the same value always yields the same
// fingerprint, so an operator can see whether a stored secret changed.
func Fingerprint(fingerprintKey []byte, targetID, name string, value []byte) string {
	m := hmac.New(sha256.New, fingerprintKey)
	m.Write(lp([]byte("agentgate.secret-fingerprint.v1"), []byte(targetID), []byte(name), value))
	return "sfp1_" + hex.EncodeToString(m.Sum(nil)[:16])
}

func validFingerprint(f string) bool {
	if len(f) != 5+32 || f[:5] != "sfp1_" {
		return false
	}
	_, err := hex.DecodeString(f[5:])
	return err == nil
}

// ParseEnvelope strictly decodes an envelope.
func ParseEnvelope(raw []byte) (*Envelope, error) {
	var e Envelope
	if err := strictDecode(raw, &e); err != nil {
		return nil, ErrEnvelope
	}
	if err := e.validShape(); err != nil {
		return nil, err
	}
	return &e, nil
}

// ParseReceipt strictly decodes a receipt.
func ParseReceipt(raw []byte) (*Receipt, error) {
	var r Receipt
	if err := strictDecode(raw, &r); err != nil {
		return nil, ErrReceipt
	}
	return &r, nil
}

// strictDecode decodes one JSON object, refusing duplicate or non-lowercase
// keys (encoding/json matches names case-insensitively), unknown fields,
// null and trailing data.
func strictDecode(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes*2 {
		return ErrEnvelope
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return ErrEnvelope
	}
	if err := walk(dec, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrEnvelope
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func walk(dec *json.Decoder, depth int) error {
	return walkValue(dec, '{', depth)
}

func walkValue(dec *json.Decoder, delim json.Delim, depth int) error {
	if depth > 8 {
		return ErrEnvelope
	}
	seen := map[string]bool{}
	for dec.More() {
		if delim == '{' {
			t, err := dec.Token()
			key, ok := t.(string)
			if err != nil || !ok || seen[key] || key == "" || len(key) > 64 {
				return ErrEnvelope
			}
			for _, c := range key {
				if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
					return ErrEnvelope
				}
			}
			seen[key] = true
		}
		t, err := dec.Token()
		if err != nil || t == nil {
			return ErrEnvelope
		}
		if d, ok := t.(json.Delim); ok {
			if d != '{' && d != '[' {
				return ErrEnvelope
			}
			if err := walkValue(dec, d, depth+1); err != nil {
				return err
			}
		}
	}
	end := json.Delim('}')
	if delim == '[' {
		end = ']'
	}
	if t, err := dec.Token(); err != nil || t != end {
		return ErrEnvelope
	}
	return nil
}

// Encode is the envelope's wire string: unpadded base64url of its JSON. It
// fits a string field such as hostproto.SecretPutPayload.Ciphertext.
func (e *Envelope) Encode() string {
	raw, _ := json.Marshal(e)
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeEnvelope reverses Encode and validates the shape.
func DecodeEnvelope(s string) (*Envelope, error) {
	if len(s) > MaxEnvelopeBytes*2 {
		return nil, ErrEnvelope
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, ErrEnvelope
	}
	return ParseEnvelope(raw)
}

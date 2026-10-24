// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Package hostproto holds the wire types shared by the control service and
// agentgate-hostd, plus the signing helpers for both directions. It depends on
// the standard library only, so the host agent can import it without pulling in
// the service.
//
// Every signed message is an Envelope. The payload is the exact JSON bytes that
// were signed, carried as unpadded base64url, so neither side has to agree on a
// canonical re-encoding. The signature covers a fixed prefix, the message
// domain, the signer's key id and those bytes:
//
//	"agentgate-hostproto-v1" 0x00 domain 0x00 key_id 0x00 payload
//
// A signature for one domain can never be replayed as another.
package hostproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Message domains. Each one names exactly one payload type.
const (
	DomainEnroll = "agentgate.hostd.enroll.v1" // host -> service, EnrollRequest, signed by the new host key
	DomainPoll   = "agentgate.hostd.poll.v1"   // host -> service, PollRequest
	DomainEvents = "agentgate.hostd.events.v1" // host -> service, EventsRequest
	DomainJob    = "agentgate.hostd.job.v1"    // service -> host, Job, signed by the service job key
)

const signaturePrefix = "agentgate-hostproto-v1"

// Size bounds. A receiver rejects anything larger before decoding it.
const (
	MaxEnvelopeBytes = 1 << 20   // one encoded envelope
	MaxPayloadBytes  = 512 << 10 // the decoded payload of one envelope
)

var b64 = base64.RawURLEncoding.Strict()

// Envelope is one signed message.
type Envelope struct {
	Domain    string `json:"domain"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// KeyID names an Ed25519 public key: "ed25519:" and the first 16 bytes of its
// SHA-256 in lowercase hex.
func KeyID(public ed25519.PublicKey) string {
	sum := sha256.Sum256(public)
	return "ed25519:" + hex.EncodeToString(sum[:16])
}

// EncodeKey and DecodeKey move raw 32-byte keys as unpadded base64url.
func EncodeKey(key []byte) string { return b64.EncodeToString(key) }

// DecodeKey accepts only the canonical unpadded base64url form of a 32-byte key.
func DecodeKey(value string) ([]byte, error) {
	if len(value) != 43 {
		return nil, errors.New("hostproto: a key is 43 base64url characters")
	}
	raw, err := b64.DecodeString(value)
	if err != nil || len(raw) != 32 || b64.EncodeToString(raw) != value {
		return nil, errors.New("hostproto: invalid key encoding")
	}
	return raw, nil
}

// SHA256Hex returns the lowercase hex SHA-256 of data.
func SHA256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func signingInput(domain, keyID string, payload []byte) []byte {
	out := make([]byte, 0, len(signaturePrefix)+len(domain)+len(keyID)+len(payload)+3)
	out = append(out, signaturePrefix...)
	out = append(out, 0)
	out = append(out, domain...)
	out = append(out, 0)
	out = append(out, keyID...)
	out = append(out, 0)
	return append(out, payload...)
}

func knownDomain(domain string) bool {
	switch domain {
	case DomainEnroll, DomainPoll, DomainEvents, DomainJob:
		return true
	}
	return false
}

// SealBytes signs exact payload bytes.
func SealBytes(domain string, key ed25519.PrivateKey, payload []byte) (Envelope, error) {
	if !knownDomain(domain) {
		return Envelope{}, fmt.Errorf("hostproto: unknown domain %q", domain)
	}
	if len(key) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("hostproto: invalid signing key")
	}
	if len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return Envelope{}, errors.New("hostproto: payload is empty or too large")
	}
	id := KeyID(key.Public().(ed25519.PublicKey))
	return Envelope{Domain: domain, KeyID: id, Payload: b64.EncodeToString(payload), Signature: b64.EncodeToString(ed25519.Sign(key, signingInput(domain, id, payload)))}, nil
}

// Seal encodes value with encoding/json and signs the resulting bytes.
func Seal(domain string, key ed25519.PrivateKey, value any) (Envelope, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return Envelope{}, err
	}
	return SealBytes(domain, key, payload)
}

// Verify checks the domain, the key id and the signature, and returns the
// exact signed payload bytes. It does not decode them.
func Verify(env Envelope, domain string, public ed25519.PublicKey) ([]byte, error) {
	if env.Domain != domain || !knownDomain(domain) {
		return nil, errors.New("hostproto: envelope domain differs")
	}
	if len(public) != ed25519.PublicKeySize || env.KeyID != KeyID(public) {
		return nil, errors.New("hostproto: envelope key differs")
	}
	if len(env.Payload) > (MaxPayloadBytes*4+2)/3+4 || len(env.Signature) != 86 {
		return nil, errors.New("hostproto: envelope size invalid")
	}
	payload, err := b64.DecodeString(env.Payload)
	if err != nil || len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return nil, errors.New("hostproto: payload encoding invalid")
	}
	signature, err := b64.DecodeString(env.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("hostproto: signature encoding invalid")
	}
	if !ed25519.Verify(public, signingInput(domain, env.KeyID, payload), signature) {
		return nil, errors.New("hostproto: signature invalid")
	}
	return payload, nil
}

// Open verifies env and strictly decodes its payload into dst.
func Open(env Envelope, domain string, public ed25519.PublicKey, dst any) error {
	payload, err := Verify(env, domain, public)
	if err != nil {
		return err
	}
	return DecodeStrict(payload, dst)
}

// UnverifiedPayload decodes the payload without checking the signature. A
// receiver uses it only to find which key to verify with (for example the
// host id in a poll, or the public key in an enrollment), and must call Open
// before trusting any field.
func UnverifiedPayload(env Envelope, dst any) error {
	if len(env.Payload) > (MaxPayloadBytes*4+2)/3+4 {
		return errors.New("hostproto: envelope size invalid")
	}
	payload, err := b64.DecodeString(env.Payload)
	if err != nil || len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return errors.New("hostproto: payload encoding invalid")
	}
	return DecodeStrict(payload, dst)
}

// DecodeEnvelope strictly decodes one encoded envelope.
func DecodeEnvelope(raw []byte) (Envelope, error) {
	var env Envelope
	if len(raw) > MaxEnvelopeBytes {
		return env, errors.New("hostproto: envelope exceeds its size limit")
	}
	return env, DecodeStrict(raw, &env)
}

// DecodeStrict rejects duplicate keys, unknown fields and trailing data.
func DecodeStrict(raw []byte, dst any) error {
	if len(raw) > MaxEnvelopeBytes {
		return errors.New("hostproto: message exceeds its size limit")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueKeys(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("hostproto: one JSON value required")
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("hostproto: %w", err)
	}
	return nil
}

func uniqueKeys(dec *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("hostproto: JSON nesting too deep")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errors.New("hostproto: unexpected JSON delimiter")
	}
	keys := map[string]bool{}
	for dec.More() {
		if delim == '{' {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return errors.New("hostproto: duplicate JSON key")
			}
			keys[name] = true
		}
		if err := uniqueKeys(dec, depth+1); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validID(value string) bool {
	if len(value) != 32 {
		return false
	}
	return validDigest(value + value)
}

func validNonce(value string) bool {
	if len(value) < 22 || len(value) > 64 {
		return false
	}
	raw, err := b64.DecodeString(value)
	return err == nil && len(raw) >= 16 && b64.EncodeToString(raw) == value
}

func printable(value string, max int) bool {
	if len(value) > max {
		return false
	}
	return !strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

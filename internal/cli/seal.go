// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// Sealing a secret value for one target. The service relays the result but
// cannot read it, and it cannot substitute the key either: the CLI accepts a
// seal key only when it is signed by the host key whose fingerprint the
// operator approved and pinned (known-targets.json).
//
//	pinned host_key_id == the target's host_key_id
//	GET /targets/{id}/seal-key -> {host_public_key, host_key_fingerprint, record}
//	hostproto.KeyID(host_public_key) == pinned host_key_id
//	record (secretseal.SignedKeyRecord) signed by host_public_key, this target, in date
//	-> secretseal (RFC 9180 HPKE) envelope, Envelope.Encode() in the ciphertext field
//
// The host publishes the signed record (agentgate-hostd heartbeat) and the
// service serves it at the seal-key endpoint; a service or host without it
// gives the CLI nothing to verify, and secret set refuses. The retired
// hostproto.SealSecret format (an unsigned key, associated data without a
// version or nonce) is never used.

// sealKeyAnswer is the answer of GET /targets/{id}/seal-key.
type sealKeyAnswer struct {
	TargetID           string          `json:"target_id"`
	HostKeyID          string          `json:"host_key_id"`
	HostPublicKey      string          `json:"host_public_key"`
	HostKeyFingerprint string          `json:"host_key_fingerprint"`
	SealKeyID          string          `json:"seal_key_id"`
	NotAfter           string          `json:"not_after"`
	Record             json.RawMessage `json:"record"`
}

// sealPlan is a verified sealing path for one target.
type sealPlan struct {
	Method             string `json:"method"`
	TargetID           string `json:"target_id"`
	HostKeyID          string `json:"host_key_id"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	SealKeyID          string `json:"seal_key_id,omitempty"`
	Verified           bool   `json:"host_signed"`
	seal               func(name string, value []byte) (*sealedValue, error)
}

// sealedValue is one sealed value plus the secret that verifies the host's
// receipt. It stays in memory only; wipe clears it.
type sealedValue struct {
	ciphertext string
	sealed     *secretseal.Sealed
}

// verify checks the host's receipt and returns the value fingerprint it
// reports: only the host that opened exactly this envelope can produce it.
func (v *sealedValue) verify(raw []byte) (string, error) {
	r, err := secretseal.ParseReceipt(raw)
	if err == nil {
		var fp string
		if fp, err = v.sealed.VerifyReceipt(r); err == nil {
			return fp, nil
		}
	}
	return "", trustError("receipt_invalid", "The host's receipt does not match the envelope this machine sealed: the service relayed a different ciphertext, or the receipt was altered.",
		"Remove the secret (agentgate secret rm NAME) and do not store secrets through this service until you know why.")
}

func (v *sealedValue) wipe() { v.sealed.Wipe() }

const sealMethodSigned = "secretseal-hpke"

func pinHint(t Target) string {
	return "Compare the fingerprint on the host console, then run agentgate target pin " + t.Name + " --host-key-id <host's fingerprint> (or approve the key with agentgate target approve-key, which pins it)."
}

// planSeal checks the pin and the service's key material before anything
// secret is read. It never contacts the network.
func planSeal(pin *KnownTarget, t Target, sk *sealKeyAnswer, now time.Time) (*sealPlan, error) {
	if pin == nil {
		return nil, trustError("host_key_not_pinned", "No host key is pinned on this machine for target "+t.Name+" ("+t.ID+").", pinHint(t))
	}
	if t.HostKeyID == "" || subtle.ConstantTimeCompare([]byte(pin.HostKeyID), []byte(t.HostKeyID)) != 1 {
		return nil, trustError("host_key_pin_mismatch", "The service reports host key "+t.HostKeyID+" for target "+t.Name+", but this machine pinned "+pin.HostKeyID+". Nothing was sent.",
			"Do not store secrets on this target until you know why: if the host was re-enrolled on purpose, approve its new key (agentgate target approve-key) after comparing it on the host console.")
	}
	if sk == nil {
		return nil, trustError("seal_key_unpublished", "The service does not publish a host-signed seal key for target "+t.Name+" (GET /targets/ID/seal-key), so there is no key the CLI can verify against the pinned host key. Nothing was read or sent.",
			"Upgrade the service and agentgate-hostd so the host publishes its signed seal key, then run secret set again.")
	}
	if sk.HostPublicKey == "" || len(sk.Record) == 0 || string(sk.Record) == "null" {
		return nil, trustError("seal_key_incomplete", "The service published only part of the target's seal key material.", "Report this to the service operator; nothing was sent.")
	}
	if (sk.TargetID != "" && sk.TargetID != t.ID) || (sk.HostKeyID != "" && sk.HostKeyID != t.HostKeyID) {
		return nil, trustError("seal_key_inconsistent", "The service answered with the seal key of another target or host key. Nothing was sent.", "Report this to the service operator.")
	}
	raw, err := hostproto.DecodeKey(sk.HostPublicKey)
	if err != nil {
		return nil, trustError("seal_key_invalid", "The service reported an invalid host public key.", "Report this to the service operator; nothing was sent.")
	}
	hostPub := ed25519.PublicKey(raw)
	if subtle.ConstantTimeCompare([]byte(hostproto.KeyID(hostPub)), []byte(pin.HostKeyID)) != 1 {
		return nil, trustError("host_key_substituted", "The host public key the service sent has fingerprint "+hostproto.KeyID(hostPub)+", not the pinned "+pin.HostKeyID+". Nothing was sent.",
			"The service (or something between you and it) substituted the host key: do not store secrets through it.")
	}
	if sk.HostKeyFingerprint != "" && sk.HostKeyFingerprint != secretseal.HostKeyFingerprint(hostPub) {
		return nil, trustError("seal_key_inconsistent", "The service's host key fingerprint does not match the host public key it sent. Nothing was sent.", "Report this to the service operator.")
	}
	if pin.HostKeyFingerprint != "" && subtle.ConstantTimeCompare([]byte(pin.HostKeyFingerprint), []byte(secretseal.HostKeyFingerprint(hostPub))) != 1 {
		return nil, trustError("host_key_substituted", "The host public key the service sent does not match the pinned "+pin.HostKeyFingerprint+". Nothing was sent.",
			"The service (or something between you and it) substituted the host key: do not store secrets through it.")
	}
	rec, err := secretseal.ParseSignedKeyRecord(sk.Record)
	if err != nil {
		return nil, trustError("seal_key_invalid", "The target's seal key record is malformed.", "Report this to the service operator; nothing was sent.")
	}
	pub, err := secretseal.VerifyKeyRecord(rec, hostPub, secretseal.HostKeyFingerprint(hostPub), t.ID, now)
	if err != nil {
		msg := "The target's seal key is not valid for this target and time. Nothing was sent."
		if errors.Is(err, secretseal.ErrSignature) || errors.Is(err, secretseal.ErrFingerprint) {
			msg = "The target's seal key is not signed by the pinned host key. Nothing was sent."
		}
		return nil, trustError("seal_key_unverified", msg, "Do not store secrets through this service until the host publishes a fresh signed seal key (restart agentgate-hostd).")
	}
	return &sealPlan{Method: sealMethodSigned, TargetID: t.ID, HostKeyID: pin.HostKeyID, HostKeyFingerprint: secretseal.HostKeyFingerprint(hostPub), SealKeyID: pub.KeyID(), Verified: true, seal: func(name string, value []byte) (*sealedValue, error) {
		sealed, err := secretseal.SealAt(pub, t.ID, name, value, now)
		if err != nil {
			return nil, failure("cannot seal the value: %v", err)
		}
		return &sealedValue{ciphertext: sealed.Envelope.Encode(), sealed: sealed}, nil
	}}, nil
}

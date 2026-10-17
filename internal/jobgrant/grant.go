// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobgrant

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"time"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var hash64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

func signingBytes(e Envelope) []byte {
	e.Signature = ""
	raw, _ := json.Marshal(e)
	return append([]byte("AGENTGATE_FULL_JOB_GRANT_V1\n"), raw...)
}
func validateClaims(c Claims, d policy.Document) error {
	if d.Profile != policy.KernelProfile || d.Lifecycle == nil || c.Binding.Validate(false) != nil {
		return errors.New("a full immutable job binding and document are required")
	}
	digest, err := d.Digest()
	if err != nil {
		return err
	}
	required, err := policy.Requirements(d)
	if err != nil {
		return err
	}
	if digest != c.DocumentDigest || digest != c.Binding.PolicyDigest || c.Binding.SchemaDigest != policy.SchemaDigest() || !reflect.DeepEqual(required, c.RequiredCapabilities) || !hash64.MatchString(c.QualificationDigest) || !hash64.MatchString(c.AuditHeaderDigest) {
		return errors.New("the full grant document, schema, capability or evidence binding differs")
	}
	if c.IssuedAt < 0 || c.NotBefore < c.IssuedAt || c.ExpiresAt <= c.NotBefore || c.IssuedMonoNS == 0 || c.DeadlineNS != c.Binding.DeadlineNS || c.DeadlineNS <= c.IssuedMonoNS {
		return errors.New("the full grant lifetime is invalid")
	}
	seconds := int64(d.Lifecycle.DurationSeconds)
	if seconds <= 0 || c.ExpiresAt-c.IssuedAt > seconds || c.DeadlineNS-c.IssuedMonoNS > uint64(seconds)*uint64(time.Second) {
		return errors.New("the full grant exceeds the document lifetime")
	}
	return nil
}

// Sign belongs in the authority. A node verifier never receives this private key.
func Sign(authorityID, keyID string, key ed25519.PrivateKey, c Claims, d policy.Document) (Envelope, error) {
	e := Envelope{Protocol: Protocol, AuthorityID: authorityID, KeyID: keyID, Claims: c}
	if !identifier.MatchString(authorityID) || !identifier.MatchString(keyID) || len(key) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("the full grant authority key is invalid")
	}
	if err := validateClaims(c, d); err != nil {
		return Envelope{}, err
	}
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, signingBytes(e)))
	raw, _ := json.Marshal(e)
	var copy Envelope
	_ = json.Unmarshal(raw, &copy)
	return copy, nil
}
func Encode(e Envelope) (string, error) {
	raw, err := json.Marshal(e)
	if err != nil || len(raw) > 32768 {
		return "", errors.New("the full grant exceeds its bound")
	}
	return string(raw), nil
}
func Decode(raw string) (Envelope, error) {
	var e Envelope
	if len(raw) > 32768 {
		return e, errors.New("the full grant exceeds its bound")
	}
	err := lifecycle.DecodeTransport(bytes.NewBufferString(raw), &e)
	if err != nil {
		return e, err
	}
	if e.Protocol != Protocol {
		return Envelope{}, errors.New("the full grant protocol is unsupported")
	}
	return e, nil
}
func VerifySigned(e Envelope, keys map[string]ed25519.PublicKey, d policy.Document) (Claims, error) {
	if e.Protocol != Protocol || !identifier.MatchString(e.AuthorityID) || !identifier.MatchString(e.KeyID) {
		return Claims{}, errors.New("the full grant protocol or authority is invalid")
	}
	key := keys[e.AuthorityID+"/"+e.KeyID]
	sig, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(sig) != e.Signature || len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, signingBytes(e), sig) {
		return Claims{}, errors.New("the full grant signature differs from pinned authority trust")
	}
	if err = validateClaims(e.Claims, d); err != nil {
		return Claims{}, err
	}
	raw, _ := json.Marshal(e.Claims)
	var c Claims
	_ = json.Unmarshal(raw, &c)
	return c, nil
}
func Digest(e Envelope) string {
	raw, _ := json.Marshal(e)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

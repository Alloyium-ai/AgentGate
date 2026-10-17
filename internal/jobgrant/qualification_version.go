// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobgrant

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
)

const QualificationVersionProtocol = "agentgate.native-version-grant.v1"
const qualificationVersionDomain = "AGENTGATE_NATIVE_VERSION_GRANT_V1\n"

func qualificationVersionSigningBytes(e Envelope) []byte {
	e.Signature = ""
	raw, _ := json.Marshal(e)
	return append([]byte(qualificationVersionDomain), raw...)
}

func SignQualificationVersion(authorityID, keyID string, key ed25519.PrivateKey, c Claims, d policy.Document, spec lifecycle.QualificationVersionSpec) (Envelope, error) {
	scope, err := lifecycle.QualificationVersionScopeDigest(spec)
	expected := spec.Binding
	expected.CgroupID = c.Binding.CgroupID
	if err != nil || scope != c.QualificationDigest || !reflect.DeepEqual(expected, c.Binding) || spec.CandidateDigest != c.DocumentDigest {
		return Envelope{}, errors.New("the version authority requires its exact candidate and permit scope")
	}
	if !identifier.MatchString(authorityID) || !identifier.MatchString(keyID) || len(key) != ed25519.PrivateKeySize {
		return Envelope{}, errors.New("the version authority key is invalid")
	}
	if err = validateClaims(c, d); err != nil {
		return Envelope{}, err
	}
	e := Envelope{Protocol: QualificationVersionProtocol, AuthorityID: authorityID, KeyID: keyID, Claims: c}
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, qualificationVersionSigningBytes(e)))
	raw, _ := json.Marshal(e)
	var out Envelope
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

func DecodeQualificationVersion(raw string) (Envelope, error) {
	var e Envelope
	if len(raw) > 32768 {
		return e, errors.New("the version grant exceeds its bound")
	}
	if err := lifecycle.DecodeTransport(bytes.NewBufferString(raw), &e); err != nil {
		return e, err
	}
	if e.Protocol != QualificationVersionProtocol {
		return Envelope{}, errors.New("the version grant protocol differs")
	}
	return e, nil
}

func VerifyQualificationVersionSigned(e Envelope, keys map[string]ed25519.PublicKey, d policy.Document) (Claims, error) {
	if e.Protocol != QualificationVersionProtocol || !identifier.MatchString(e.AuthorityID) || !identifier.MatchString(e.KeyID) {
		return Claims{}, errors.New("the version grant protocol or authority differs")
	}
	key := keys[e.AuthorityID+"/"+e.KeyID]
	signature, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != e.Signature || len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, qualificationVersionSigningBytes(e), signature) {
		return Claims{}, errors.New("the version grant signature differs")
	}
	if err = validateClaims(e.Claims, d); err != nil {
		return Claims{}, err
	}
	raw, _ := json.Marshal(e.Claims)
	var out Claims
	_ = json.Unmarshal(raw, &out)
	return out, nil
}

func NewQualificationVersionVerifier(c Config, p *lifecycle.QualificationFixturePermit) (*Verifier, error) {
	if p == nil || p.Purpose() != lifecycle.QualificationVersionPurpose {
		return nil, errors.New("the native version verifier requires its own permit purpose")
	}
	return newQualificationVerifier(c, p)
}

func (v *Verifier) verifySignedAuthorization(raw string, d policy.Document) (Claims, error) {
	if v.fixture != nil && v.fixture.Purpose() == lifecycle.QualificationVersionPurpose {
		e, err := DecodeQualificationVersion(raw)
		if err != nil {
			return Claims{}, err
		}
		return VerifyQualificationVersionSigned(e, v.config.Authorities, d)
	}
	e, err := Decode(raw)
	if err != nil {
		return Claims{}, err
	}
	return VerifySigned(e, v.config.Authorities, d)
}

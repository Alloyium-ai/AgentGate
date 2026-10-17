// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobaudit

import (
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var hash64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

func clone[T any](v T) T {
	raw, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}
func hash(domain string, v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(append([]byte(domain), raw...))
	return hex.EncodeToString(sum[:])
}
func HeaderBytes(h Header) ([]byte, error) {
	if h.FixturePurpose != "" && h.FixturePurpose != lifecycle.QualificationFixturePurpose && h.FixturePurpose != lifecycle.QualificationVersionPurpose {
		return nil, errors.New("the audit fixture purpose is unsupported")
	}
	if h.Protocol != HeaderProtocol || h.Binding.Validate(false) != nil || h.DocumentDigest != h.Binding.PolicyDigest || !hash64.MatchString(h.QualificationDigest) || h.CreatedMonoNS == 0 || h.CreatedMonoNS >= h.Binding.DeadlineNS || len(h.RequiredCapabilities) == 0 || len(h.RequiredStreams) == 0 || len(h.RequiredStreams) > 64 {
		return nil, errors.New("the full audit header is invalid")
	}
	names := map[string]bool{}
	caps := map[string]bool{}
	resources := 0
	observations := 0
	for _, cap := range h.RequiredCapabilities {
		if cap == "" || caps[cap] {
			return nil, errors.New("the audit capability registry is invalid")
		}
		caps[cap] = true
	}
	for _, s := range h.RequiredStreams {
		if !identifier.MatchString(s.Name) || !identifier.MatchString(s.Version) || names[s.Name] || !hash64.MatchString(s.ArtifactDigest) || (s.Kind != "resource" && s.Kind != "observation" && s.Kind != "control") {
			return nil, errors.New("the audit stream registry is invalid")
		}
		names[s.Name] = true
		artifactKnown := false
		for _, value := range h.Binding.ArtifactDigests {
			artifactKnown = artifactKnown || value == s.ArtifactDigest
		}
		if !artifactKnown {
			return nil, errors.New("the stream artifact is absent from the job binding")
		}
		if s.Kind == "resource" {
			f, ok := resourceFormats[s.Name]
			if !ok || f.Version != s.Version {
				return nil, errors.New("the resource stream format is unknown")
			}
			resources++
		}
		if s.Kind == "observation" {
			f, ok := observationFormats[s.Name]
			if !ok || (f.Version != s.Version && !(s.Name == "syscalls" && s.Version == syscallrules.LegacyFormat)) {
				return nil, errors.New("the observation stream format is unknown")
			}
			observations++
		}
	}
	if resources != len(resourceFormats) || observations != len(observationFormats) {
		return nil, errors.New("the audit header requires every mandatory resource stream")
	}
	return json.Marshal(h)
}
func HeaderDigest(h Header) (string, error) {
	raw, err := HeaderBytes(h)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(HeaderDomain), raw...))
	return hex.EncodeToString(sum[:]), nil
}
func eventDigest(e Event) string { e.Digest = ""; return hash("AGENTGATE_JOB_AUDIT_EVENT_V1\n", e) }
func sealBytes(s NodeSeal) []byte {
	s.Signature = ""
	raw, _ := json.Marshal(s)
	return append([]byte("AGENTGATE_JOB_AUDIT_SEAL_V1\n"), raw...)
}
func SealDigest(s NodeSeal) string { return hash("AGENTGATE_JOB_AUDIT_SIGNED_SEAL_V1\n", s) }
func receiptBytes(r AuthorityReceipt) []byte {
	r.Signature = ""
	raw, _ := json.Marshal(r)
	return append([]byte("AGENTGATE_JOB_AUDIT_AUTHORITY_V1\n"), raw...)
}
func validSignature(public ed25519.PublicKey, raw []byte, encoded string) bool {
	sig, err := base64.RawURLEncoding.DecodeString(encoded)
	return err == nil && base64.RawURLEncoding.EncodeToString(sig) == encoded && len(public) == ed25519.PublicKeySize && ed25519.Verify(public, raw, sig)
}
func grantMatches(h Header, e jobgrant.Envelope, trust Trust) error {
	var c jobgrant.Claims
	var err error
	if h.FixturePurpose == lifecycle.QualificationVersionPurpose {
		c, err = jobgrant.VerifyQualificationVersionSigned(e, trust.AuthorityKeys, trust.Document)
	} else {
		c, err = jobgrant.VerifySigned(e, trust.AuthorityKeys, trust.Document)
	}
	if err != nil {
		return err
	}
	digest, err := HeaderDigest(h)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(h.Binding, c.Binding) || h.DocumentDigest != c.DocumentDigest || h.QualificationDigest != c.QualificationDigest || !reflect.DeepEqual(h.RequiredCapabilities, c.RequiredCapabilities) || c.AuditHeaderDigest != digest || c.IssuedMonoNS < h.CreatedMonoNS {
		return errors.New("the full grant differs from its prepared audit header")
	}
	return nil
}

// SignReceipt belongs in the authority after it verifies the node evidence.
func SignReceipt(authorityID, keyID string, key ed25519.PrivateKey, b Bundle, trust Trust, issuedAt int64) (AuthorityReceipt, error) {
	verdict := verify(b, trust, false)
	if verdict.State != "VALID_COMPLETE" || !identifier.MatchString(authorityID) || !identifier.MatchString(keyID) || len(key) != ed25519.PrivateKeySize || issuedAt < 0 || issuedAt < b.Grant.Claims.IssuedAt {
		return AuthorityReceipt{}, errors.New("the authority cannot accept incomplete node evidence")
	}
	r := AuthorityReceipt{"agentgate.full-job-authority-receipt.v1", authorityID, keyID, clone(b.Header.Binding), SealDigest(*b.Seal), issuedAt, true, ""}
	r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, receiptBytes(r)))
	return r, nil
}

type Format struct {
	Version string
	Bytes   int
}

var resourceFormats = map[string]Format{"files": {"files216.v1", 216}, "peers": {"peers96.v2", 96}, "sockets": {"sockets112.v1", 112}, "custody": {"custody64.v1", 64}, "process": {"process80.v1", 80}}

func ResourceFormats() map[string]Format {
	out := map[string]Format{}
	for name, f := range resourceFormats {
		out[name] = f
	}
	return out
}

var observationFormats = map[string]Format{"syscalls": {syscallrules.Format, 128}}

func observationFormat(name, version string) Format {
	if name == "syscalls" && version == syscallrules.LegacyFormat {
		return Format{syscallrules.LegacyFormat, 104}
	}
	format := observationFormats[name]
	if format.Version != version {
		return Format{}
	}
	return format
}

func ObservationFormats() map[string]Format {
	out := map[string]Format{}
	for name, f := range observationFormats {
		out[name] = f
	}
	return out
}

func separateTrust(nodes, authorities map[string]ed25519.PublicKey) bool {
	if len(nodes) == 0 || len(authorities) == 0 {
		return false
	}
	for _, n := range nodes {
		if len(n) != ed25519.PublicKeySize {
			return false
		}
		for _, a := range authorities {
			if len(a) != ed25519.PublicKeySize || bytes.Equal(n, a) {
				return false
			}
		}
	}
	return true
}

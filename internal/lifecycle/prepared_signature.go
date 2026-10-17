// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

const PreparedSigningDomain = "AGENTGATE_JOB_PREPARED_V1\n"

type PreparedNodeTime struct {
	Wall   int64
	MonoNS uint64
}

func preparedContent(r PrepareResponse) error {
	if r.Protocol != PreparedProtocol || r.Binding.Validate(false) != nil || !identifier.MatchString(r.PreparationKeyID) || r.ManifestDigest != r.Binding.JobDigest || r.PreparedAtUnix <= 0 || r.PreparedMonoNS == 0 || r.PreparedMonoNS >= r.PreparationDeadlineNS || r.PreparationDeadlineNS > r.Binding.DeadlineNS || r.PreparationDeadlineNS-r.PreparedMonoNS > uint64(30*time.Second) || len(r.AuditHeader) == 0 || len(r.AuditHeader) > 65536 || !validDigest(r.AuditHeaderDigest) {
		return errors.New("the signed preparation content is invalid")
	}
	if r.Evidence.FixturePurpose != "" {
		return errors.New("qualification fixtures have no normal preparation signature")
	}
	if checkEvidence(r.Evidence, r.Binding, "quarantined") != nil || !r.Evidence.Empty || r.Evidence.RightsRemoved {
		return errors.New("the signed preparation lacks an empty enforced quarantine")
	}
	digest := sha256.Sum256(append([]byte("AGENTGATE_JOB_AUDIT_HEADER_V1\n"), r.AuditHeader...))
	if hex.EncodeToString(digest[:]) != r.AuditHeaderDigest {
		return errors.New("the signed preparation audit header digest differs")
	}
	var header map[string]json.RawMessage
	if DecodeTransport(bytes.NewReader(r.AuditHeader), &header) != nil {
		return errors.New("the signed preparation audit header is ambiguous")
	}
	if raw, ok := header["fixture_purpose"]; ok {
		var purpose string
		if json.Unmarshal(raw, &purpose) != nil || purpose != "" {
			return errors.New("a fixture header cannot enter normal admission")
		}
	}
	var binding Binding
	var created uint64
	var protocol, document string
	var required []string
	if DecodeTransport(bytes.NewReader(header["binding"]), &binding) != nil || !reflect.DeepEqual(binding, r.Binding) || json.Unmarshal(header["created_mono_ns"], new(string)) != nil || json.Unmarshal(header["protocol"], &protocol) != nil || protocol != "agentgate.full-job-audit.v1" || json.Unmarshal(header["document_digest"], &document) != nil || document != binding.PolicyDigest || json.Unmarshal(header["required_capabilities"], &required) != nil || checkCapabilities(r.Evidence, required) != nil {
		return errors.New("the signed preparation header binding differs")
	}
	var encoded string
	_ = json.Unmarshal(header["created_mono_ns"], &encoded)
	if json.Unmarshal([]byte(encoded), &created) != nil || created == 0 || created > r.PreparedMonoNS {
		return errors.New("the signed preparation node clock differs")
	}
	return nil
}

// PrepareSigningBytes binds the complete typed response. The caller sets its
// measured times and signer ID before requesting a node signature.
func PrepareSigningBytes(r PrepareResponse) ([]byte, error) {
	if err := preparedContent(r); err != nil {
		return nil, err
	}
	r.PreparationSignature = ""
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(PreparedSigningDomain), raw...), nil
}

// VerifyPrepared uses nodeID/keyID trust. Authority hosts compare wall freshness
// and use the returned node monotonic sample; they never substitute their own.
func VerifyPrepared(r PrepareResponse, pinned map[string]ed25519.PublicKey, expected Binding, nowWall int64, maxAge time.Duration) (PreparedNodeTime, error) {
	if expected.Validate(expected.CgroupID == 0) != nil || maxAge < time.Second || maxAge > 30*time.Second || maxAge%time.Second != 0 || nowWall <= 0 {
		return PreparedNodeTime{}, errors.New("the preparation verification context is invalid")
	}
	if expected.CgroupID == 0 {
		expected.CgroupID = r.Binding.CgroupID
	}
	if !reflect.DeepEqual(expected, r.Binding) || r.PreparedAtUnix > nowWall+1 || nowWall-r.PreparedAtUnix > int64(maxAge/time.Second) {
		return PreparedNodeTime{}, errors.New("the preparation binding or wall freshness differs")
	}
	raw, err := PrepareSigningBytes(r)
	if err != nil {
		return PreparedNodeTime{}, err
	}
	age := nowWall - r.PreparedAtUnix
	if age < 0 {
		age = 0
	}
	if uint64(age)*uint64(time.Second) >= r.PreparationDeadlineNS-r.PreparedMonoNS {
		return PreparedNodeTime{}, errors.New("the signed preparation lease expired")
	}
	public := pinned[r.Binding.NodeID+"/"+r.PreparationKeyID]
	signature, err := base64.RawURLEncoding.DecodeString(r.PreparationSignature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != r.PreparationSignature || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, raw, signature) {
		return PreparedNodeTime{}, errors.New("the preparation signature differs from pinned node trust")
	}
	return PreparedNodeTime{r.PreparedAtUnix, r.PreparedMonoNS}, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func signedPreparation(t *testing.T) (PrepareResponse, ed25519.PrivateKey, map[string]ed25519.PublicKey) {
	t.Helper()
	b := fixtureBinding()
	b.CgroupID = 100
	b.DeadlineNS = uint64(60 * time.Second)
	header, _ := json.Marshal(map[string]any{"protocol": "agentgate.full-job-audit.v1", "binding": b, "document_digest": b.PolicyDigest, "created_mono_ns": "1", "required_capabilities": []string{"fs.rules.v1"}})
	digest := sha256.Sum256(append([]byte("AGENTGATE_JOB_AUDIT_HEADER_V1\n"), header...))
	r := PrepareResponse{PreparationKeyID: "node-key", PreparedAtUnix: 150, PreparedMonoNS: uint64(time.Second), AuditHeader: header, AuditHeaderDigest: hex.EncodeToString(digest[:]), Protocol: PreparedProtocol, Binding: b, ManifestDigest: b.JobDigest, PreparationDeadlineNS: uint64(10 * time.Second), Evidence: backendFixture().evidence(b, "quarantined")}
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", 32)))
	raw, err := PrepareSigningBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	r.PreparationSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, raw))
	return r, key, map[string]ed25519.PublicKey{b.NodeID + "/node-key": key.Public().(ed25519.PublicKey)}
}
func TestSignedPreparationBindsAnEmptyDomainAndTrustedNodeTime(t *testing.T) {
	r, _, keys := signedPreparation(t)
	expected := clone(r.Binding)
	expected.CgroupID = 0
	result, err := VerifyPrepared(r, keys, expected, 151, 30*time.Second)
	if err != nil || result.Wall != 150 || result.MonoNS != uint64(time.Second) {
		t.Fatal("signed node custody or time differs", err)
	}
	if r.Binding.CgroupID != 100 || expected.CgroupID != 0 {
		t.Fatal("verification changed the immutable caller binding")
	}
}
func TestSignedPreparationRejectsForgeryAndLeaseOrIdentityChanges(t *testing.T) {
	for _, name := range []string{"unsigned", "key", "signature", "binding", "header", "evidence", "time", "stale", "lease", "future", "context"} {
		t.Run(name, func(t *testing.T) {
			r, _, keys := signedPreparation(t)
			expected := clone(r.Binding)
			now := int64(151)
			switch name {
			case "unsigned":
				r.PreparationSignature = ""
			case "key":
				keys = map[string]ed25519.PublicKey{}
			case "signature":
				r.PreparationSignature = strings.Repeat("A", 86)
			case "binding":
				expected.AgentID = "other-agent"
			case "header":
				r.AuditHeader = append(r.AuditHeader, ' ')
			case "evidence":
				r.Evidence.Empty = false
			case "time":
				r.PreparedMonoNS++
			case "stale":
				now = 181
			case "lease":
				now = 159
			case "future":
				now = 148
			case "context":
				expected.BootID = "other-boot"
			}
			if _, err := VerifyPrepared(r, keys, expected, now, 30*time.Second); err == nil {
				t.Fatal("untrusted preparation passed")
			}
		})
	}
}
func TestPreparationSignerRejectsUnqualifiedOrExpiredContent(t *testing.T) {
	for _, name := range []string{"empty", "hooks", "capability", "deadline", "header-time", "generation"} {
		t.Run(name, func(t *testing.T) {
			r, _, _ := signedPreparation(t)
			switch name {
			case "empty":
				r.Evidence.Empty = false
			case "hooks":
				r.Evidence.MandatoryHooks = false
			case "capability":
				cap := r.Evidence.Capabilities["fs.rules.v1"]
				cap.State = "probe-only"
				r.Evidence.Capabilities["fs.rules.v1"] = cap
			case "deadline":
				r.PreparedMonoNS = r.PreparationDeadlineNS
			case "header-time":
				r.PreparedMonoNS = 0
			case "generation":
				r.Binding.Generation++
			}
			r.Evidence.Digest = EvidenceDigest(r.Evidence)
			if _, err := PrepareSigningBytes(r); err == nil {
				t.Fatal("invalid quarantine content could be signed")
			}
		})
	}
}

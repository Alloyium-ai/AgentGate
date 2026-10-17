// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
)

func versionResponseFixture(t *testing.T) (QualificationVersionPrepared, lifecycle.QualificationVersionSpec, map[string]ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()
	old, base, keys, watch := qualificationResponseFixture(t)
	spec := lifecycle.QualificationVersionSpec(base)
	spec.Manifest.RuntimeVersion = lifecycle.QualificationVersionRuntime
	spec.Manifest.Executable = lifecycle.QualificationVersionExecutable
	spec.Manifest.ExecutableDigest = lifecycle.QualificationVersionSHA256
	spec.Manifest.Arguments = []string{"--version"}
	sum := sha256.Sum256(nil)
	spec.Manifest.InputDigest = hex.EncodeToString(sum[:])
	spec.Binding.JobDigest, _ = spec.Manifest.Digest()
	files, _ := runtimeclosure.New([]runtimeclosure.File{})
	spec.Binding.ArtifactDigests["runtime.codex"] = lifecycle.QualificationVersionSHA256
	spec.Binding.ArtifactDigests["runtime.codex.files"] = files.Digest()
	d, err := policy.Parse(spec.Document, "json")
	if err != nil {
		t.Fatal(err)
	}
	d.Runtime.Seccomp.AllowSyscalls = []string{"execve"}
	d.Programs.Rules = []policy.ProgramRule{{ID: "version-exec", Selector: policy.Selector{Kind: "exact", Path: spec.Manifest.Executable}, Effect: "allow"}}
	d.Files.Rules = []policy.FileRule{{ID: "version-image", Selector: policy.Selector{Kind: "exact", Path: spec.Manifest.Executable}, Operations: []string{"read", "mmap", "map_execute"}, Effect: "allow"}}
	d.RequiredCapabilities, err = policy.Requirements(d)
	if err != nil {
		t.Fatal(err)
	}
	spec.Binding.PolicyDigest, err = d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	spec.CandidateDigest = spec.Binding.PolicyDigest
	spec.Document, err = d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	scope, err := lifecycle.QualificationVersionScopeDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	b := spec.Binding
	b.CgroupID = old.Record.Binding.CgroupID
	r := QualificationVersionPrepared(old)
	r.Protocol = QualificationVersionPreparedProtocol
	r.Purpose = lifecycle.QualificationVersionPurpose
	r.PermitDigest = scope
	r.Record.Binding = b
	e := &r.Record.Evidence[0]
	e.Binding = b
	e.FixturePurpose = r.Purpose
	for _, id := range d.RequiredCapabilities {
		e.Capabilities[id] = lifecycle.Capability{State: "fixture-only", Mechanisms: []string{r.Purpose}, EvidenceDigest: scope}
	}
	e.Digest = lifecycle.EvidenceDigest(*e)
	r.Record.Watchdog.Binding = b
	r.Record.Watchdog.Signature = ""
	raw, _ := json.Marshal(r.Record.Watchdog)
	watchKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	r.Record.Watchdog.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(watchKey, append([]byte("agentgate-watchdog-custody-v1\n"), raw...)))
	var header jobaudit.Header
	if err = json.Unmarshal(r.AuditHeader, &header); err != nil {
		t.Fatal(err)
	}
	header.FixturePurpose = r.Purpose
	header.Binding = b
	header.DocumentDigest = b.PolicyDigest
	header.QualificationDigest = scope
	header.RequiredCapabilities = d.RequiredCapabilities
	r.AuditHeader, err = jobaudit.HeaderBytes(header)
	if err != nil {
		t.Fatal(err)
	}
	r.AuditHeaderDigest, err = jobaudit.HeaderDigest(header)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := QualificationVersionPreparedSigningBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)), encoded))
	return r, spec, keys, watch
}

func TestVersionPreparationHasSeparatePurposeAndSigningDomain(t *testing.T) {
	r, spec, keys, watch := versionResponseFixture(t)
	if _, err := VerifyQualificationVersionPrepared(r, spec, keys, watch, 100, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := QualificationPreparedSigningBytes(QualificationPrepared(r)); err == nil {
		t.Fatal("the version preparation entered fixed-worker signing")
	}
	if _, err := VerifyQualificationPrepared(QualificationPrepared(r), lifecycle.QualificationFixtureSpec(spec), keys, watch, 100, 5*time.Second); err == nil {
		t.Fatal("the version preparation entered fixed-worker verification")
	}
	r.Signature = ""
	raw, _ := json.Marshal(r)
	r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32)), append([]byte(QualificationPreparedDomain), raw...)))
	if _, err := VerifyQualificationVersionPrepared(r, spec, keys, watch, 100, 5*time.Second); err == nil {
		t.Fatal("the fixed-worker signing domain entered native-version verification")
	}
}

func TestVersionPreparationRejectsChangedCandidateAndRawDenial(t *testing.T) {
	for _, name := range []string{"candidate", "quarantine", "manifest", "watchdog", "signature"} {
		t.Run(name, func(t *testing.T) {
			r, spec, keys, watch := versionResponseFixture(t)
			switch name {
			case "candidate":
				spec.CandidateDigest = spec.TargetDigest
			case "quarantine":
				r.Quarantine.Domain++
			case "manifest":
				spec.Manifest.Arguments = []string{"exec", "prompt"}
			case "watchdog":
				watch = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{8}, 32)).Public().(ed25519.PublicKey)
			case "signature":
				r.Signature = "changed"
			}
			if _, err := VerifyQualificationVersionPrepared(r, spec, keys, watch, 100, 5*time.Second); err == nil {
				t.Fatal("a changed version preparation passed")
			}
		})
	}
}

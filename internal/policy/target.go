// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
)

const CapabilityVersion = "agentgate.capabilities.v1"
const CompilerVersion = "agentgate.policy-preview.v1"

var hash64 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var revision40 = regexp.MustCompile(`^[a-f0-9]{40}$`)

type Capability struct {
	State         string   `json:"state"`
	Mechanisms    []string `json:"mechanisms"`
	ReceiptSHA256 string   `json:"receipt_sha256"`
}
type HookProbe struct {
	Hook     string `json:"hook"`
	Helper   string `json:"helper"`
	Loaded   bool   `json:"loaded"`
	Attached bool   `json:"attached"`
	Error    string `json:"error,omitempty"`
}
type CapabilityReport struct {
	SchemaVersion      string                `json:"schema_version"`
	Node               string                `json:"node"`
	Boot               string                `json:"boot"`
	Challenge          string                `json:"challenge"`
	Kernel             string                `json:"kernel"`
	Architecture       string                `json:"architecture"`
	SourceRevision     string                `json:"source_revision"`
	ArtifactSHA256     string                `json:"artifact_sha256"`
	PolicySchemaDigest string                `json:"policy_schema_digest"`
	InventorySHA256    string                `json:"inventory_sha256,omitempty"`
	BTFSHA256          string                `json:"btf_sha256,omitempty"`
	KernelConfigSHA256 string                `json:"kernel_config_sha256,omitempty"`
	IssuedAt           int64                 `json:"issued_at"`
	ValidUntil         int64                 `json:"valid_until"`
	Capabilities       map[string]Capability `json:"capabilities"`
	Probes             []HookProbe           `json:"probes"`
	Qualification      *QualificationScope   `json:"qualification,omitempty"`
}
type CapabilityEnvelope struct {
	Report    CapabilityReport `json:"report"`
	Signature string           `json:"signature"`
}
type TargetBinding struct{ Node, Boot, Challenge string }
type VerifiedTarget struct {
	report CapabilityReport
	digest string
}

func (target VerifiedTarget) Digest() string { return target.digest }

// Report returns a copy. Callers cannot change the verified target's maps.
func (target VerifiedTarget) Report() CapabilityReport {
	raw, _ := json.Marshal(target.report)
	var report CapabilityReport
	_ = json.Unmarshal(raw, &report)
	return report
}

func SignReport(report CapabilityReport, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("capability signer requires an Ed25519 private key")
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return nil, err
	}
	signature := ed25519.Sign(key, append([]byte("AGENTGATE_CAPABILITIES_V1\n"), raw...))
	return json.Marshal(CapabilityEnvelope{report, base64.RawURLEncoding.EncodeToString(signature)})
}
func VerifyTarget(data []byte, pinned ed25519.PublicKey, expected TargetBinding, now int64) (VerifiedTarget, error) {
	var target VerifiedTarget
	if len(data) == 0 || len(data) > MaxBytes {
		return target, errors.New("capability report exceeds its input limit")
	}
	if _, err := parseValue(data, "json"); err != nil {
		return target, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var envelope CapabilityEnvelope
	if err := decoder.Decode(&envelope); err != nil {
		return target, err
	}
	raw, err := json.Marshal(envelope.Report)
	if err != nil {
		return target, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(pinned) != ed25519.PublicKeySize || !ed25519.Verify(pinned, append([]byte("AGENTGATE_CAPABILITIES_V1\n"), raw...), signature) {
		return target, errors.New("capability report signature differs from pinned node trust")
	}
	if err = checkReport(envelope.Report, expected, now); err != nil {
		return target, err
	}
	// Decoding owns the maps. Mutating the caller's input cannot change this target.
	target.report = envelope.Report
	sum := sha256.Sum256(raw)
	target.digest = hex.EncodeToString(sum[:])
	return target, nil
}
func checkReport(report CapabilityReport, expected TargetBinding, now int64) error {
	if expected.Node == "" || expected.Boot == "" || expected.Challenge == "" || report.SchemaVersion != CapabilityVersion || report.Node != expected.Node || report.Boot != expected.Boot || report.Challenge != expected.Challenge {
		return errors.New("capability report identity, boot, or challenge differs")
	}
	if report.PolicySchemaDigest != SchemaDigest() || !hash64.MatchString(report.ArtifactSHA256) || !revision40.MatchString(report.SourceRevision) {
		return errors.New("capability report schema or artifact identity differs")
	}
	for _, value := range []string{report.InventorySHA256, report.BTFSHA256, report.KernelConfigSHA256} {
		if value != "" && !hash64.MatchString(value) {
			return errors.New("capability report inventory or target measurement differs")
		}
	}
	if report.IssuedAt < 0 || report.ValidUntil < 0 || report.IssuedAt > now+30 || report.IssuedAt > report.ValidUntil || report.ValidUntil-report.IssuedAt > 300 || now >= report.ValidUntil {
		return errors.New("capability report is stale or outside its bounded lifetime")
	}
	if report.Kernel == "" || report.Architecture != "x86_64" || len(report.Capabilities) > 64 || len(report.Probes) > 64 {
		return errors.New("capability report platform or entry limit differs")
	}
	catalog, err := CapabilityIDs()
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, id := range catalog {
		known[id] = true
	}
	for id, capability := range report.Capabilities {
		if !known[id] {
			return fmt.Errorf("capability report names unregistered capability %s", id)
		}
		if capability.State != "enforced" && capability.State != "probe-only" && capability.State != "unavailable" && capability.State != "audit-only" && capability.State != "not-applicable" {
			return errors.New("capability report contains an unknown state")
		}
		if len(capability.Mechanisms) > 16 {
			return errors.New("capability mechanism limit exceeded")
		}
		if capability.State == "enforced" && (!hash64.MatchString(capability.ReceiptSHA256) || len(capability.Mechanisms) == 0) {
			return errors.New("enforced capability requires a qualification receipt and mechanism")
		}
	}
	if report.Qualification != nil {
		if err := report.Qualification.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type Preview struct {
	Purpose              string          `json:"purpose"`
	PolicyDigest         string          `json:"policy_digest"`
	SchemaDigest         string          `json:"schema_digest"`
	CompilerVersion      string          `json:"compiler_version"`
	TargetDigest         string          `json:"target_digest"`
	RequiredCapabilities []string        `json:"required_capabilities"`
	EffectivePolicy      json.RawMessage `json:"effective_policy"`
}

// PreviewForTarget validates a contract. It does not install or qualify hooks.
func PreviewForTarget(document Document, target VerifiedTarget, now int64) (Preview, error) {
	var preview Preview
	if err := document.Validate(); err != nil {
		return preview, err
	}
	if err := document.CheckDeclaredRequirements(); err != nil {
		return preview, err
	}
	if document.Profile == SelectedProfile {
		return preview, errors.New("the compatibility profile is inspection-only and cannot authorize execution")
	}
	if target.digest == "" || now >= target.report.ValidUntil {
		return preview, errors.New("a current authenticated target report is required")
	}
	if !hash64.MatchString(target.report.InventorySHA256) || !hash64.MatchString(target.report.BTFSHA256) || !hash64.MatchString(target.report.KernelConfigSHA256) {
		return preview, errors.New("the full policy requires signed inventory, BTF, and kernel configuration measurements")
	}
	required, err := Requirements(document)
	if err != nil {
		return preview, err
	}
	scope := target.report.Qualification
	if scope == nil || scope.Validate() != nil {
		return preview, errors.New("the full policy preview requires a valid qualification scope")
	}
	digest, err := document.Digest()
	if err != nil || !containsSorted(scope.PolicyDigests, digest) ||
		len(target.report.Capabilities) != len(scope.RequiredCapabilities) {
		return preview, errors.New("the target report does not qualify this exact policy and capability set")
	}
	for _, name := range required {
		if !containsSorted(scope.RequiredCapabilities, name) {
			return preview, fmt.Errorf("target qualification scope omits required capability %s", name)
		}
		capability, exists := target.report.Capabilities[name]
		if !exists || capability.State != "enforced" {
			return preview, fmt.Errorf("target capability %s lacks enforcement qualification", name)
		}
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return preview, err
	}
	sum := sha256.Sum256(raw)
	return Preview{"validation-preview", hex.EncodeToString(sum[:]), SchemaDigest(), CompilerVersion, target.digest, required, raw}, nil
}

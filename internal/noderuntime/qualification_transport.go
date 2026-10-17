// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"
)

const QualificationStartProtocol = "agentgate.fixed-qualification-node-start.v1"
const QualificationPreparedProtocol = "agentgate.fixed-qualification-prepared.v1"
const QualificationRunProtocol = "agentgate.fixed-qualification-run.v1"
const QualificationStatusProtocol = "agentgate.fixed-qualification-status.v1"
const QualificationStopProtocol = "agentgate.fixed-qualification-stop.v1"
const QualificationStateProtocol = "agentgate.fixed-qualification-grant-state.v1"
const QualificationPreparedDomain = "AGENTGATE_FIXED_QUALIFICATION_PREPARED_V1\n"

// QualificationStart travels only through the trusted sealed descriptor.
type QualificationStart struct {
	Protocol       string                             `json:"protocol"`
	NodeConfigFile string                             `json:"node_config_file"`
	Spec           lifecycle.QualificationFixtureSpec `json:"spec"`
	Parent         lifecycle.DaemonIdentity           `json:"parent"`
}
type QualificationPrepared struct {
	Protocol          string                           `json:"protocol"`
	Purpose           string                           `json:"purpose"`
	PermitDigest      string                           `json:"permit_digest"`
	TargetDigest      string                           `json:"target_digest"`
	Record            lifecycle.Record                 `json:"record"`
	Quarantine        enforcement.ResourceReadbackWire `json:"quarantine"`
	AuditHeader       []byte                           `json:"audit_header"`
	AuditHeaderDigest string                           `json:"audit_header_digest"`
	PreparedAtUnix    int64                            `json:"prepared_at_unix"`
	PreparedMonoNS    uint64                           `json:"prepared_mono_ns,string"`
	NodeKeyID         string                           `json:"node_key_id"`
	Signature         string                           `json:"signature"`
}
type QualificationRunRequest struct {
	Protocol      string                  `json:"protocol"`
	Authorization lifecycle.Authorization `json:"authorization"`
}
type QualificationStatus struct {
	Protocol string              `json:"protocol"`
	Purpose  string              `json:"purpose"`
	Record   lifecycle.Record    `json:"record"`
	Terminal *lifecycle.Terminal `json:"terminal,omitempty"`
}
type QualificationStopRequest struct {
	Protocol string `json:"protocol"`
	Reason   string `json:"reason"`
}
type QualificationStateRequest struct {
	Protocol string `json:"protocol"`
	GrantID  string `json:"grant_id"`
}
type QualificationStateResponse struct {
	Protocol string `json:"protocol"`
	GrantID  string `json:"grant_id"`
	Known    bool   `json:"known"`
	Revoked  bool   `json:"revoked"`
}

func validateQualificationPrepared(r QualificationPrepared) error {
	return validateQualificationPreparedPurpose(r, QualificationPreparedProtocol, lifecycle.QualificationFixturePurpose)
}

func validateQualificationPreparedPurpose(r QualificationPrepared, protocol, purpose string) error {
	b := r.Record.Binding
	if r.Protocol != protocol || r.Purpose != purpose || !hash64.MatchString(r.PermitDigest) || !hash64.MatchString(r.TargetDigest) || !identifier.MatchString(r.NodeKeyID) || b.Validate(false) != nil || r.Record.State != "quarantined" || r.Record.Process != nil || r.Record.Authorization != nil || r.Record.Watchdog == nil || !reflect.DeepEqual(r.Record.Watchdog.Binding, b) || len(r.Record.Evidence) != 1 || r.Record.Revision < 2 || r.PreparedAtUnix <= 0 || r.PreparedMonoNS == 0 || r.PreparedMonoNS >= r.Record.PreparationDeadlineNS || r.Record.PreparationDeadlineNS > b.DeadlineNS || r.Record.PreparationDeadlineNS-r.PreparedMonoNS > uint64(30*time.Second) {
		return errors.New("the fixed qualification preparation differs")
	}
	if r.Quarantine.Validate() != nil || r.Quarantine.Domain != b.CgroupID {
		return errors.New("the fixed qualification quarantine is not empty")
	}
	e := r.Record.Evidence[0]
	if lifecycle.VerifyReadback(e, b, "quarantined") != nil || e.FixturePurpose != purpose || !e.Empty || e.RightsRemoved {
		return errors.New("the fixed qualification preparation lacks raw deny custody")
	}
	var header jobaudit.Header
	if lifecycle.DecodeTransport(bytes.NewReader(r.AuditHeader), &header) != nil || header.FixturePurpose != purpose || !reflect.DeepEqual(header.Binding, b) || header.QualificationDigest != r.PermitDigest || header.DocumentDigest != b.PolicyDigest || header.CreatedMonoNS > r.PreparedMonoNS {
		return errors.New("the fixed qualification header differs")
	}
	encoded, err := jobaudit.HeaderBytes(header)
	if err != nil || !bytes.Equal(encoded, r.AuditHeader) {
		return errors.New("the fixed qualification header is not canonical")
	}
	if len(header.RequiredStreams) != 7 {
		return errors.New("the fixed qualification requires seven streams")
	}
	for _, stream := range header.RequiredStreams {
		if stream.ArtifactDigest != b.ArtifactDigests[stream.Name] || stream.Kind == "control" && (stream.Name != "node" || stream.Version != "nodecontrol.v1") {
			return errors.New("the fixed qualification stream artifact differs")
		}
	}
	digest, err := jobaudit.HeaderDigest(header)
	if err != nil || digest != r.AuditHeaderDigest || len(e.Capabilities) != len(header.RequiredCapabilities) {
		return errors.New("the fixed qualification header digest differs")
	}
	for _, id := range header.RequiredCapabilities {
		cap := e.Capabilities[id]
		if cap.State != "fixture-only" || cap.EvidenceDigest != r.PermitDigest || !reflect.DeepEqual(cap.Mechanisms, []string{purpose}) {
			return errors.New("the fixed qualification preparation invents enforced capabilities")
		}
	}
	return nil
}
func QualificationPreparedSigningBytes(r QualificationPrepared) ([]byte, error) {
	if err := validateQualificationPrepared(r); err != nil {
		return nil, err
	}
	r.Signature = ""
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(QualificationPreparedDomain), raw...), nil
}
func VerifyQualificationPrepared(r QualificationPrepared, spec lifecycle.QualificationFixtureSpec, keys map[string]ed25519.PublicKey, watchdogKey ed25519.PublicKey, wall int64, maxAge time.Duration) (lifecycle.PreparedNodeTime, error) {
	digest, err := lifecycle.QualificationFixtureScopeDigest(spec)
	if err != nil || digest != r.PermitDigest || spec.TargetDigest != r.TargetDigest || wall <= 0 || maxAge < time.Second || maxAge > 30*time.Second || maxAge%time.Second != 0 || r.PreparedAtUnix > wall+1 || wall-r.PreparedAtUnix > int64(maxAge/time.Second) {
		return lifecycle.PreparedNodeTime{}, errors.New("the fixed qualification scope or freshness differs")
	}
	expected := spec.Binding
	expected.CgroupID = r.Record.Binding.CgroupID
	if !reflect.DeepEqual(expected, r.Record.Binding) {
		return lifecycle.PreparedNodeTime{}, errors.New("the fixed qualification resolved binding differs")
	}
	document, err := policy.Parse(spec.Document, "json")
	if err != nil {
		return lifecycle.PreparedNodeTime{}, err
	}
	var header jobaudit.Header
	if lifecycle.DecodeTransport(bytes.NewReader(r.AuditHeader), &header) != nil || !reflect.DeepEqual(document.RequiredCapabilities, header.RequiredCapabilities) {
		return lifecycle.PreparedNodeTime{}, errors.New("the fixed qualification required set differs")
	}
	raw, err := QualificationPreparedSigningBytes(r)
	if err != nil {
		return lifecycle.PreparedNodeTime{}, err
	}
	if lifecycle.VerifyWatchdogAck(*r.Record.Watchdog, r.Record.Binding, watchdogKey, r.PreparedMonoNS) != nil {
		return lifecycle.PreparedNodeTime{}, errors.New("the fixed qualification watchdog custody differs")
	}
	age := wall - r.PreparedAtUnix
	if age < 0 {
		age = 0
	}
	if uint64(age)*uint64(time.Second) >= r.Record.PreparationDeadlineNS-r.PreparedMonoNS {
		return lifecycle.PreparedNodeTime{}, errors.New("the fixed qualification preparation expired")
	}
	signature, err := base64.RawURLEncoding.DecodeString(r.Signature)
	key := keys[r.Record.Binding.NodeID+"/"+r.NodeKeyID]
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != r.Signature || len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, raw, signature) {
		return lifecycle.PreparedNodeTime{}, errors.New("the fixed qualification node signature differs")
	}
	return lifecycle.PreparedNodeTime{Wall: r.PreparedAtUnix, MonoNS: r.PreparedMonoNS}, nil
}

func (s QualificationStart) Validate() error {
	if s.Protocol != QualificationStartProtocol || !canonical(s.NodeConfigFile) || !strings.HasPrefix(s.NodeConfigFile, s.Spec.OwnedRoot+"/") || s.Parent.PID <= 1 || s.Parent.StartTimeTicks == 0 || !identifier.MatchString(s.Parent.InstanceID) {
		return errors.New("the fixed qualification start scope differs")
	}
	_, err := lifecycle.QualificationFixtureScopeDigest(s.Spec)
	return err
}

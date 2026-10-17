// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
)

const QualificationVersionStartProtocol = "agentgate.native-version-node-start.v1"
const QualificationVersionPreparedProtocol = "agentgate.native-version-prepared.v1"
const QualificationVersionRunProtocol = "agentgate.native-version-run.v1"
const QualificationVersionStatusProtocol = "agentgate.native-version-status.v1"
const QualificationVersionStopProtocol = "agentgate.native-version-stop.v1"
const qualificationVersionPreparedDomain = "AGENTGATE_NATIVE_VERSION_PREPARED_V1\n"

type QualificationVersionStart struct {
	Protocol       string                             `json:"protocol"`
	NodeConfigFile string                             `json:"node_config_file"`
	Spec           lifecycle.QualificationVersionSpec `json:"spec"`
	Parent         lifecycle.DaemonIdentity           `json:"parent"`
}
type QualificationVersionPrepared QualificationPrepared
type QualificationVersionRunRequest QualificationRunRequest
type QualificationVersionStatus QualificationStatus
type QualificationVersionStopRequest QualificationStopRequest

func (s QualificationVersionStart) Validate() error {
	if s.Protocol != QualificationVersionStartProtocol || !canonical(s.NodeConfigFile) || !strings.HasPrefix(s.NodeConfigFile, s.Spec.OwnedRoot+"/") || s.Parent.PID <= 1 || s.Parent.StartTimeTicks == 0 || !identifier.MatchString(s.Parent.InstanceID) {
		return errors.New("the native version start scope differs")
	}
	_, err := lifecycle.QualificationVersionScopeDigest(s.Spec)
	return err
}
func QualificationVersionPreparedSigningBytes(r QualificationVersionPrepared) ([]byte, error) {
	if err := validateQualificationPreparedPurpose(QualificationPrepared(r), QualificationVersionPreparedProtocol, lifecycle.QualificationVersionPurpose); err != nil {
		return nil, err
	}
	r.Signature = ""
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return append([]byte(qualificationVersionPreparedDomain), raw...), nil
}
func VerifyQualificationVersionPrepared(r QualificationVersionPrepared, spec lifecycle.QualificationVersionSpec, keys map[string]ed25519.PublicKey, watchdogKey ed25519.PublicKey, wall int64, maxAge time.Duration) (lifecycle.PreparedNodeTime, error) {
	scope, err := lifecycle.QualificationVersionScopeDigest(spec)
	if err != nil || scope != r.PermitDigest || spec.TargetDigest != r.TargetDigest || wall <= 0 || maxAge < time.Second || maxAge > 30*time.Second || maxAge%time.Second != 0 || r.PreparedAtUnix > wall+1 || wall-r.PreparedAtUnix > int64(maxAge/time.Second) {
		return lifecycle.PreparedNodeTime{}, errors.New("the native version preparation scope or freshness differs")
	}
	expected := spec.Binding
	expected.CgroupID = r.Record.Binding.CgroupID
	if !reflect.DeepEqual(expected, r.Record.Binding) {
		return lifecycle.PreparedNodeTime{}, errors.New("the native version resolved binding differs")
	}
	document, err := policy.Parse(spec.Document, "json")
	if err != nil {
		return lifecycle.PreparedNodeTime{}, err
	}
	var header jobaudit.Header
	if lifecycle.DecodeTransport(bytes.NewReader(r.AuditHeader), &header) != nil || !reflect.DeepEqual(document.RequiredCapabilities, header.RequiredCapabilities) {
		return lifecycle.PreparedNodeTime{}, errors.New("the native version required capability set differs")
	}
	raw, err := QualificationVersionPreparedSigningBytes(r)
	if err != nil {
		return lifecycle.PreparedNodeTime{}, err
	}
	if lifecycle.VerifyWatchdogAck(*r.Record.Watchdog, r.Record.Binding, watchdogKey, r.PreparedMonoNS) != nil {
		return lifecycle.PreparedNodeTime{}, errors.New("the native version watchdog custody differs")
	}
	age := wall - r.PreparedAtUnix
	if age < 0 {
		age = 0
	}
	if uint64(age)*uint64(time.Second) >= r.Record.PreparationDeadlineNS-r.PreparedMonoNS {
		return lifecycle.PreparedNodeTime{}, errors.New("the native version preparation expired")
	}
	signature, err := base64.RawURLEncoding.DecodeString(r.Signature)
	key := keys[r.Record.Binding.NodeID+"/"+r.NodeKeyID]
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != r.Signature || len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, raw, signature) {
		return lifecycle.PreparedNodeTime{}, errors.New("the native version node signature differs")
	}
	return lifecycle.PreparedNodeTime{Wall: r.PreparedAtUnix, MonoNS: r.PreparedMonoNS}, nil
}

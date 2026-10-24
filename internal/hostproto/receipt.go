// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"encoding/json"
	"errors"
	"regexp"
)

// ReceiptVersion is the only accepted Receipt.Version.
const ReceiptVersion = "agentgate.receipt.v1"

// MaxReceiptBytes bounds one encoded receipt.
const MaxReceiptBytes = 128 << 10

// MountIdentity records what a mount actually was on the host.
type MountIdentity struct {
	Name string `json:"name"`
	Mode string `json:"mode"`
	// Identity is "dev:ino" of a live bind, or "sha256:<hex>" of a snapshot.
	Identity string `json:"identity"`
}

// Receipt is the evidence a host returns for one launch.
type Receipt struct {
	Version      string `json:"version"`
	LaunchID     string `json:"launch_id"`
	TargetID     string `json:"target_id"`
	SpecDigest   string `json:"spec_digest"`
	PolicyDigest string `json:"policy_digest"`
	// BPFObjects maps each loaded BPF object name to its SHA-256.
	BPFObjects  map[string]string `json:"bpf_objects"`
	GuardDigest string            `json:"guard_digest"`
	// NetworkEvidence and HostControlEvidence are the blocks that
	// pilot-network-diagnostic writes, carried verbatim.
	NetworkEvidence     json.RawMessage `json:"network_evidence,omitempty"`
	HostControlEvidence json.RawMessage `json:"host_control_evidence,omitempty"`
	Mounts              []MountIdentity `json:"mounts"`
	// BrokerCounts maps an upstream host to the number of requests the broker
	// forwarded. It never carries bodies, headers or secrets.
	BrokerCounts map[string]uint64 `json:"broker_counts"`
	StartedAtMS  int64             `json:"started_at_ms"`
	EndedAtMS    int64             `json:"ended_at_ms"`
	ExitCode     *int              `json:"exit_code,omitempty"`
	// Reason is a short code: exited, stopped, expired, failed, lost_host, ...
	Reason string `json:"reason"`
	// DomainEmpty and EnforcementReleased must both be true before the service
	// marks a launch stopped or expired.
	DomainEmpty         bool `json:"domain_empty"`
	EnforcementReleased bool `json:"enforcement_released"`
	// KernelVerified is false until a verification report for the kernel is
	// attached. Protocol v1 carries no report, so it must be false.
	KernelVerified bool `json:"kernel_verified"`
}

var objectName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
var identityPattern = regexp.MustCompile(`^([0-9]{1,20}:[0-9]{1,20}|sha256:[a-f0-9]{64})$`)

// Check validates a receipt against the job it answers.
func (r Receipt) Check(j Job) error {
	if r.Version != ReceiptVersion {
		return errors.New("hostproto: receipt version unknown")
	}
	if r.LaunchID != j.LaunchID || r.TargetID != j.TargetID || r.SpecDigest != j.SpecDigest || r.PolicyDigest != j.PolicyDigest || !validID(r.LaunchID) {
		return errors.New("hostproto: receipt is bound to another launch, target or digest")
	}
	if r.KernelVerified {
		return errors.New("hostproto: kernel_verified requires an attached verification report")
	}
	if r.BPFObjects == nil || len(r.BPFObjects) > 32 || r.Mounts == nil || len(r.Mounts) > MaxMounts || r.BrokerCounts == nil || len(r.BrokerCounts) > 64 {
		return errors.New("hostproto: receipt maps and lists must be explicit and bounded")
	}
	for name, sum := range r.BPFObjects {
		if !objectName.MatchString(name) || !validDigest(sum) {
			return errors.New("hostproto: receipt BPF object digest invalid")
		}
	}
	if r.GuardDigest != "" && !validDigest(r.GuardDigest) {
		return errors.New("hostproto: receipt guard digest invalid")
	}
	for _, m := range r.Mounts {
		if !MountNamePattern.MatchString(m.Name) || (m.Mode != "read-only" && m.Mode != "snapshot" && m.Mode != "read-write") || !identityPattern.MatchString(m.Identity) {
			return errors.New("hostproto: receipt mount identity invalid")
		}
	}
	for upstream := range r.BrokerCounts {
		if !UpstreamPattern.MatchString(upstream) {
			return errors.New("hostproto: receipt broker upstream invalid")
		}
	}
	if r.StartedAtMS < 0 || r.EndedAtMS < r.StartedAtMS || !reasonPattern.MatchString(r.Reason) {
		return errors.New("hostproto: receipt times or reason invalid")
	}
	if r.ExitCode != nil && (*r.ExitCode < -1 || *r.ExitCode > 255) {
		return errors.New("hostproto: receipt exit code out of range")
	}
	for _, block := range []json.RawMessage{r.NetworkEvidence, r.HostControlEvidence} {
		if len(block) > 0 {
			var v map[string]any
			if json.Unmarshal(block, &v) != nil {
				return errors.New("hostproto: receipt evidence block must be a JSON object")
			}
		}
	}
	raw, _ := json.Marshal(r)
	if len(raw) > MaxReceiptBytes {
		return errors.New("hostproto: receipt exceeds its size limit")
	}
	return nil
}

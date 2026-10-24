// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

// JobVersion is the only accepted Job.Version.
const JobVersion = "agentgate.hostd.job.v1"

// Job types.
const (
	JobProvision     = "provision"
	JobApplyProfile  = "apply-profile"
	JobLaunch        = "launch"
	JobStop          = "stop"
	JobCollect       = "collect"
	JobSecretPut     = "secret-put"
	JobSecretDelete  = "secret-delete"
	JobSnapshotMount = "snapshot-mount"
)

// JobTypes lists every job type in a fixed order.
var JobTypes = []string{JobProvision, JobApplyProfile, JobLaunch, JobStop, JobCollect, JobSecretPut, JobSecretDelete, JobSnapshotMount}

// Job is one unit of host work, sealed under DomainJob with the service job
// key. A host acts on a job only after Check succeeds; otherwise it drops the
// job and reports a "rejected" result.
type Job struct {
	Version      string          `json:"version"`
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	TargetID     string          `json:"target_id"`
	LaunchID     string          `json:"launch_id"`
	SpecDigest   string          `json:"spec_digest"`
	PolicyDigest string          `json:"policy_digest"`
	IssuedAtMS   int64           `json:"issued_at_ms"`
	DeadlineMS   int64           `json:"deadline_ms"`
	Payload      json.RawMessage `json:"payload"`
}

// ProvisionPayload prepares a target: pull the pinned images and confirm the
// guard and enforcement components are installed. It never starts an agent.
type ProvisionPayload struct {
	Images []string `json:"images"`
	Reason string   `json:"reason"`
}

// ApplyProfilePayload stages one validated policy document on the host, for
// example to pre-check it with the native validator. It does not change any
// running launch.
type ApplyProfilePayload struct {
	ProfileID      string          `json:"profile_id"`
	ProfileVersion int             `json:"profile_version"`
	Policy         json.RawMessage `json:"policy"`
}

// LaunchMount is one resolved mount. Path is where the agent sees it.
type LaunchMount struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Mode   string `json:"mode"`
	Path   string `json:"path"`
}

// LaunchSecret is one brokered secret. The value never appears here: the host
// already holds it from a secret-put job and exposes only the broker address.
type LaunchSecret struct {
	Ref       string   `json:"ref"`
	SecretID  string   `json:"secret_id"`
	Env       string   `json:"env"`
	Upstreams []string `json:"upstreams"`
	Header    string   `json:"header"`
}

// LaunchPayload starts one agent. Spec is the exact canonical spec bytes whose
// SHA-256 is Job.SpecDigest; Policy is the exact policy bytes whose SHA-256 is
// Job.PolicyDigest. The host enforces ExpiresAtMS in the kernel policy and
// itself, and reports a heartbeat at least every HeartbeatSeconds.
type LaunchPayload struct {
	Spec             json.RawMessage `json:"spec"`
	Policy           json.RawMessage `json:"policy"`
	ExpiresAtMS      int64           `json:"expires_at_ms"`
	HeartbeatSeconds int             `json:"heartbeat_seconds"`
	Mounts           []LaunchMount   `json:"mounts"`
	Secrets          []LaunchSecret  `json:"secrets"`
}

// StopPayload stops one launch. The host stops the agent, waits up to
// GraceSeconds, kills what remains, empties the domain, releases enforcement,
// and returns the receipt. A stop for a launch that already ended returns the
// recorded receipt.
type StopPayload struct {
	Reason       string `json:"reason"`
	GraceSeconds int    `json:"grace_seconds"`
}

// CollectPayload asks for the receipt of a launch without changing it.
type CollectPayload struct {
	Reason string `json:"reason"`
}

// SecretPutPayload stores one sealed secret on the host. Ciphertext is a
// SealSecret output for this host's X25519 key with AAD SecretAAD(target id,
// name). The service cannot decrypt it.
type SecretPutPayload struct {
	SecretID         string   `json:"secret_id"`
	Name             string   `json:"name"`
	Upstreams        []string `json:"upstreams"`
	Header           string   `json:"header"`
	Ciphertext       string   `json:"ciphertext"`
	CiphertextSHA256 string   `json:"ciphertext_sha256"`
}

// SecretDeletePayload removes a stored secret value from the host.
type SecretDeletePayload struct {
	SecretID string `json:"secret_id"`
	Name     string `json:"name"`
}

// SnapshotMountPayload copies a read-only snapshot of a host folder for a
// launch. The host applies its own source rules again.
type SnapshotMountPayload struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	MaxBytes   int64  `json:"max_bytes"`
	MaxEntries int    `json:"max_entries"`
}

// Bounds for job payload fields.
const (
	MaxJobLifetime     = 25 * time.Hour
	SnapshotMaxBytes   = 256 << 20
	SnapshotMaxEntries = 20000
	MaxSecretBytes     = 8192
	MaxMounts          = 8
	MaxSecrets         = 8
	MountRoot          = "/var/lib/agentgate/mounts"
)

var (
	// NamePattern is the launch, target, profile and secret name rule.
	NamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	// MountNamePattern matches the POC mount name rule.
	MountNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	// BindSourcePattern keeps a bind source to characters that need no quoting
	// (CheckMountSource also bounds it to 4096 bytes).
	BindSourcePattern = regexp.MustCompile(`^/[A-Za-z0-9._@+/-]+$`)
	// ImagePattern requires an immutable digest reference.
	ImagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,199}(:[A-Za-z0-9._-]{1,64})?@sha256:[a-f0-9]{64}$`)
	// UpstreamPattern is an exact lowercase DNS host name, optionally with a port.
	UpstreamPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:[0-9]{1,5})?$`)
	// HeaderPattern is an HTTP header name.
	HeaderPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	envPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	reasonPattern = regexp.MustCompile(`^[a-z0-9_.:-]{1,64}$`)
)

func knownJobType(t string) bool {
	for _, v := range JobTypes {
		if v == t {
			return true
		}
	}
	return false
}

// launchBound reports whether a job type is bound to a launch and its digests.
func launchBound(t string) bool {
	return t == JobLaunch || t == JobStop || t == JobCollect
}

// Check validates a job for this host at now: version, type, target binding,
// issue time, deadline, digest binding and the typed payload. It returns the
// decoded payload (one of the *Payload types, by value).
func (j Job) Check(targetID string, now time.Time) (any, error) {
	if j.Version != JobVersion || !validID(j.ID) || !knownJobType(j.Type) {
		return nil, errors.New("hostproto: unknown job version, id or type")
	}
	if j.TargetID != targetID || !validID(targetID) {
		return nil, errors.New("hostproto: job is for another target")
	}
	issued, deadline := time.UnixMilli(j.IssuedAtMS), time.UnixMilli(j.DeadlineMS)
	if issued.After(now.Add(MaxClockSkew)) || !deadline.After(now) || !deadline.After(issued) || deadline.Sub(issued) > MaxJobLifetime {
		return nil, errors.New("hostproto: job is expired, not yet valid, or has an unbounded deadline")
	}
	if launchBound(j.Type) {
		if !validID(j.LaunchID) || !validDigest(j.SpecDigest) || !validDigest(j.PolicyDigest) {
			return nil, errors.New("hostproto: launch job requires launch id and both digests")
		}
	} else if j.Type == JobApplyProfile {
		if j.LaunchID != "" || j.SpecDigest != "" || !validDigest(j.PolicyDigest) {
			return nil, errors.New("hostproto: apply-profile binds only a policy digest")
		}
	} else if j.Type == JobSnapshotMount {
		if j.LaunchID != "" && !validID(j.LaunchID) || j.SpecDigest != "" && !validDigest(j.SpecDigest) || j.PolicyDigest != "" {
			return nil, errors.New("hostproto: snapshot-mount binds at most a launch")
		}
	} else if j.LaunchID != "" || j.SpecDigest != "" || j.PolicyDigest != "" {
		return nil, errors.New("hostproto: this job type is not bound to a launch")
	}
	if len(j.Payload) == 0 {
		return nil, errors.New("hostproto: job payload missing")
	}
	return j.decode()
}

func (j Job) decode() (any, error) {
	switch j.Type {
	case JobProvision:
		var p ProvisionPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if p.Images == nil || len(p.Images) > 8 || !reasonPattern.MatchString(p.Reason) {
			return nil, errors.New("hostproto: provision needs an explicit image list and a reason code")
		}
		for _, image := range p.Images {
			if !ImagePattern.MatchString(image) {
				return nil, errors.New("hostproto: provision image is not digest pinned")
			}
		}
		return p, nil
	case JobApplyProfile:
		var p ApplyProfilePayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !validID(p.ProfileID) || p.ProfileVersion < 1 || SHA256Hex(p.Policy) != j.PolicyDigest {
			return nil, errors.New("hostproto: apply-profile policy differs from its digest")
		}
		return p, nil
	case JobLaunch:
		var p LaunchPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if SHA256Hex(p.Spec) != j.SpecDigest || SHA256Hex(p.Policy) != j.PolicyDigest {
			return nil, errors.New("hostproto: launch spec or policy differs from its digest")
		}
		var spec LaunchSpec
		if err := DecodeStrict(p.Spec, &spec); err != nil {
			return nil, err
		}
		if p.ExpiresAtMS <= j.IssuedAtMS || p.ExpiresAtMS > j.DeadlineMS || p.HeartbeatSeconds < 5 || p.HeartbeatSeconds > 60 {
			return nil, errors.New("hostproto: launch expiry or heartbeat out of range")
		}
		if p.ExpiresAtMS-j.IssuedAtMS > int64(spec.LifetimeSeconds)*1000+int64(MaxClockSkew/time.Millisecond) {
			return nil, errors.New("hostproto: launch expiry exceeds the spec lifetime")
		}
		if err := checkMounts(p.Mounts); err != nil {
			return nil, err
		}
		if err := checkSecrets(p.Secrets); err != nil {
			return nil, err
		}
		return p, nil
	case JobStop:
		var p StopPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !reasonPattern.MatchString(p.Reason) || p.GraceSeconds < 0 || p.GraceSeconds > 300 {
			return nil, errors.New("hostproto: stop needs a reason code and 0..300 grace seconds")
		}
		return p, nil
	case JobCollect:
		var p CollectPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !reasonPattern.MatchString(p.Reason) {
			return nil, errors.New("hostproto: collect needs a reason code")
		}
		return p, nil
	case JobSecretPut:
		var p SecretPutPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !validID(p.SecretID) || !NamePattern.MatchString(p.Name) || !HeaderPattern.MatchString(p.Header) || checkUpstreams(p.Upstreams) != nil {
			return nil, errors.New("hostproto: secret-put metadata invalid")
		}
		raw, err := b64.DecodeString(p.Ciphertext)
		if err != nil || len(raw) < sealOverhead || len(raw) > MaxSecretBytes+sealOverhead || SHA256Hex(raw) != p.CiphertextSHA256 {
			return nil, errors.New("hostproto: secret-put ciphertext invalid or differs from its fingerprint")
		}
		return p, nil
	case JobSecretDelete:
		var p SecretDeletePayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !validID(p.SecretID) || !NamePattern.MatchString(p.Name) {
			return nil, errors.New("hostproto: secret-delete metadata invalid")
		}
		return p, nil
	case JobSnapshotMount:
		var p SnapshotMountPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !MountNamePattern.MatchString(p.Name) || CheckMountSource(p.Source) != nil || p.MaxBytes < 1 || p.MaxBytes > SnapshotMaxBytes || p.MaxEntries < 1 || p.MaxEntries > SnapshotMaxEntries {
			return nil, errors.New("hostproto: snapshot-mount fields invalid")
		}
		return p, nil
	}
	return nil, errors.New("hostproto: unknown job type")
}

func checkMounts(mounts []LaunchMount) error {
	if mounts == nil || len(mounts) > MaxMounts {
		return errors.New("hostproto: mounts must be an explicit bounded array")
	}
	seen := map[string]bool{}
	for _, m := range mounts {
		if !MountNamePattern.MatchString(m.Name) || seen[m.Name] || m.Path != MountRoot+"/"+m.Name || CheckMountSource(m.Source) != nil {
			return errors.New("hostproto: mount invalid or repeated")
		}
		if m.Mode != "read-only" && m.Mode != "snapshot" && m.Mode != "read-write" {
			return errors.New("hostproto: mount mode invalid")
		}
		seen[m.Name] = true
	}
	return nil
}

func checkSecrets(secrets []LaunchSecret) error {
	if secrets == nil || len(secrets) > MaxSecrets {
		return errors.New("hostproto: secrets must be an explicit bounded array")
	}
	seen := map[string]bool{}
	for _, s := range secrets {
		if !NamePattern.MatchString(s.Ref) || seen[s.Ref] || !validID(s.SecretID) || !envPattern.MatchString(s.Env) || !HeaderPattern.MatchString(s.Header) || checkUpstreams(s.Upstreams) != nil {
			return errors.New("hostproto: secret binding invalid or repeated")
		}
		seen[s.Ref] = true
	}
	return nil
}

func checkUpstreams(values []string) error {
	if len(values) < 1 || len(values) > 8 {
		return errors.New("hostproto: 1 to 8 upstreams required")
	}
	seen := map[string]bool{}
	for _, v := range values {
		if len(v) > 253 || !UpstreamPattern.MatchString(v) || seen[v] {
			return errors.New("hostproto: upstream must be a unique exact host name")
		}
		seen[v] = true
	}
	return nil
}

// ProtectedMountTrees may never be shared or contain a shared tree.
var ProtectedMountTrees = []string{"/proc", "/sys", "/dev", "/run", "/var/run", "/etc", "/root", "/boot", "/usr", "/bin",
	"/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/var/lib/docker", "/var/lib/containerd",
	"/var/lib/cloud", "/var/lib/kubelet", "/snap", "/var/lib/agentgate"}

// secretComponents are per-user credential stores; a source may not contain or
// sit inside one.
var secretComponents = []string{".ssh", ".gnupg", ".aws", ".azure", ".config", ".docker", ".kube", ".netrc",
	".git-credentials", ".password-store", ".vault-token", ".local"}

func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// CheckMountSource applies the static source rules both sides share. The host
// applies its own home-directory and filesystem checks on top.
func CheckMountSource(source string) error {
	if len(source) > 4096 || !BindSourcePattern.MatchString(source) || path.Clean(source) != source || source == "/" {
		return fmt.Errorf("hostproto: mount source must be a canonical absolute path of safe characters: %q", source)
	}
	for _, p := range ProtectedMountTrees {
		if overlaps(source, p) {
			return fmt.Errorf("hostproto: mount source %s overlaps protected tree %s", source, p)
		}
	}
	if strings.HasPrefix(source, "/var/lib/agentgate-") {
		return errors.New("hostproto: mount source overlaps an AgentGate instance directory")
	}
	parts := strings.Split(source[1:], "/")
	for _, part := range parts {
		for _, secret := range secretComponents {
			if part == secret {
				return fmt.Errorf("hostproto: mount source passes through the credential store %s", secret)
			}
		}
	}
	if parts[0] == "home" && len(parts) <= 2 {
		return errors.New("hostproto: mount source is a home directory or contains one")
	}
	return nil
}

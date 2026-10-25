// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"time"
)

// HTTP paths, relative to the service origin. Each takes one Envelope as an
// application/json body; the reply is plain JSON (or the service error
// envelope) because the transport is TLS to the pinned service origin.
const (
	PathEnroll = "/api/v1/hostd/enroll"
	PathPoll   = "/api/v1/hostd/poll"
	PathResync = "/api/v1/hostd/resync"
	// PathEvents is a pattern; replace {id} with the job id.
	PathEvents = "/api/v1/hostd/jobs/{id}/events"
)

// Timing bounds the service enforces.
const (
	MaxClockSkew          = 60 * time.Second
	EnrollmentTokenTTL    = 15 * time.Minute
	DefaultPollInterval   = 10 * time.Second
	MissedHeartbeatsLimit = 3
)

// Capabilities a host may advertise. Unknown values are rejected.
const (
	CapabilityDocker      = "docker"
	CapabilityBPFLSM      = "bpf-lsm"
	CapabilityLiveMounts  = "live-mounts"
	CapabilitySnapshots   = "snapshot-mounts"
	CapabilityBroker      = "broker"
	CapabilityAppliance   = "appliance"
	CapabilityPOCPolicyV2 = "pocpolicy-v2"
	// CapabilityBrokeredSecrets means the host stores sealed secrets and runs
	// a per-launch credential broker: the broker image or binary, its run_as
	// identity, the secret store and the broker network pool are present. A
	// launch that references secrets needs it. CapabilityBroker is the older
	// name; no host reports it and the service no longer accepts it instead.
	CapabilityBrokeredSecrets = "brokered-secrets"
)

var knownCapabilities = map[string]bool{CapabilityDocker: true, CapabilityBPFLSM: true, CapabilityLiveMounts: true, CapabilitySnapshots: true, CapabilityBroker: true, CapabilityAppliance: true, CapabilityPOCPolicyV2: true, CapabilityBrokeredSecrets: true}

// MaxSealKeyRecordBytes bounds the signed seal key record in a heartbeat.
const MaxSealKeyRecordBytes = 4 << 10

// TokenPattern is the enrollment token format: "agtenr_" and 43 base64url characters.
var TokenPattern = regexp.MustCompile(`^agtenr_[A-Za-z0-9_-]{43}$`)
var hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// Header is embedded in every signed host request after enrollment. The
// sequence is shared by every request a host signs. It must be strictly
// greater than the last sequence the service accepted. Gaps are accepted (a
// request lost before it reached the service leaves one); a repeat or a lower
// value is rejected. A host serializes its signed requests and persists the
// counter before sending.
type Header struct {
	HostID      string `json:"host_id"`
	Nonce       string `json:"nonce"`
	TimestampMS int64  `json:"timestamp_ms"`
	Sequence    uint64 `json:"sequence"`
}

// Check validates the header shape and the timestamp skew against now.
func (h Header) Check(now time.Time) error {
	if !validID(h.HostID) {
		return errors.New("hostproto: host_id must be a 32-hex target id")
	}
	if !validNonce(h.Nonce) {
		return errors.New("hostproto: nonce must be 16 to 48 random bytes in base64url")
	}
	if h.Sequence == 0 || h.Sequence > 1<<53 {
		return errors.New("hostproto: sequence must be positive")
	}
	skew := now.Sub(time.UnixMilli(h.TimestampMS))
	if skew > MaxClockSkew || skew < -MaxClockSkew {
		return errors.New("hostproto: timestamp is outside the allowed clock skew")
	}
	return nil
}

// EnrollRequest binds a host key to a target. It is sealed under DomainEnroll
// with the private half of PublicKey, which proves possession.
type EnrollRequest struct {
	Token string `json:"token"`
	// PublicKey is the host's Ed25519 signing key (base64url, 32 bytes).
	PublicKey string `json:"public_key"`
	// EncryptionKey is the host's X25519 key that clients seal secrets to.
	EncryptionKey string   `json:"encryption_key"`
	Hostname      string   `json:"hostname"`
	Capabilities  []string `json:"capabilities"`
	AgentVersion  string   `json:"agent_version"`
	Nonce         string   `json:"nonce"`
	TimestampMS   int64    `json:"timestamp_ms"`
}

// Check validates every field except the token's validity, which only the
// service can decide.
func (e EnrollRequest) Check(now time.Time) error {
	if !TokenPattern.MatchString(e.Token) {
		return errors.New("hostproto: enrollment token format invalid")
	}
	if _, err := DecodeKey(e.PublicKey); err != nil {
		return err
	}
	if _, err := DecodeKey(e.EncryptionKey); err != nil {
		return err
	}
	if !hostnamePattern.MatchString(e.Hostname) || !printable(e.AgentVersion, 64) || e.AgentVersion == "" {
		return errors.New("hostproto: hostname or agent version invalid")
	}
	if err := CheckCapabilities(e.Capabilities); err != nil {
		return err
	}
	if !validNonce(e.Nonce) {
		return errors.New("hostproto: nonce invalid")
	}
	skew := now.Sub(time.UnixMilli(e.TimestampMS))
	if skew > MaxClockSkew || skew < -MaxClockSkew {
		return errors.New("hostproto: timestamp is outside the allowed clock skew")
	}
	return nil
}

// CheckCapabilities accepts a short list of unique known capabilities.
func CheckCapabilities(values []string) error {
	if values == nil || len(values) > len(knownCapabilities) {
		return errors.New("hostproto: capabilities must be an explicit array")
	}
	seen := map[string]bool{}
	for _, v := range values {
		if !knownCapabilities[v] || seen[v] {
			return errors.New("hostproto: unknown or repeated capability " + v)
		}
		seen[v] = true
	}
	return nil
}

// EnrollResponse tells the host who it is and which service key signs its
// jobs. The binding is not active yet: an administrator must compare the
// host key fingerprint (HostKeyID, also printed by the host) with the one the
// service shows and approve it. Until then polls are refused with
// key_approval_pending. TokenMAC lets the host check that the reply came from a party that
// knows the one-time token, so a substituted job key is detected even before
// the first job arrives.
type EnrollResponse struct {
	TargetID            string `json:"target_id"`
	TargetName          string `json:"target_name"`
	HostKeyID           string `json:"host_key_id"`
	JobKey              string `json:"job_key"`
	JobKeyID            string `json:"job_key_id"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
	ServerTimeMS        int64  `json:"server_time_ms"`
	TokenMAC            string `json:"token_mac"`
}

func enrollMACInput(r EnrollResponse) []byte {
	return []byte(signaturePrefix + "\x00enroll-response\x00" + r.TargetID + "\x00" + r.TargetName + "\x00" + r.HostKeyID + "\x00" + r.JobKey + "\x00" + r.JobKeyID)
}

// EnrollResponseMAC computes TokenMAC: hex HMAC-SHA256 keyed by the token.
func EnrollResponseMAC(token string, r EnrollResponse) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write(enrollMACInput(r))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyEnrollResponse checks TokenMAC and that JobKeyID names JobKey.
func VerifyEnrollResponse(token string, r EnrollResponse) error {
	if !hmac.Equal([]byte(EnrollResponseMAC(token, r)), []byte(r.TokenMAC)) {
		return errors.New("hostproto: enrollment reply is not bound to the token")
	}
	key, err := DecodeKey(r.JobKey)
	if err != nil || KeyID(key) != r.JobKeyID {
		return errors.New("hostproto: job key id differs from the job key")
	}
	if !validID(r.TargetID) {
		return errors.New("hostproto: target id invalid")
	}
	return nil
}

// Heartbeat is carried by every poll.
type Heartbeat struct {
	Capabilities []string `json:"capabilities"`
	// RunningLaunches lists launch ids whose domains are live on the host.
	RunningLaunches []string `json:"running_launches"`
	AgentVersion    string   `json:"agent_version"`
	// KernelVerified is false until a verification report for this kernel is
	// attached. The service rejects true in protocol v1.
	KernelVerified bool `json:"kernel_verified"`
	// SealKey is the host's secretseal.SignedKeyRecord: the X25519 key clients
	// seal secrets to, signed by the enrolled host key. The service stores it
	// verbatim and serves it at GET /targets/{id}/seal-key; it cannot forge
	// one, because clients verify the signature against a pinned fingerprint.
	SealKey json.RawMessage `json:"seal_key,omitempty"`
	// MountRoots are the host folders this host's own operator allows
	// launches to mount or snapshot (agentgate-hostd mount-roots), as the host
	// enforces them right now; empty refuses every host folder. The service
	// shows them next to its own list for the target and refuses to plan a
	// mount outside them; it can never change them. Absent (nil) from a host
	// that predates the field.
	MountRoots *[]string `json:"mount_roots,omitempty"`
}

// MaxRunningLaunches bounds one heartbeat.
const MaxRunningLaunches = 64

// PollRequest is sealed under DomainPoll with the enrolled host key.
type PollRequest struct {
	Header
	Heartbeat Heartbeat `json:"heartbeat"`
	// MaxJobs is 1 to 16.
	MaxJobs int `json:"max_jobs"`
}

// Check validates the request shape.
func (p PollRequest) Check(now time.Time) error {
	if err := p.Header.Check(now); err != nil {
		return err
	}
	if p.MaxJobs < 1 || p.MaxJobs > 16 {
		return errors.New("hostproto: max_jobs must be 1 to 16")
	}
	if err := CheckCapabilities(p.Heartbeat.Capabilities); err != nil {
		return err
	}
	if p.Heartbeat.RunningLaunches == nil || len(p.Heartbeat.RunningLaunches) > MaxRunningLaunches {
		return errors.New("hostproto: running_launches must be an explicit bounded array")
	}
	for _, id := range p.Heartbeat.RunningLaunches {
		if !validID(id) {
			return errors.New("hostproto: running launch id invalid")
		}
	}
	if !printable(p.Heartbeat.AgentVersion, 64) || p.Heartbeat.AgentVersion == "" {
		return errors.New("hostproto: agent version invalid")
	}
	if p.Heartbeat.KernelVerified {
		return errors.New("hostproto: kernel_verified requires an attached verification report, which protocol v1 does not carry")
	}
	if p.Heartbeat.MountRoots != nil {
		if err := CheckMountRoots(*p.Heartbeat.MountRoots); err != nil {
			return err
		}
	}
	if len(p.Heartbeat.SealKey) > 0 {
		var object map[string]json.RawMessage
		if len(p.Heartbeat.SealKey) > MaxSealKeyRecordBytes || json.Unmarshal(p.Heartbeat.SealKey, &object) != nil {
			return errors.New("hostproto: seal_key must be one bounded JSON object")
		}
	}
	return nil
}

// PollResponse carries zero or more jobs. Each Envelope opens under DomainJob
// with the job key from EnrollResponse into a Job.
type PollResponse struct {
	ServerTimeMS        int64      `json:"server_time_ms"`
	PollIntervalSeconds int        `json:"poll_interval_seconds"`
	AcceptedSequence    uint64     `json:"accepted_sequence"`
	Jobs                []Envelope `json:"jobs"`
}

// SequenceRejection is the error body detail the service returns when a
// sequence is not greater than the last accepted one, so an honest host can
// resynchronise its counter. It is sent only after the signature verified.
type SequenceRejection struct {
	LastAcceptedSequence uint64 `json:"last_accepted_sequence"`
}

// ResyncRequest is sealed under DomainResync with the enrolled host key. A
// host that lost its sequence counter (crash before persisting, disk wipe)
// sends it to reset the service's last accepted sequence to zero, then
// continues from sequence 1. It carries no sequence of its own: replay is
// bounded by the timestamp skew (MaxClockSkew) and the service's nonce
// window, which keeps every nonce for twice the skew. A resync never
// re-enables a request older than the skew bound, because every signed
// request also carries a timestamp.
type ResyncRequest struct {
	HostID      string `json:"host_id"`
	Nonce       string `json:"nonce"`
	TimestampMS int64  `json:"timestamp_ms"`
	// Reason is a short code such as counter-lost or disk-restored.
	Reason string `json:"reason"`
}

// Check validates the request shape and the timestamp skew.
func (r ResyncRequest) Check(now time.Time) error {
	if !validID(r.HostID) || !validNonce(r.Nonce) || !reasonPattern.MatchString(r.Reason) {
		return errors.New("hostproto: resync fields invalid")
	}
	skew := now.Sub(time.UnixMilli(r.TimestampMS))
	if skew > MaxClockSkew || skew < -MaxClockSkew {
		return errors.New("hostproto: timestamp is outside the allowed clock skew")
	}
	return nil
}

// ResyncResponse confirms the reset.
type ResyncResponse struct {
	LastAcceptedSequence uint64 `json:"last_accepted_sequence"`
	ServerTimeMS         int64  `json:"server_time_ms"`
}

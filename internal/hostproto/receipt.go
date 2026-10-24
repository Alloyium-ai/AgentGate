// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"
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
	// BrokerEvidence summarizes the launch broker's stats document: counts
	// and fixed codes only. Present exactly when the launch used a broker.
	BrokerEvidence *BrokerEvidence `json:"broker_evidence,omitempty"`
	StartedAtMS    int64           `json:"started_at_ms"`
	EndedAtMS      int64           `json:"ended_at_ms"`
	ExitCode       *int            `json:"exit_code,omitempty"`
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

// BrokerEvidenceVersion is the only accepted BrokerEvidence.Version.
const BrokerEvidenceVersion = "agentgate.broker-evidence.v1"

// BrokerEvidence is the bounded summary of one broker stats document
// (agentgate.broker-stats.v1) that the host verified against the
// configuration it wrote: launch id and configuration digest. It holds counts,
// fixed reason codes and upstream names only; never a body, header value,
// query, client address, request path or secret. Missing names why the stats
// could not be read or verified (then every other field is empty).
type BrokerEvidence struct {
	Version          string                         `json:"version"`
	Missing          string                         `json:"missing,omitempty"`
	ConfigSHA256     string                         `json:"config_sha256,omitempty"`
	Listen           string                         `json:"listen,omitempty"`
	State            string                         `json:"state,omitempty"`
	StopReason       string                         `json:"stop_reason,omitempty"`
	Complete         bool                           `json:"complete"`
	StartedAt        string                         `json:"started_at,omitempty"`
	UpdatedAt        string                         `json:"updated_at,omitempty"`
	Hardening        *BrokerHardening               `json:"hardening,omitempty"`
	Connections      BrokerConnections              `json:"connections"`
	Requests         BrokerRequests                 `json:"requests"`
	Denied           map[string]uint64              `json:"denied"`
	Routes           map[string]BrokerRouteEvidence `json:"routes"`
	DenialsRecorded  int                            `json:"denials_recorded"`
	DenialsTruncated bool                           `json:"denials_truncated"`
}

// BrokerHardening is the process state the broker reported before serving.
type BrokerHardening struct {
	UID            int  `json:"uid"`
	GID            int  `json:"gid"`
	NotDumpable    bool `json:"not_dumpable"`
	CoreLimitZero  bool `json:"core_limit_zero"`
	NoNewPrivs     bool `json:"no_new_privs"`
	NoCapabilities bool `json:"no_effective_capabilities"`
	MemoryLocked   bool `json:"secret_memory_locked"`
}

// BrokerConnections counts inbound connections.
type BrokerConnections struct {
	Accepted uint64 `json:"accepted"`
	Rejected uint64 `json:"rejected_over_limit"`
}

// BrokerRequests counts requests across routes.
type BrokerRequests struct {
	Total     uint64 `json:"total"`
	Denied    uint64 `json:"denied"`
	Forwarded uint64 `json:"forwarded"`
}

// BrokerRouteEvidence counts one route's traffic to its one upstream.
type BrokerRouteEvidence struct {
	Upstream   string            `json:"upstream"`
	Requests   uint64            `json:"requests"`
	Forwarded  uint64            `json:"forwarded"`
	Status     map[string]uint64 `json:"status"`
	Errors     map[string]uint64 `json:"errors"`
	BytesIn    uint64            `json:"bytes_in"`
	BytesOut   uint64            `json:"bytes_out"`
	Redactions uint64            `json:"redactions"`
}

var (
	codePattern      = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	routeNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	listenPattern    = regexp.MustCompile(`^tcp:(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})(\.(25[0-5]|2[0-4][0-9]|1?[0-9]{1,2})){3}:[0-9]{4,5}$`)
	statusClasses    = map[string]bool{"1xx": true, "2xx": true, "3xx": true, "4xx": true, "5xx": true, "other": true}
)

// Check validates the evidence shape and returns the forwarded requests per
// upstream (keyed as BrokerCounts is: "host" for port 443, else "host:port").
func (b BrokerEvidence) Check() (map[string]uint64, error) {
	counts := map[string]uint64{}
	if b.Version != BrokerEvidenceVersion {
		return nil, errors.New("hostproto: broker evidence version unknown")
	}
	if b.Missing != "" {
		if !reasonPattern.MatchString(b.Missing) || b.ConfigSHA256 != "" || b.Listen != "" || b.State != "" || b.Complete || len(b.Routes) > 0 ||
			len(b.Denied) > 0 || b.Hardening != nil || b.Requests != (BrokerRequests{}) || b.Connections != (BrokerConnections{}) {
			return nil, errors.New("hostproto: broker evidence that names missing stats carries nothing else")
		}
		return counts, nil
	}
	if !validDigest(b.ConfigSHA256) || !listenPattern.MatchString(b.Listen) || (b.State != "starting" && b.State != "running" && b.State != "stopped") {
		return nil, errors.New("hostproto: broker evidence binding invalid")
	}
	switch b.StopReason {
	case "", "deadline", "signal", "error":
	default:
		return nil, errors.New("hostproto: broker evidence stop reason invalid")
	}
	for _, stamp := range []string{b.StartedAt, b.UpdatedAt} {
		if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil || len(stamp) > 40 {
			return nil, errors.New("hostproto: broker evidence time invalid")
		}
	}
	if b.Denied == nil || len(b.Denied) > 64 || b.Routes == nil || len(b.Routes) > 16 || b.DenialsRecorded < 0 || b.DenialsRecorded > 256 {
		return nil, errors.New("hostproto: broker evidence maps must be explicit and bounded")
	}
	var denied uint64
	for code, n := range b.Denied {
		if !codePattern.MatchString(code) {
			return nil, errors.New("hostproto: broker denial reason invalid")
		}
		denied += n
	}
	if denied != b.Requests.Denied {
		return nil, errors.New("hostproto: broker denial counts differ from the denied total")
	}
	var forwarded uint64
	for name, r := range b.Routes {
		host, port, ok := strings.Cut(r.Upstream, ":")
		if !routeNamePattern.MatchString(name) || !ok || !UpstreamPattern.MatchString(r.Upstream) || strings.Contains(port, ":") || host == "" ||
			r.Forwarded > r.Requests || r.Status == nil || len(r.Status) > len(statusClasses) || r.Errors == nil || len(r.Errors) > 16 {
			return nil, errors.New("hostproto: broker route evidence invalid")
		}
		for class := range r.Status {
			if !statusClasses[class] {
				return nil, errors.New("hostproto: broker status class invalid")
			}
		}
		for kind := range r.Errors {
			if !codePattern.MatchString(kind) {
				return nil, errors.New("hostproto: broker error kind invalid")
			}
		}
		forwarded += r.Forwarded
		key := r.Upstream
		if port == "443" {
			key = host
		}
		counts[key] += r.Forwarded
	}
	if forwarded != b.Requests.Forwarded {
		return nil, errors.New("hostproto: broker route counts differ from the forwarded total")
	}
	return counts, nil
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
	// Broker counts come only from verified broker evidence, and must equal it.
	if r.BrokerEvidence == nil {
		if len(r.BrokerCounts) > 0 {
			return errors.New("hostproto: receipt broker counts need broker evidence")
		}
	} else {
		counts, err := r.BrokerEvidence.Check()
		if err != nil {
			return err
		}
		if len(counts) != len(r.BrokerCounts) {
			return errors.New("hostproto: receipt broker counts differ from the broker evidence")
		}
		for upstream, n := range counts {
			if got, ok := r.BrokerCounts[upstream]; !ok || got != n {
				return errors.New("hostproto: receipt broker counts differ from the broker evidence")
			}
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

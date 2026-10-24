// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/pocpolicy"
)

// Launch knobs passed to the launch runtime.
const (
	launcherJobVersion = "agentgate.launcher-job.v1"
	launchStopGrace    = 10
	launchLogLimit     = 16 << 20
	launchUploadLimit  = 1 << 20
	maxLaunchJobBytes  = 256 << 10
)

type launcherMount struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Mode   string `json:"mode"`
}

// launcherJob is what launch.py run reads on standard input.
type launcherJob struct {
	Version             string          `json:"version"`
	LaunchID            string          `json:"launch_id"`
	JobID               string          `json:"job_id"`
	Spec                json.RawMessage `json:"spec"`
	SpecDigest          string          `json:"spec_digest"`
	Policy              json.RawMessage `json:"policy"`
	PolicyDigest        string          `json:"policy_digest"`
	ProfilePolicyDigest string          `json:"profile_policy_digest"`
	StopGraceSeconds    int             `json:"stop_grace_seconds"`
	LogLimitBytes       int             `json:"log_limit_bytes"`
	UploadLimitBytes    int             `json:"upload_limit_bytes"`
	LifetimeSeconds     int             `json:"lifetime_seconds"`
	ExpiresAtMS         int64           `json:"expires_at_ms"`
	Mounts              []launcherMount `json:"mounts"`
}

// secretLike is the contract's rule for environment names that must never
// carry a value: *_KEY, *_TOKEN, *_SECRET, *PASSWORD* (and close variants).
func secretLike(name string) bool {
	upper := strings.ToUpper(name)
	for _, suffix := range []string{"KEY", "TOKEN", "SECRET", "SECRETS"} {
		if strings.HasSuffix(upper, suffix) {
			return true
		}
	}
	for _, part := range []string{"PASSWORD", "PASSWD", "CREDENTIAL"} {
		if strings.Contains(upper, part) {
			return true
		}
	}
	return false
}

// prepareLaunch checks a verified launch job on this host and builds the
// launcher job. Every refusal happens before anything runs.
func prepareLaunch(job hostproto.Job, p hostproto.LaunchPayload, caps []string, now time.Time) ([]byte, map[string]string, string, error) {
	var spec hostproto.LaunchSpec
	if err := hostproto.DecodeStrict(p.Spec, &spec); err != nil {
		return nil, nil, "invalid_spec", err
	}
	if spec.Version != hostproto.LaunchSpecVersion || !hostproto.NamePattern.MatchString(spec.Name) {
		return nil, nil, "invalid_spec", errors.New("launch spec version or name invalid")
	}
	if len(p.Secrets) > 0 || len(spec.Secrets) > 0 {
		return nil, nil, "broker_unavailable", errors.New("this host has no credential broker; a launch that needs secrets does not start")
	}
	if err := pocpolicy.ValidateLifetime(spec.Mode, spec.LifetimeSeconds); err != nil {
		return nil, nil, "invalid_lifetime", err
	}
	if !hostproto.ImagePattern.MatchString(spec.Agent.Image) && !strings.HasPrefix(spec.Agent.Image, "sha256:") {
		return nil, nil, "invalid_image", errors.New("agent image must be an immutable digest reference")
	}
	for name := range spec.Agent.Env {
		if secretLike(name) {
			return nil, nil, "secret_in_env", fmt.Errorf("environment name %s looks like a secret; secrets arrive only through the broker", name)
		}
	}
	// The effective lifetime never runs past the signed expiry. The host kills
	// the domain at the expiry itself; the kernel policy expires one lifetime
	// after the guard attaches (see docs/PROVISIONING.md).
	remaining := time.UnixMilli(p.ExpiresAtMS).Sub(now)
	lifetime := spec.LifetimeSeconds
	if limit := int(remaining / time.Second); limit < lifetime {
		lifetime = limit
	}
	if err := pocpolicy.ValidateLifetime(spec.Mode, lifetime); err != nil {
		return nil, nil, "expired_before_start", fmt.Errorf("the launch expires before a %s lifetime can start: %v", spec.Mode, err)
	}
	profile, err := pocpolicy.Parse(p.Policy)
	if err != nil {
		return nil, nil, "policy_invalid", err
	}
	effective, err := profile.ForLaunch(spec.Mode, lifetime)
	if err != nil {
		return nil, nil, "policy_invalid", err
	}
	modes := map[string]string{}
	mounts := make([]launcherMount, 0, len(p.Mounts))
	has := func(name string) bool {
		for _, item := range caps {
			if item == name {
				return true
			}
		}
		return false
	}
	for _, m := range p.Mounts {
		if m.Path != path.Join(hostproto.MountRoot, m.Name) {
			return nil, nil, "invalid_mount", errors.New("mount path differs from its name")
		}
		switch m.Mode {
		case "snapshot":
			if !has(hostproto.CapabilitySnapshots) {
				return nil, nil, "unsupported_capability", errors.New("this target does not take snapshot mounts")
			}
		default:
			if !has(hostproto.CapabilityLiveMounts) {
				return nil, nil, "unsupported_capability", fmt.Errorf("mount %s needs live-mounts, which this target does not advertise", m.Name)
			}
		}
		modes[m.Name] = m.Mode
		mounts = append(mounts, launcherMount{Name: m.Name, Source: m.Source, Mode: m.Mode})
	}
	policy, err := json.Marshal(effective)
	if err != nil {
		return nil, nil, "policy_invalid", err
	}
	raw, err := json.Marshal(launcherJob{Version: launcherJobVersion, LaunchID: job.LaunchID, JobID: job.ID, Spec: p.Spec,
		SpecDigest: job.SpecDigest, Policy: policy, PolicyDigest: effective.Digest(), ProfilePolicyDigest: job.PolicyDigest,
		StopGraceSeconds: launchStopGrace, LogLimitBytes: launchLogLimit, UploadLimitBytes: launchUploadLimit,
		LifetimeSeconds: lifetime, ExpiresAtMS: p.ExpiresAtMS, Mounts: mounts})
	if err != nil {
		return nil, nil, "invalid_spec", err
	}
	if len(raw) > maxLaunchJobBytes {
		return nil, nil, "invalid_spec", errors.New("launch job exceeds its bound")
	}
	return raw, modes, "", nil
}

func (d *Daemon) startLaunch(ctx context.Context, job hostproto.Job, p hostproto.LaunchPayload) {
	if reason := d.degradedReason(); reason != "" {
		d.finish(job.ID, hostproto.ResultRejected, "host_degraded", "this host could not reconcile an earlier launch: "+reason, nil, "not_started")
		return
	}
	raw, modes, code, err := prepareLaunch(job, p, d.capabilities(ctx), d.Now())
	if err != nil {
		d.finish(job.ID, hostproto.ResultRejected, code, err.Error(), nil, "not_started")
		return
	}
	heartbeat := time.Duration(p.HeartbeatSeconds) * time.Second
	if heartbeat <= 0 {
		heartbeat = defaultHeartbeat
	}
	launchCtx, cancel := context.WithCancel(ctx)
	active := &activeLaunch{jobID: job.ID, launchID: job.LaunchID, heartbeat: heartbeat, started: d.Now(), cancel: cancel, done: make(chan struct{})}
	d.mu.Lock()
	// One active launch per target: the runtime's instance lock enforces it
	// too, but refusing here never even starts a second runtime.
	if len(d.active) > 0 {
		d.mu.Unlock()
		cancel()
		d.finish(job.ID, hostproto.ResultRejected, "target_busy", "another launch is running on this target", nil, "not_started")
		return
	}
	d.active[job.LaunchID] = active
	d.mu.Unlock()
	d.background(func() {
		defer func() {
			cancel()
			d.mu.Lock()
			delete(d.active, job.LaunchID)
			d.mu.Unlock()
			close(active.done)
		}()
		d.superviseLaunch(launchCtx, job, raw, modes)
	})
}

// logMessages turns raw output into valid UTF-8 pieces of at most the event
// message bound. The exact bytes stay in the host log and its digest.
func logMessages(raw []byte) []string {
	text := strings.ToValidUTF8(string(raw), "�")
	var out []string
	for len(text) > 0 {
		cut := len(text)
		if cut > hostproto.MaxEventMessage {
			cut = hostproto.MaxEventMessage
			for cut > 0 && !utf8.RuneStart(text[cut]) {
				cut--
			}
		}
		out = append(out, text[:cut])
		text = text[cut:]
	}
	return out
}

func (d *Daemon) superviseLaunch(ctx context.Context, job hostproto.Job, raw []byte, modes map[string]string) {
	var receipt json.RawMessage
	var rejected *LauncherEvent
	emit := func(event LauncherEvent) {
		switch event.Event {
		case "state":
			if event.State == "provisioning" || event.State == "running" || event.State == "stopping" {
				if _, err := d.Outbox.Append(job.ID, hostproto.Event{TimeMS: d.Now().UnixMilli(), Kind: hostproto.EventState, State: event.State}, false); err != nil {
					d.logf("launch %s: state event not queued: %v", job.LaunchID, err)
				}
			}
		case "log":
			if event.Stream != "stdout" && event.Stream != "stderr" {
				return
			}
			data, err := base64.StdEncoding.DecodeString(event.Data)
			if err != nil {
				return
			}
			for _, message := range logMessages(data) {
				if _, appendErr := d.Outbox.Append(job.ID, hostproto.Event{TimeMS: d.Now().UnixMilli(), Kind: hostproto.EventLog, Stream: event.Stream, Message: message}, true); appendErr != nil {
					d.logf("launch %s: log event not queued: %v", job.LaunchID, appendErr)
				}
			}
		case "rejected":
			copied := event
			rejected = &copied
		case "receipt":
			if len(event.Receipt) > 0 && len(event.Receipt) <= 32<<20 {
				receipt = append(json.RawMessage(nil), event.Receipt...)
			}
		}
	}
	runErr := d.Runtime.Run(ctx, raw, emit)
	if receipt == nil && rejected != nil {
		code := map[string]string{"busy": "target_busy", "duplicate_launch": "duplicate_launch"}[rejected.Reason]
		if code == "" {
			code = "invalid_job"
		}
		d.finish(job.ID, hostproto.ResultRejected, code, rejected.Error, nil, "not_started")
		return
	}
	if receipt == nil {
		// The runtime died before its receipt: let it tear down what it left
		// (domain, target, guard, pins) and record the launch, then read that.
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if _, err := d.Runtime.Stop(cleanupCtx, job.LaunchID, 0, "stop_requested"); err != nil {
			d.logf("launch %s: teardown after a runtime failure: %v", job.LaunchID, err)
		}
		receipt, _ = d.Runtime.Receipt(cleanupCtx, job.LaunchID)
		if runErr != nil {
			d.progress(job.ID, "launch runtime failed: "+runErr.Error())
		}
	}
	d.finishWithReceipt(job, receipt, modes, "receipt_absent")
}

// finishWithReceipt converts a launcher receipt and records the job result.
func (d *Daemon) finishWithReceipt(job hostproto.Job, raw json.RawMessage, modes map[string]string, missing string) {
	if raw == nil {
		d.finish(job.ID, hostproto.ResultFailed, "evidence_missing", "no receipt is available for this launch", nil, missing)
		return
	}
	receipt, status, reason, err := convertReceipt(job, d.Identity.TargetID, raw, modes)
	if err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "evidence_invalid", err.Error(), nil, "receipt_invalid")
		return
	}
	d.finish(job.ID, status, reason, "", receipt, "")
}

// launcherReceipt is the part of launch.py's receipt the protocol carries.
type launcherReceipt struct {
	LaunchID            string             `json:"launch_id"`
	JobID               string             `json:"job_id"`
	SpecDigest          string             `json:"spec_digest"`
	PolicyDigest        string             `json:"policy_digest"`
	ProfilePolicyDigest string             `json:"profile_policy_digest"`
	Mode                string             `json:"mode"`
	LifetimeSeconds     int                `json:"lifetime_seconds"`
	ImageID             *string            `json:"image_id"`
	State               string             `json:"state"`
	Reason              string             `json:"reason"`
	ExitCode            *int               `json:"exit_code"`
	StartedAt           *string            `json:"started_at"`
	EndedAt             string             `json:"ended_at"`
	Objects             map[string]*string `json:"objects"`
	Mounts              []struct {
		Path       string  `json:"path"`
		ReadOnly   bool    `json:"read_only"`
		Device     *uint64 `json:"device"`
		Inode      *uint64 `json:"inode"`
		TreeSHA256 *string `json:"tree_sha256"`
	} `json:"mounts"`
	Logs             json.RawMessage            `json:"logs"`
	Output           json.RawMessage            `json:"output"`
	Evidence         map[string]json.RawMessage `json:"evidence"`
	EvidenceComplete bool                       `json:"evidence_complete"`
	GuardSHA256      *string                    `json:"guard_receipt_sha256"`
	Cleanup          struct {
		DomainEmpty         bool     `json:"domain_empty"`
		EnforcementReleased bool     `json:"enforcement_released"`
		Errors              []string `json:"errors"`
	} `json:"cleanup"`
	EvidenceMissing *string `json:"evidence_missing"`
	SetupError      *string `json:"setup_error"`
	Reconciled      bool    `json:"reconciled"`
	KernelVerified  bool    `json:"kernel_verified"`
}

var receiptReasons = map[string]string{"exited": "exited", "stop_requested": "stopped", "lifetime_expired": "expired"}

func parseTime(value string) int64 {
	for _, layout := range []string{"2006-01-02T15:04:05.000000Z", time.RFC3339Nano} {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UnixMilli()
		}
	}
	return 0
}

// convertReceipt binds the launcher's receipt to the job and fits it into the
// protocol receipt. It refuses a receipt for another launch.
func convertReceipt(job hostproto.Job, targetID string, raw json.RawMessage, modes map[string]string) (*hostproto.Receipt, string, string, error) {
	var in launcherReceipt
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, "", "", fmt.Errorf("launch receipt: %w", err)
	}
	if in.LaunchID != job.LaunchID || in.SpecDigest != job.SpecDigest || in.ProfilePolicyDigest != job.PolicyDigest {
		return nil, "", "", errors.New("the launch receipt is bound to another launch or digest")
	}
	if in.KernelVerified {
		return nil, "", "", errors.New("the launch receipt claims kernel verification")
	}
	out := &hostproto.Receipt{Version: hostproto.ReceiptVersion, LaunchID: job.LaunchID, TargetID: targetID,
		SpecDigest: job.SpecDigest, PolicyDigest: job.PolicyDigest, BPFObjects: map[string]string{},
		Mounts: []hostproto.MountIdentity{}, BrokerCounts: map[string]uint64{}, ExitCode: in.ExitCode,
		DomainEmpty: in.Cleanup.DomainEmpty, EnforcementReleased: in.Cleanup.EnforcementReleased}
	for name, sum := range in.Objects {
		if sum == nil {
			continue
		}
		if strings.HasSuffix(name, ".bpf.o") {
			out.BPFObjects[name] = *sum
		} else if name == "pilot-network-diagnostic" {
			out.GuardDigest = *sum
		}
	}
	var mountErrors []string
	for _, m := range in.Mounts {
		name := path.Base(m.Path)
		mode := modes[name]
		if mode == "" {
			mode = "read-only"
			if !m.ReadOnly {
				mode = "read-write"
			}
		}
		identity := ""
		switch {
		case mode == "snapshot" && m.TreeSHA256 != nil:
			identity = "sha256:" + *m.TreeSHA256
		case mode != "snapshot" && m.Device != nil && m.Inode != nil:
			identity = strconv.FormatUint(*m.Device, 10) + ":" + strconv.FormatUint(*m.Inode, 10)
		default:
			mountErrors = append(mountErrors, name)
			continue
		}
		out.Mounts = append(out.Mounts, hostproto.MountIdentity{Name: name, Mode: mode, Identity: identity})
	}
	if in.StartedAt != nil {
		out.StartedAtMS = parseTime(*in.StartedAt)
	}
	out.EndedAtMS = parseTime(in.EndedAt)
	if out.EndedAtMS < out.StartedAtMS {
		out.EndedAtMS = out.StartedAtMS
	}
	reason := receiptReasons[in.Reason]
	if reason == "" {
		reason = reasonCode(in.Reason)
	}
	out.Reason = reason
	status := hostproto.ResultFailed
	if (in.State == "stopped" || in.State == "expired") && in.Cleanup.DomainEmpty && in.Cleanup.EnforcementReleased {
		status = hostproto.ResultSucceeded
	}
	network := map[string]any{"effective_policy_digest": in.PolicyDigest, "mode": in.Mode,
		"lifetime_seconds": in.LifetimeSeconds, "image_id": in.ImageID, "state": in.State, "launcher_reason": in.Reason,
		"evidence_complete": in.EvidenceComplete, "evidence_missing": in.EvidenceMissing, "guard_receipt_sha256": in.GuardSHA256,
		"logs": in.Logs, "output": in.Output, "cleanup_errors": in.Cleanup.Errors, "setup_error": in.SetupError,
		"reconciled": in.Reconciled, "mount_identity_errors": mountErrors, "kernel_verified": false}
	guard := map[string]json.RawMessage{}
	for key, value := range in.Evidence {
		if key != "host" {
			guard[key] = value
		}
	}
	network["guard"] = guard
	host := in.Evidence["host"]
	if err := fitReceipt(out, network, host); err != nil {
		return nil, "", "", err
	}
	if err := out.Check(job); err != nil {
		return nil, "", "", err
	}
	return out, status, reason, nil
}

// fitReceipt places the evidence blocks, trimming lists (never counts or
// digests) until the receipt fits the protocol bound.
func fitReceipt(out *hostproto.Receipt, network map[string]any, host json.RawMessage) error {
	attempts := []func(){
		func() {},
		func() { trimGuard(network, "target", "network_denials", "rule_ids") },
		func() { host = trimHost(host, 10) },
		func() { host = trimHost(host, 0); trimGuard(network, "network") },
		func() {
			host = json.RawMessage(`{"trimmed":true}`)
			network["guard"] = map[string]any{"trimmed": true}
			delete(network, "logs")
		},
	}
	for _, step := range attempts {
		step()
		encoded, err := json.Marshal(network)
		if err != nil {
			return err
		}
		out.NetworkEvidence = encoded
		out.HostControlEvidence = nil
		if len(host) > 0 && string(host) != "null" {
			out.HostControlEvidence = host
		}
		full, err := json.Marshal(out)
		if err != nil {
			return err
		}
		if len(full) <= hostproto.MaxReceiptBytes {
			return nil
		}
	}
	return errors.New("the launch receipt does not fit the protocol bound")
}

func trimGuard(network map[string]any, keys ...string) {
	guard, ok := network["guard"].(map[string]json.RawMessage)
	if !ok {
		return
	}
	for _, key := range keys {
		if _, present := guard[key]; present {
			guard[key] = json.RawMessage(`"trimmed"`)
		}
	}
}

func trimHost(host json.RawMessage, keep int) json.RawMessage {
	var value map[string]map[string]any
	if json.Unmarshal(host, &value) != nil {
		return host
	}
	for _, part := range value {
		if denials, ok := part["denials"].([]any); ok && len(denials) > keep {
			part["denials"] = denials[:keep]
			part["denials_trimmed"] = true
		}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return host
	}
	return encoded
}

func (d *Daemon) waitLaunch(launchID string, bound time.Duration) bool {
	d.mu.Lock()
	active := d.active[launchID]
	d.mu.Unlock()
	if active == nil {
		return true
	}
	select {
	case <-active.done:
		return true
	case <-time.After(bound):
		return false
	}
}

func (d *Daemon) cancelLaunch(launchID string) {
	d.mu.Lock()
	active := d.active[launchID]
	d.mu.Unlock()
	if active != nil {
		active.cancel()
	}
}

func (d *Daemon) stopJob(ctx context.Context, job hostproto.Job, p hostproto.StopPayload) {
	grace := p.GraceSeconds
	if grace > maxLauncherStopWait {
		grace = maxLauncherStopWait // the runtime's graceful-stop bound; the kill follows
	}
	reason := "stop_requested"
	if p.Reason == "lost_host" || p.Reason == "lost-host" {
		reason = "lost_host"
	}
	var status StopStatus
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		status, err = d.Runtime.Stop(ctx, job.LaunchID, grace, reason)
		if !errors.Is(err, ErrRuntimeBusy) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if errors.Is(err, ErrUnknownLaunch) {
		d.finish(job.ID, hostproto.ResultFailed, "unknown_launch", "this target never ran the launch", nil, "launch_unknown")
		return
	}
	if err != nil {
		// The stop request did not land: stop the supervised runtime directly.
		d.cancelLaunch(job.LaunchID)
		d.progress(job.ID, "stop request failed, cancelling the launch runtime: "+err.Error())
	}
	bound := time.Duration(grace)*time.Second + stopWaitMargin
	if !d.waitLaunch(job.LaunchID, bound) {
		d.cancelLaunch(job.LaunchID)
		d.waitLaunch(job.LaunchID, stopWaitMargin)
	}
	_ = status
	raw, receiptErr := d.Runtime.Receipt(ctx, job.LaunchID)
	if receiptErr != nil && !errors.Is(receiptErr, ErrUnknownLaunch) {
		d.logf("launch %s: receipt read failed: %v", job.LaunchID, receiptErr)
	}
	d.finishWithReceipt(job, raw, d.launchModes(job.LaunchID), "receipt_absent")
}

func (d *Daemon) collectJob(ctx context.Context, job hostproto.Job) {
	raw, err := d.Runtime.Receipt(ctx, job.LaunchID)
	if errors.Is(err, ErrUnknownLaunch) {
		d.finish(job.ID, hostproto.ResultFailed, "unknown_launch", "this target never ran the launch", nil, "launch_unknown")
		return
	}
	if err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "collect_failed", err.Error(), nil, "receipt_unreadable")
		return
	}
	d.finishWithReceipt(job, raw, d.launchModes(job.LaunchID), "receipt_absent")
}

// launchModes recovers the mount modes a launch used from its recorded receipt mounts.
func (d *Daemon) launchModes(launchID string) map[string]string {
	modes := map[string]string{}
	entry, err := d.Ledger.LaunchResult(launchID)
	if err != nil || entry == nil || entry.Result == nil || entry.Result.Receipt == nil {
		return modes
	}
	for _, m := range entry.Result.Receipt.Mounts {
		modes[m.Name] = m.Mode
	}
	return modes
}

func (d *Daemon) provisionJob(ctx context.Context, job hostproto.Job, p hostproto.ProvisionPayload) {
	output, err := d.Runtime.Provision(ctx)
	if err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "provision_failed", lastLines(output, 20)+"\n"+err.Error(), nil, "")
		return
	}
	info, err := d.Runtime.Info(ctx)
	if err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "runtime_unavailable", err.Error(), nil, "")
		return
	}
	for _, image := range p.Images {
		d.progress(job.ID, "pulling "+image)
		if err = d.Runtime.Pull(ctx, image); err != nil {
			d.finish(job.ID, hostproto.ResultFailed, "image_pull_failed", err.Error(), nil, "")
			return
		}
	}
	d.mu.Lock()
	d.caps = nil // refresh on the next poll
	d.mu.Unlock()
	message := fmt.Sprintf("ready: runtime %s, instance %s, source %s, kernel preflight ok=%t", info.Runtime, info.Instance, info.SourceRevision, info.Preflight.OK)
	if !info.Preflight.OK {
		message += " (" + info.Preflight.Error + "; launches will fail closed until it passes)"
	}
	d.finish(job.ID, hostproto.ResultSucceeded, "ready", message, nil, "")
}

func lastLines(text string, n int) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func (d *Daemon) applyProfileJob(ctx context.Context, job hostproto.Job, p hostproto.ApplyProfilePayload) {
	result, err := d.Runtime.StageProfile(ctx, p.ProfileID, p.ProfileVersion, p.Policy)
	if err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "policy_rejected", err.Error(), nil, "")
		return
	}
	d.finish(job.ID, hostproto.ResultSucceeded, "staged", "profile staged: "+string(result), nil, "")
}

func (d *Daemon) snapshotJob(ctx context.Context, job hostproto.Job, p hostproto.SnapshotMountPayload) {
	if !d.hasCapability(ctx, hostproto.CapabilitySnapshots) {
		d.finish(job.ID, hostproto.ResultRejected, "unsupported_capability", "this target does not take snapshot mounts", nil, "")
		return
	}
	result, err := d.Runtime.Snapshot(ctx, p.Name, p.Source, p.MaxBytes, p.MaxEntries)
	if err != nil {
		d.finish(job.ID, hostproto.ResultFailed, "snapshot_failed", err.Error(), nil, "")
		return
	}
	d.finish(job.ID, hostproto.ResultSucceeded, "snapshot_installed", "snapshot installed: "+string(result), nil, "")
}

// Recover runs once at start: the runtime tears down every launch it no
// longer supervises, and each job that was in flight is reported failed with
// host_restarted (or its own terminal receipt when it finished just before).
func (d *Daemon) Recover(ctx context.Context) {
	if _, err := d.Runtime.Reconcile(ctx, "host_restarted"); err != nil {
		d.setDegraded(err.Error())
		d.logf("reconcile failed; launches are refused until it succeeds: %v", err)
	} else {
		d.setDegraded("")
	}
	entries, err := d.Ledger.Unfinished()
	if err != nil {
		d.setDegraded("ledger unreadable: " + err.Error())
		d.logf("ledger unreadable: %v", err)
		return
	}
	for _, entry := range entries {
		job := hostproto.Job{ID: entry.JobID, Type: entry.Type, TargetID: d.Identity.TargetID, LaunchID: entry.LaunchID,
			SpecDigest: entry.SpecDigest, PolicyDigest: entry.PolicyDigest}
		message := "the host agent restarted while this job ran; nothing was retried"
		if entry.LaunchID == "" || (entry.Type != hostproto.JobLaunch && entry.Type != hostproto.JobStop && entry.Type != hostproto.JobCollect) {
			d.finish(entry.JobID, hostproto.ResultFailed, "host_restarted", message, nil, "")
			continue
		}
		raw, receiptErr := d.Runtime.Receipt(ctx, entry.LaunchID)
		if receiptErr != nil || raw == nil {
			d.finish(entry.JobID, hostproto.ResultFailed, "host_restarted", message, nil, "receipt_absent")
			continue
		}
		receipt, status, reason, convertErr := convertReceipt(job, d.Identity.TargetID, raw, map[string]string{})
		if convertErr != nil {
			d.finish(entry.JobID, hostproto.ResultFailed, "host_restarted", message+": "+convertErr.Error(), nil, "receipt_invalid")
			continue
		}
		if reason == "host_restarted" || status != hostproto.ResultSucceeded {
			status = hostproto.ResultFailed
		}
		d.finish(entry.JobID, status, reason, message, receipt, "")
	}
}

func (d *Daemon) retryReconcile(ctx context.Context) {
	d.mu.Lock()
	busy := len(d.active) > 0
	d.mu.Unlock()
	if busy {
		return
	}
	if _, err := d.Runtime.Reconcile(ctx, "host_restarted"); err == nil {
		d.setDegraded("")
	}
}

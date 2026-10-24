// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/broker"
	"alloyium.local/kernel-poc/internal/hostproto"
)

const (
	testTarget = "0123456789abcdef0123456789abcdef"
	testLaunch = "fedcba9876543210fedcba9876543210"
	testToken  = "agtenr_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)

// fakeService checks every host request the way the service must: envelope
// signature, header shape, strictly increasing sequence, unique nonce.
type fakeService struct {
	mu        sync.Mutex
	t         *testing.T
	jobKey    ed25519.PrivateKey
	hostKey   ed25519.PublicKey
	now       func() time.Time
	lastSeq   uint64
	nonces    map[string]bool
	jobs      []hostproto.Envelope
	events    map[string][]hostproto.Event
	offline   bool
	polls     []hostproto.PollRequest
	enrollMAC string
	badMAC    bool
}

func newFakeService(t *testing.T, now func() time.Time) *fakeService {
	_, jobKey, _ := ed25519.GenerateKey(rand.Reader)
	return &fakeService{t: t, jobKey: jobKey, now: now, nonces: map[string]bool{}, events: map[string][]hostproto.Event{}}
}

func (s *fakeService) header(h hostproto.Header) error {
	if err := h.Check(s.now()); err != nil {
		return err
	}
	if h.Sequence <= s.lastSeq {
		return &StatusError{Status: 409, Body: "sequence", LastAccepted: s.lastSeq}
	}
	if s.nonces[h.Nonce] {
		return &StatusError{Status: 409, Body: "nonce replay"}
	}
	s.lastSeq, s.nonces[h.Nonce] = h.Sequence, true
	return nil
}

func (s *fakeService) Enroll(_ context.Context, env hostproto.Envelope) (hostproto.EnrollResponse, error) {
	var request hostproto.EnrollRequest
	if err := hostproto.UnverifiedPayload(env, &request); err != nil {
		return hostproto.EnrollResponse{}, err
	}
	public, _ := hostproto.DecodeKey(request.PublicKey)
	if err := hostproto.Open(env, hostproto.DomainEnroll, public, &request); err != nil {
		return hostproto.EnrollResponse{}, err
	}
	if err := request.Check(s.now()); err != nil || request.Token != testToken {
		return hostproto.EnrollResponse{}, &StatusError{Status: 403, Body: "token rejected " + request.Token}
	}
	s.hostKey = public
	pub := s.jobKey.Public().(ed25519.PublicKey)
	resp := hostproto.EnrollResponse{TargetID: testTarget, TargetName: "local", HostKeyID: hostproto.KeyID(public),
		JobKey: hostproto.EncodeKey(pub), JobKeyID: hostproto.KeyID(pub), PollIntervalSeconds: 5, ServerTimeMS: s.now().UnixMilli()}
	resp.TokenMAC = hostproto.EnrollResponseMAC(testToken, resp)
	if s.badMAC {
		resp.TokenMAC = strings.Repeat("0", 64)
	}
	return resp, nil
}

func (s *fakeService) Poll(_ context.Context, env hostproto.Envelope) (hostproto.PollResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.offline {
		return hostproto.PollResponse{}, errors.New("connection refused")
	}
	var request hostproto.PollRequest
	if err := hostproto.Open(env, hostproto.DomainPoll, s.hostKey, &request); err != nil {
		s.t.Errorf("poll signature: %v", err)
		return hostproto.PollResponse{}, err
	}
	if err := request.Check(s.now()); err != nil {
		s.t.Errorf("poll shape: %v", err)
		return hostproto.PollResponse{}, err
	}
	if err := s.header(request.Header); err != nil {
		return hostproto.PollResponse{}, err
	}
	s.polls = append(s.polls, request)
	jobs := s.jobs
	s.jobs = nil
	return hostproto.PollResponse{ServerTimeMS: s.now().UnixMilli(), PollIntervalSeconds: 5, AcceptedSequence: request.Sequence, Jobs: jobs}, nil
}

func (s *fakeService) Events(_ context.Context, jobID string, env hostproto.Envelope) (hostproto.EventsResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.offline {
		return hostproto.EventsResponse{}, errors.New("connection refused")
	}
	var request hostproto.EventsRequest
	if err := hostproto.Open(env, hostproto.DomainEvents, s.hostKey, &request); err != nil {
		return hostproto.EventsResponse{}, err
	}
	if err := request.Check(s.now()); err != nil {
		s.t.Errorf("events shape: %v", err)
		return hostproto.EventsResponse{}, err
	}
	if err := s.header(request.Header); err != nil {
		return hostproto.EventsResponse{}, err
	}
	held := s.events[jobID]
	for _, event := range request.Events {
		if int(event.Seq) == len(held)+1 {
			held = append(held, event)
		} else if int(event.Seq) > len(held)+1 {
			s.t.Errorf("event gap: got %d after %d", event.Seq, len(held))
		}
	}
	s.events[jobID] = held
	completed := len(held) > 0 && held[len(held)-1].Kind == hostproto.EventResult
	return hostproto.EventsResponse{AcceptedThrough: uint32(len(held)), Completed: completed, JobState: "x"}, nil
}

func (s *fakeService) send(t *testing.T, job hostproto.Job) {
	t.Helper()
	env, err := hostproto.Seal(hostproto.DomainJob, s.jobKey, job)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.jobs = append(s.jobs, env)
	s.mu.Unlock()
}

func (s *fakeService) results(jobID string) []hostproto.JobResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []hostproto.JobResult
	for _, event := range s.events[jobID] {
		if event.Result != nil {
			out = append(out, *event.Result)
		}
	}
	return out
}

func (s *fakeService) kinds(jobID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, event := range s.events[jobID] {
		out = append(out, event.Kind+":"+event.State+event.Stream)
	}
	return out
}

// fakeRuntime records every call; Run replays scripted launcher lines.
type fakeRuntime struct {
	mu         sync.Mutex
	calls      []string
	lines      func(job launcherJob, emit func(LauncherEvent), ctx context.Context)
	jobs       []launcherJob
	receipts   map[string]json.RawMessage
	stopErr    error
	reconcile  error
	info       RuntimeInfo
	provision  error
	stops      []string
	runStarted chan struct{}
}

func newFakeRuntime() *fakeRuntime {
	r := &fakeRuntime{receipts: map[string]json.RawMessage{}, runStarted: make(chan struct{}, 8)}
	r.info.Runtime = RuntimeDockerHost
	r.info.Capabilities = []string{"live-mounts", "snapshots"}
	return r
}

func (r *fakeRuntime) record(call string) {
	r.mu.Lock()
	r.calls = append(r.calls, call)
	r.mu.Unlock()
}

func (r *fakeRuntime) Info(context.Context) (RuntimeInfo, error) {
	r.record("info")
	return r.info, nil
}

func (r *fakeRuntime) Run(ctx context.Context, raw []byte, emit func(LauncherEvent)) error {
	r.record("run")
	var job launcherJob
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&job); err != nil {
		return err
	}
	r.mu.Lock()
	r.jobs = append(r.jobs, job)
	lines := r.lines
	r.mu.Unlock()
	r.runStarted <- struct{}{}
	if lines != nil {
		lines(job, emit, ctx)
	}
	return nil
}

func (r *fakeRuntime) Stop(_ context.Context, launchID string, grace int, reason string) (StopStatus, error) {
	r.record(fmt.Sprintf("stop %s %d %s", launchID, grace, reason))
	r.mu.Lock()
	r.stops = append(r.stops, reason)
	err := r.stopErr
	r.mu.Unlock()
	return StopStatus{State: "stopping", StopRequested: true}, err
}

func (r *fakeRuntime) Receipt(_ context.Context, launchID string) (json.RawMessage, error) {
	r.record("receipt " + launchID)
	r.mu.Lock()
	defer r.mu.Unlock()
	raw, ok := r.receipts[launchID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownLaunch, launchID)
	}
	return raw, nil
}

func (r *fakeRuntime) Reconcile(_ context.Context, reason string) ([]ReconcileItem, error) {
	r.record("reconcile " + reason)
	return nil, r.reconcile
}

func (r *fakeRuntime) StageProfile(_ context.Context, id string, version int, policy []byte) (json.RawMessage, error) {
	r.record("stage " + id)
	return json.RawMessage(`{"policy_digest":"x"}`), nil
}

func (r *fakeRuntime) Snapshot(_ context.Context, name, source string, maxBytes int64, maxEntries int) (json.RawMessage, error) {
	r.record("snapshot " + name + " " + source)
	return json.RawMessage(`{"tree_sha256":"y"}`), nil
}

func (r *fakeRuntime) Pull(_ context.Context, image string) error {
	r.record("pull " + image)
	return nil
}

func (r *fakeRuntime) Provision(context.Context) (string, error) {
	r.record("provision")
	return "ready=true\n", r.provision
}

func (r *fakeRuntime) called(prefix string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, call := range r.calls {
		if strings.HasPrefix(call, prefix) {
			n++
		}
	}
	return n
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type harness struct {
	t       *testing.T
	dir     string
	clock   *clock
	service *fakeService
	runtime *fakeRuntime
	daemon  *Daemon
}

func testConfig() Config {
	return Config{ServiceURL: "https://agentgate.example", Runtime: RuntimeDockerHost, Instance: "demo",
		Launcher: []string{"/usr/bin/python3", "-I", "/var/lib/agentgate-poc-demo/launch.py"}}
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	if err := ensurePrivateDir(dir); err != nil {
		t.Fatal(err)
	}
	c := &clock{t: time.Now()}
	h := &harness{t: t, dir: dir, clock: c, service: newFakeService(t, c.now), runtime: newFakeRuntime()}
	cfg := testConfig()
	if err := saveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := Enroll(context.Background(), dir, cfg, h.service, testToken, "host-1", []string{"docker"}, c.now, rand.Reader); err != nil {
		t.Fatal(err)
	}
	h.open()
	return h
}

func (h *harness) open() {
	h.t.Helper()
	cfg, err := loadConfig(h.dir)
	if err != nil {
		h.t.Fatal(err)
	}
	id, err := loadIdentity(h.dir)
	if err != nil {
		h.t.Fatal(err)
	}
	keys, err := loadOrCreateKeys(h.dir, rand.Reader)
	if err != nil {
		h.t.Fatal(err)
	}
	h.daemon, err = newDaemon(cfg, h.dir, id, keys, h.service, h.runtime, h.clock.now, rand.Reader, nil)
	if err != nil {
		h.t.Fatal(err)
	}
}

func (h *harness) cycle() {
	h.t.Helper()
	ctx := context.Background()
	_ = h.daemon.FlushOutbox(ctx)
	if err := h.daemon.PollOnce(ctx); err != nil {
		h.t.Logf("poll: %v", err)
	}
	h.daemon.Wait()
	if err := h.daemon.FlushOutbox(ctx); err != nil {
		h.t.Logf("flush: %v", err)
	}
}

var jobCounter int

func nextJobID() string {
	jobCounter++
	return fmt.Sprintf("%032x", jobCounter+0x1000)
}

func policyBytes(t *testing.T) []byte {
	raw, err := os.ReadFile("../../poc/ssh-diagnostic/policy.full.example.json")
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		t.Fatal(err)
	}
	return compact.Bytes()
}

func specBytes(mode string, lifetime int, env string) []byte {
	return []byte(`{"version":"agentgate.launch.v1","name":"repo-fixer","target":"local","mode":"` + mode + `","lifetime_seconds":` +
		fmt.Sprint(lifetime) + `,"agent":{"image":"agentgate-coding@sha256:` + strings.Repeat("a", 64) +
		`","command":["sh","-c","echo hi"],"env":` + env + `,"workdir":""},"access":{"profile":"python-dev","version":3},"mounts":[],"secrets":[],"approval":"auto"}`)
}

// specWithSecret is a spec that references secret model-api.
func specWithSecret(mode string, lifetime int) []byte {
	return []byte(strings.Replace(string(specBytes(mode, lifetime, "{}")), `"secrets":[]`, `"secrets":[{"ref":"model-api","expose":{"env":"MODEL_BASE_URL"}}]`, 1))
}

func testLaunchSecret() hostproto.LaunchSecret {
	return hostproto.LaunchSecret{Ref: "model-api", SecretID: strings.Repeat("1", 32), Env: "MODEL_BASE_URL", Upstreams: []string{"api.model.example"},
		Header: "x-api-key", Rules: []hostproto.BrokerRule{{Methods: []string{"POST"}, Path: "/v1/messages", Match: "exact"}}}
}

func (h *harness) launchJob(spec []byte, mounts []hostproto.LaunchMount, secrets []hostproto.LaunchSecret) hostproto.Job {
	policy := policyBytes(h.t)
	if mounts == nil {
		mounts = []hostproto.LaunchMount{}
	}
	if secrets == nil {
		secrets = []hostproto.LaunchSecret{}
	}
	now := h.clock.now()
	var lifetime struct {
		LifetimeSeconds int `json:"lifetime_seconds"`
	}
	_ = json.Unmarshal(spec, &lifetime)
	payload, _ := json.Marshal(hostproto.LaunchPayload{Spec: spec, Policy: policy, ExpiresAtMS: now.Add(time.Duration(lifetime.LifetimeSeconds) * time.Second).UnixMilli(),
		HeartbeatSeconds: 10, Mounts: mounts, Secrets: secrets})
	return hostproto.Job{Version: hostproto.JobVersion, ID: nextJobID(), Type: hostproto.JobLaunch, TargetID: testTarget,
		LaunchID: testLaunch, SpecDigest: hostproto.SHA256Hex(spec), PolicyDigest: hostproto.SHA256Hex(policy),
		IssuedAtMS: now.UnixMilli(), DeadlineMS: now.Add(2 * time.Hour).UnixMilli(), Payload: payload}
}

func (h *harness) boundJob(kind string, payload any) hostproto.Job {
	raw, _ := json.Marshal(payload)
	now := h.clock.now()
	return hostproto.Job{Version: hostproto.JobVersion, ID: nextJobID(), Type: kind, TargetID: testTarget, LaunchID: testLaunch,
		SpecDigest: hostproto.SHA256Hex(specBytes("oneshot", 30, "{}")), PolicyDigest: hostproto.SHA256Hex(policyBytes(h.t)),
		IssuedAtMS: now.UnixMilli(), DeadlineMS: now.Add(time.Hour).UnixMilli(), Payload: raw}
}

func launcherReceiptFor(job launcherJob, state, reason string, clean bool, exit *int) json.RawMessage {
	sum := strings.Repeat("b", 64)
	receipt := map[string]any{"version": "agentgate.launch-receipt.v1", "launch_id": job.LaunchID, "job_id": job.JobID,
		"spec_digest": job.SpecDigest, "policy_digest": job.PolicyDigest, "profile_policy_digest": job.ProfilePolicyDigest,
		"mode": "oneshot", "lifetime_seconds": job.LifetimeSeconds, "image_id": "sha256:" + strings.Repeat("f", 64),
		"state": state, "reason": reason, "exit_code": exit, "started_at": "2026-10-24T10:00:00.000000Z",
		"ended_at": "2026-10-24T10:00:05.000000Z",
		"objects": map[string]any{"network_policy.bpf.o": sum, "fs_access.bpf.o": sum, "process_guard.bpf.o": sum,
			"pilot-network-diagnostic": sum, "run-in-target.sh": sum},
		"mounts": []map[string]any{{"path": "/var/lib/agentgate/mounts/repo", "read_only": true, "device": 2049, "inode": 77}},
		"logs":   map[string]any{"stdout": map[string]any{"bytes": 3}},
		"evidence": map[string]any{"network": map[string]any{"observed": 4, "complete": true}, "complete": true,
			"host": map[string]any{"complete": true, "filesystem": map[string]any{"denials": []any{map[string]any{"path": "/etc/shadow"}}}}},
		"evidence_complete": true, "cleanup": map[string]any{"domain_empty": clean, "enforcement_released": clean, "errors": []string{}},
		"kernel_verified": false}
	raw, _ := json.Marshal(receipt)
	return raw
}

// scripted runs a launch that emits the usual lines and a receipt.
func (h *harness) scripted(state, reason string, clean bool) {
	h.runtime.lines = func(job launcherJob, emit func(LauncherEvent), _ context.Context) {
		emit(LauncherEvent{Event: "state", State: "provisioning"})
		emit(LauncherEvent{Event: "state", State: "running"})
		emit(LauncherEvent{Event: "log", Stream: "stdout", Data: base64.StdEncoding.EncodeToString([]byte("hi\n"))})
		emit(LauncherEvent{Event: "heartbeat"})
		emit(LauncherEvent{Event: "state", State: "stopping"})
		zero := 0
		receipt := launcherReceiptFor(job, state, reason, clean, &zero)
		h.runtime.mu.Lock()
		h.runtime.receipts[job.LaunchID] = receipt
		h.runtime.mu.Unlock()
		emit(LauncherEvent{Event: "receipt", Receipt: receipt})
	}
}

func TestEnrollmentPersistsPrivateKeysAndNeverTheToken(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{signingKeyName, encryptionKeyName, identityName, configName} {
		info, err := os.Stat(filepath.Join(h.dir, name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, err, info)
		}
	}
	filepath.Walk(h.dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			raw, _ := os.ReadFile(path)
			if bytes.Contains(raw, []byte(testToken)) {
				t.Errorf("%s holds the enrollment token", path)
			}
		}
		return nil
	})
	if info, _ := os.Stat(h.dir); info.Mode().Perm() != 0o700 {
		t.Fatal("state directory is not 0700")
	}
}

func TestEnrollmentRejectsAReplyNotBoundToTheToken(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "s")
	_ = ensurePrivateDir(dir)
	c := &clock{t: time.Now()}
	service := newFakeService(t, c.now)
	service.badMAC = true
	if _, err := Enroll(context.Background(), dir, testConfig(), service, testToken, "h", []string{"docker"}, c.now, rand.Reader); err == nil {
		t.Fatal("a substituted job key was accepted")
	}
	if _, err := loadIdentity(dir); err == nil {
		t.Fatal("an identity was saved after a failed enrollment")
	}
	service.badMAC = false
	_, err := Enroll(context.Background(), dir, testConfig(), service, "agtenr_"+strings.Repeat("B", 43), "h", []string{"docker"}, c.now, rand.Reader)
	if err == nil || strings.Contains(err.Error(), strings.Repeat("B", 43)) {
		t.Fatalf("a wrong token was accepted or echoed: %v", err)
	}
	if _, err = Enroll(context.Background(), dir, testConfig(), service, "short", "h", []string{"docker"}, c.now, rand.Reader); err == nil {
		t.Fatal("a malformed token was sent")
	}
}

func TestPollSequenceIsStrictlyIncreasingAcrossRestarts(t *testing.T) {
	h := newHarness(t)
	h.cycle()
	h.cycle()
	first := h.service.lastSeq
	h.open() // a daemon restart reads the persisted counter
	h.cycle()
	if h.service.lastSeq <= first {
		t.Fatalf("sequence went from %d to %d", first, h.service.lastSeq)
	}
	// A lost local counter is resynchronised forward from the service's rejection.
	_ = os.Remove(filepath.Join(h.dir, sequenceName))
	h.open()
	if err := h.daemon.PollOnce(context.Background()); err == nil {
		t.Fatal("a repeated sequence was accepted")
	}
	if err := h.daemon.PollOnce(context.Background()); err != nil {
		t.Fatalf("no resynchronisation: %v", err)
	}
	if len(h.service.polls) == 0 || h.service.polls[0].Heartbeat.KernelVerified {
		t.Fatal("a heartbeat claimed kernel verification")
	}
}

func TestDamagedSequenceFailsClosed(t *testing.T) {
	h := newHarness(t)
	if err := writeFileAtomic(filepath.Join(h.dir, sequenceName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.daemon.PollOnce(context.Background()); err == nil {
		t.Fatal("a damaged sequence was guessed")
	}
}

func TestForgedJobsAreDroppedAndNeverRecorded(t *testing.T) {
	h := newHarness(t)
	job := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	_, forger, _ := ed25519.GenerateKey(rand.Reader)
	env, _ := hostproto.Seal(hostproto.DomainJob, forger, job)
	h.service.jobs = append(h.service.jobs, env)
	// A genuine envelope with a tampered payload.
	good, _ := hostproto.Seal(hostproto.DomainJob, h.service.jobKey, job)
	tampered := good
	tampered.Payload = good.Payload[:len(good.Payload)-4] + "AAAA"
	h.service.jobs = append(h.service.jobs, tampered)
	// A poll-domain signature replayed as a job.
	wrongDomain, _ := hostproto.Seal(hostproto.DomainPoll, h.service.jobKey, job)
	wrongDomain.Domain = hostproto.DomainJob
	h.service.jobs = append(h.service.jobs, wrongDomain)
	h.cycle()
	if h.runtime.called("run") != 0 {
		t.Fatal("a forged job ran")
	}
	if _, err := h.daemon.Ledger.Get(job.ID); err == nil {
		t.Fatal("a forged job entered the ledger")
	}
}

func TestExpiredWrongTargetAndWrongDigestJobsAreRejected(t *testing.T) {
	h := newHarness(t)
	expired := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	expired.DeadlineMS = h.clock.now().Add(-time.Second).UnixMilli()
	other := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	other.TargetID = strings.Repeat("9", 32)
	digest := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	digest.SpecDigest = strings.Repeat("0", 64)
	future := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	future.IssuedAtMS = h.clock.now().Add(10 * time.Minute).UnixMilli()
	future.DeadlineMS = h.clock.now().Add(20 * time.Minute).UnixMilli()
	for _, job := range []hostproto.Job{expired, other, digest, future} {
		h.service.send(t, job)
	}
	h.cycle()
	if h.runtime.called("run") != 0 {
		t.Fatal("an invalid job ran")
	}
	for _, job := range []hostproto.Job{expired, other, digest, future} {
		results := h.service.results(job.ID)
		if len(results) != 1 || results[0].Status != hostproto.ResultRejected || results[0].Reason != "invalid_job" {
			t.Fatalf("job %s results %+v", job.ID, results)
		}
	}
}

func TestLaunchRunsOnceAndReportsAReceipt(t *testing.T) {
	h := newHarness(t)
	h.scripted("stopped", "exited", true)
	job := h.launchJob(specBytes("oneshot", 30, `{"EDITOR":"vi"}`), []hostproto.LaunchMount{{Name: "repo", Source: "/srv/repos/app", Mode: "read-only", Path: hostproto.MountRoot + "/repo"}}, nil)
	h.service.send(t, job)
	h.cycle()
	if h.runtime.called("run") != 1 {
		t.Fatal("the launch did not run exactly once")
	}
	launched := h.runtime.jobs[0]
	if launched.LifetimeSeconds > 30 || launched.LifetimeSeconds < 28 || launched.ProfilePolicyDigest != job.PolicyDigest || launched.SpecDigest != job.SpecDigest {
		t.Fatalf("launcher job %+v", launched)
	}
	var policy struct {
		Mode     string `json:"mode"`
		Duration int    `json:"duration_seconds"`
	}
	_ = json.Unmarshal(launched.Policy, &policy)
	if policy.Mode != "oneshot" || policy.Duration != launched.LifetimeSeconds {
		t.Fatalf("effective policy %s", launched.Policy)
	}
	kinds := h.service.kinds(job.ID)
	want := []string{"state:provisioning", "state:running", "log:stdout", "state:stopping", "result:"}
	if strings.Join(kinds, ",") != strings.Join(want, ",") {
		t.Fatalf("events %v", kinds)
	}
	result := h.service.results(job.ID)[0]
	if result.Status != hostproto.ResultSucceeded || result.Reason != "exited" || result.Receipt == nil {
		t.Fatalf("result %+v", result)
	}
	receipt := result.Receipt
	if err := receipt.Check(job); err != nil || receipt.KernelVerified || !receipt.DomainEmpty || len(receipt.BPFObjects) != 3 || receipt.GuardDigest == "" {
		t.Fatalf("receipt %+v: %v", receipt, err)
	}
	if len(receipt.Mounts) != 1 || receipt.Mounts[0].Identity != "2049:77" || receipt.Mounts[0].Mode != "read-only" {
		t.Fatalf("mounts %+v", receipt.Mounts)
	}
	if !bytes.Contains(receipt.NetworkEvidence, []byte(`"effective_policy_digest"`)) || !bytes.Contains(receipt.HostControlEvidence, []byte("/etc/shadow")) {
		t.Fatal("evidence blocks absent")
	}
	// The same job id again: never run again; the recorded result stands.
	h.service.send(t, job)
	h.cycle()
	if h.runtime.called("run") != 1 {
		t.Fatal("a replayed job id ran twice")
	}
	if !h.daemon.Outbox.Completed(job.ID) {
		t.Fatal("the service did not complete the job")
	}
}

func TestUncleanTeardownIsNeverSuccess(t *testing.T) {
	h := newHarness(t)
	h.scripted("stopped", "exited", false)
	job := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	h.service.send(t, job)
	h.cycle()
	if result := h.service.results(job.ID)[0]; result.Status != hostproto.ResultFailed {
		t.Fatalf("an uncleaned launch succeeded: %+v", result)
	}
}

func TestLaunchesThatCannotRunAreRejectedBeforeAnything(t *testing.T) {
	h := newHarness(t)
	h.runtime.info.Capabilities = []string{"snapshots"}
	h.daemon.caps = nil
	cases := map[string]hostproto.Job{
		"broker_unavailable":     h.launchJob(specWithSecret("oneshot", 30), nil, []hostproto.LaunchSecret{testLaunchSecret()}),
		"secret_binding_differs": h.launchJob(specBytes("oneshot", 30, "{}"), nil, []hostproto.LaunchSecret{testLaunchSecret()}),
		"secret_in_env":          h.launchJob(specBytes("oneshot", 30, `{"GITHUB_TOKEN":"x"}`), nil, nil),
		"invalid_lifetime":       h.launchJob(specBytes("session", 30, "{}"), nil, nil),
		"unsupported_capability": h.launchJob(specBytes("oneshot", 30, "{}"),
			[]hostproto.LaunchMount{{Name: "repo", Source: "/srv/repos/app", Mode: "read-write", Path: hostproto.MountRoot + "/repo"}}, nil),
	}
	for _, job := range cases {
		h.service.send(t, job)
	}
	h.cycle()
	if h.runtime.called("run") != 0 {
		t.Fatal("a refused launch ran")
	}
	for reason, job := range cases {
		results := h.service.results(job.ID)
		if len(results) != 1 || results[0].Status != hostproto.ResultRejected || results[0].Reason != reason || results[0].EvidenceMissing != "not_started" {
			t.Errorf("%s: %+v", reason, results)
		}
	}
}

func TestMountsOverlappingHostStateOrSecretsAreRefused(t *testing.T) {
	h := newHarness(t)
	h.daemon.Config.SecretRoot = "/srv/agentgate-secrets"
	sources := []string{h.dir, h.dir + "/keys", filepath.Dir(h.dir), "/srv/agentgate-secrets", "/srv/agentgate-secrets/local", "/srv"}
	jobs := []hostproto.Job{}
	for i, source := range sources {
		job := h.launchJob(specBytes("oneshot", 30, "{}"),
			[]hostproto.LaunchMount{{Name: "repo", Source: source, Mode: "snapshot", Path: hostproto.MountRoot + "/repo"}}, nil)
		job.LaunchID = fmt.Sprintf("%032x", 0xabc0+i)
		h.service.send(t, job)
		jobs = append(jobs, job)
	}
	h.cycle()
	if h.runtime.called("run") != 0 {
		t.Fatal("a launch mounting the host state or the secret store ran")
	}
	for i, job := range jobs {
		results := h.service.results(job.ID)
		if len(results) != 1 || results[0].Status != hostproto.ResultRejected || results[0].Reason != "invalid_mount" {
			t.Errorf("%s: %+v", sources[i], results)
		}
	}
}

func TestShortenedExpiryShortensTheKernelLifetimeAndTooLateIsRefused(t *testing.T) {
	h := newHarness(t)
	h.scripted("stopped", "exited", true)
	job := h.launchJob(specBytes("session", 3600, "{}"), nil, nil)
	var payload hostproto.LaunchPayload
	_ = json.Unmarshal(job.Payload, &payload)
	payload.ExpiresAtMS = h.clock.now().Add(30 * time.Minute).UnixMilli()
	job.Payload, _ = json.Marshal(payload)
	h.service.send(t, job)
	h.cycle()
	if got := h.runtime.jobs[0].LifetimeSeconds; got > 1800 || got < 1790 {
		t.Fatalf("effective lifetime %d", got)
	}
	late := h.launchJob(specBytes("session", 3600, "{}"), nil, nil)
	_ = json.Unmarshal(late.Payload, &payload)
	payload.ExpiresAtMS = h.clock.now().Add(30 * time.Second).UnixMilli()
	late.Payload, _ = json.Marshal(payload)
	late.LaunchID = strings.Repeat("e", 32)
	h.service.send(t, late)
	h.cycle()
	if r := h.service.results(late.ID); len(r) != 1 || r[0].Reason != "expired_before_start" {
		t.Fatalf("late launch %+v", r)
	}
}

func TestOneLaunchPerTarget(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	h.runtime.lines = func(job launcherJob, emit func(LauncherEvent), _ context.Context) {
		<-release
		zero := 0
		emit(LauncherEvent{Event: "receipt", Receipt: launcherReceiptFor(job, "stopped", "exited", true, &zero)})
	}
	first := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	h.service.send(t, first)
	_ = h.daemon.PollOnce(context.Background())
	<-h.runtime.runStarted
	second := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	second.LaunchID = strings.Repeat("d", 32)
	h.service.send(t, second)
	_ = h.daemon.PollOnce(context.Background())
	if got := h.service.polls[len(h.service.polls)-1].Heartbeat.RunningLaunches; len(got) != 1 || got[0] != testLaunch {
		t.Fatalf("heartbeat running launches %v", got)
	}
	close(release)
	h.daemon.Wait()
	_ = h.daemon.FlushOutbox(context.Background())
	if r := h.service.results(second.ID); len(r) != 1 || r[0].Reason != "target_busy" {
		t.Fatalf("second launch %+v", r)
	}
	if h.runtime.called("run") != 1 {
		t.Fatal("two launches ran")
	}
}

func TestLostServiceStopsTheLaunchAfterItsGrace(t *testing.T) {
	h := newHarness(t)
	release := make(chan struct{})
	h.runtime.lines = func(job launcherJob, emit func(LauncherEvent), _ context.Context) {
		<-release
		zero := 0
		emit(LauncherEvent{Event: "receipt", Receipt: launcherReceiptFor(job, "failed", "service_unreachable", true, &zero)})
	}
	job := h.launchJob(specBytes("session", 3600, "{}"), nil, nil)
	h.service.send(t, job)
	_ = h.daemon.PollOnce(context.Background())
	<-h.runtime.runStarted
	h.service.offline = true
	h.clock.add(20 * time.Second)
	h.daemon.EnforceGrace(context.Background())
	if h.runtime.called("stop") != 0 {
		t.Fatal("stopped within the grace")
	}
	h.clock.add(15 * time.Second) // beyond 3 x 10 s heartbeats
	_ = h.daemon.PollOnce(context.Background())
	h.daemon.EnforceGrace(context.Background())
	h.daemon.EnforceGrace(context.Background())
	if h.runtime.called("stop "+testLaunch+" 0 service_unreachable") != 1 {
		t.Fatalf("calls %v", h.runtime.calls)
	}
	close(release)
	h.daemon.Wait()
	h.service.offline = false
	_ = h.daemon.FlushOutbox(context.Background())
	if r := h.service.results(job.ID); len(r) != 1 || r[0].Status != hostproto.ResultFailed || r[0].Reason != "service_unreachable" {
		t.Fatalf("result %+v", r)
	}
}

func TestReceiptsSurviveARestartUntilAcknowledged(t *testing.T) {
	h := newHarness(t)
	h.scripted("expired", "lifetime_expired", true)
	job := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	h.service.send(t, job)
	_ = h.daemon.PollOnce(context.Background())
	h.daemon.Wait()
	h.service.offline = true
	if err := h.daemon.FlushOutbox(context.Background()); err == nil {
		t.Fatal("an offline upload succeeded")
	}
	h.open() // restart with the service still away
	if pending := h.daemon.Outbox.Pending(); len(pending) != 1 || pending[0] != job.ID {
		t.Fatalf("pending %v", pending)
	}
	h.service.offline = false
	if err := h.daemon.FlushOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	r := h.service.results(job.ID)
	if len(r) != 1 || r[0].Reason != "expired" || r[0].Status != hostproto.ResultSucceeded {
		t.Fatalf("result %+v", r)
	}
	if len(h.daemon.Outbox.Pending()) != 0 || !h.daemon.Outbox.Completed(job.ID) {
		t.Fatal("acknowledged events remain pending")
	}
	entries, _ := os.ReadDir(filepath.Join(h.dir, "outbox", job.ID))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			t.Fatalf("acknowledged event file kept: %s", entry.Name())
		}
	}
}

func TestCrashMidLaunchReportsHostRestarted(t *testing.T) {
	h := newHarness(t)
	job := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	if _, _, err := h.daemon.Ledger.Begin(LedgerEntry{JobID: job.ID, Type: job.Type, LaunchID: job.LaunchID, SpecDigest: job.SpecDigest, PolicyDigest: job.PolicyDigest, DeadlineMS: job.DeadlineMS}); err != nil {
		t.Fatal(err)
	}
	_, _ = h.daemon.Ledger.Update(job.ID, JobRunning, nil)
	// The runtime's reconcile wrote this receipt for the abandoned launch.
	effective := launcherJob{LaunchID: job.LaunchID, JobID: job.ID, SpecDigest: job.SpecDigest, ProfilePolicyDigest: job.PolicyDigest, PolicyDigest: strings.Repeat("c", 64), LifetimeSeconds: 30}
	h.runtime.receipts[job.LaunchID] = launcherReceiptFor(effective, "failed", "host_restarted", true, nil)
	h.open()
	h.daemon.Recover(context.Background())
	if h.runtime.called("reconcile host_restarted") != 1 {
		t.Fatal("no reconcile at start")
	}
	_ = h.daemon.FlushOutbox(context.Background())
	r := h.service.results(job.ID)
	if len(r) != 1 || r[0].Status != hostproto.ResultFailed || r[0].Reason != "host_restarted" || r[0].Receipt == nil {
		t.Fatalf("result %+v", r)
	}
	// The job is finished: a replay never runs it.
	h.service.send(t, job)
	h.cycle()
	if h.runtime.called("run") != 0 {
		t.Fatal("a recovered job ran again")
	}
	// A failed reconcile refuses new launches until it succeeds.
	h.runtime.reconcile = errors.New("busy")
	h.daemon.Recover(context.Background())
	next := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	h.service.send(t, next)
	h.cycle()
	if r := h.service.results(next.ID); len(r) != 1 || r[0].Reason != "host_degraded" {
		t.Fatalf("degraded launch %+v", r)
	}
}

func TestRuntimeDeathWithoutReceiptTearsDownAndReports(t *testing.T) {
	h := newHarness(t)
	h.runtime.lines = func(job launcherJob, emit func(LauncherEvent), _ context.Context) {
		emit(LauncherEvent{Event: "state", State: "provisioning"})
		h.runtime.receipts[job.LaunchID] = launcherReceiptFor(job, "failed", "launcher_lost", true, nil)
	}
	job := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	h.service.send(t, job)
	h.cycle()
	if h.runtime.called("stop "+testLaunch+" 0 stop_requested") != 1 {
		t.Fatalf("no teardown after runtime death: %v", h.runtime.calls)
	}
	if r := h.service.results(job.ID); len(r) != 1 || r[0].Reason != "launcher_lost" || r[0].Status != hostproto.ResultFailed {
		t.Fatalf("result %+v", r)
	}
}

func TestDoubleStopReturnsTheRecordedReceipt(t *testing.T) {
	h := newHarness(t)
	h.scripted("stopped", "stop_requested", true)
	launch := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	h.service.send(t, launch)
	h.cycle()
	stop := h.boundJob(hostproto.JobStop, hostproto.StopPayload{Reason: "operator-stop", GraceSeconds: 300})
	stop.SpecDigest, stop.PolicyDigest = launch.SpecDigest, launch.PolicyDigest
	again := stop
	again.ID = nextJobID()
	h.service.send(t, stop)
	h.service.send(t, again)
	h.cycle()
	for _, id := range []string{stop.ID, again.ID} {
		r := h.service.results(id)
		if len(r) != 1 || r[0].Receipt == nil || r[0].Status != hostproto.ResultSucceeded || r[0].Reason != "stopped" {
			t.Fatalf("stop %s: %+v", id, r)
		}
	}
	if h.runtime.called("stop "+testLaunch+" 30 stop_requested") != 2 {
		t.Fatalf("grace is not capped at the runtime bound: %v", h.runtime.calls)
	}
	unknown := h.boundJob(hostproto.JobStop, hostproto.StopPayload{Reason: "operator-stop", GraceSeconds: 1})
	unknown.LaunchID = strings.Repeat("a", 32)
	h.runtime.stopErr = fmt.Errorf("%w: never ran", ErrUnknownLaunch)
	h.service.send(t, unknown)
	h.cycle()
	if r := h.service.results(unknown.ID); len(r) != 1 || r[0].Reason != "unknown_launch" {
		t.Fatalf("unknown stop %+v", r)
	}
}

func TestMalformedSecretJobsAreRejectedAndOtherJobsRun(t *testing.T) {
	h := newHarness(t)
	sealed := make([]byte, 80) // not a secretseal envelope (the retired format's framing)
	put, _ := json.Marshal(hostproto.SecretPutPayload{SecretID: strings.Repeat("1", 32), Name: "model-api", Upstreams: []string{"api.model.example"},
		Header: "x-api-key", Ciphertext: hostproto.EncodeSealed(sealed), CiphertextSHA256: hostproto.SHA256Hex(sealed)})
	now := h.clock.now()
	plain := func(kind string, payload []byte, policy string) hostproto.Job {
		return hostproto.Job{Version: hostproto.JobVersion, ID: nextJobID(), Type: kind, TargetID: testTarget, PolicyDigest: policy,
			IssuedAtMS: now.UnixMilli(), DeadlineMS: now.Add(time.Hour).UnixMilli(), Payload: payload}
	}
	secret := plain(hostproto.JobSecretPut, put, "")
	provision := plain(hostproto.JobProvision, []byte(`{"images":["agentgate-coding@sha256:`+strings.Repeat("a", 64)+`"],"reason":"bring-up"}`), "")
	snapshot := plain(hostproto.JobSnapshotMount, []byte(`{"name":"repo","source":"/srv/repos/app","max_bytes":1024,"max_entries":10}`), "")
	policy := policyBytes(t)
	apply, _ := json.Marshal(hostproto.ApplyProfilePayload{ProfileID: strings.Repeat("a", 32), ProfileVersion: 3, Policy: policy})
	profile := plain(hostproto.JobApplyProfile, apply, hostproto.SHA256Hex(policy))
	for _, job := range []hostproto.Job{secret, provision, snapshot, profile} {
		h.service.send(t, job)
	}
	h.cycle()
	if r := h.service.results(secret.ID); len(r) != 1 || r[0].Status != hostproto.ResultRejected || r[0].Reason != "invalid_job" || r[0].SecretReceipt != nil {
		t.Fatalf("secret %+v", r)
	}
	for _, job := range []hostproto.Job{provision, snapshot, profile} {
		if r := h.service.results(job.ID); len(r) != 1 || r[0].Status != hostproto.ResultSucceeded {
			t.Fatalf("%s %+v", job.Type, r)
		}
	}
	if h.runtime.called("pull agentgate-coding@sha256:") != 1 || h.runtime.called("snapshot repo /srv/repos/app") != 1 {
		t.Fatalf("calls %v", h.runtime.calls)
	}
	failing := plain(hostproto.JobProvision, []byte(`{"images":[],"reason":"bring-up"}`), "")
	h.runtime.provision = errors.New("agentgate-appliance-error: supported host requires the /dev/kvm character device")
	h.service.send(t, failing)
	h.cycle()
	r := h.service.results(failing.ID)
	if len(r) != 1 || r[0].Reason != "provision_failed" {
		t.Fatalf("provision failure %+v", r)
	}
}

func TestOversizedLogsAreBoundedAndValidUTF8(t *testing.T) {
	h := newHarness(t)
	h.runtime.lines = func(job launcherJob, emit func(LauncherEvent), _ context.Context) {
		chunk := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff, 'a'}, 4096))
		for i := 0; i < 2200; i++ {
			emit(LauncherEvent{Event: "log", Stream: "stderr", Data: chunk})
		}
		emit(LauncherEvent{Event: "log", Stream: "../etc", Data: chunk})
		zero := 0
		emit(LauncherEvent{Event: "receipt", Receipt: launcherReceiptFor(job, "stopped", "exited", true, &zero)})
	}
	job := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	h.service.send(t, job)
	for i := 0; i < 200 && !h.daemon.Outbox.Completed(job.ID); i++ {
		h.cycle()
	}
	h.service.mu.Lock()
	events := h.service.events[job.ID]
	h.service.mu.Unlock()
	if len(events) > hostproto.MaxEventsPerJob || events[len(events)-1].Kind != hostproto.EventResult {
		t.Fatalf("%d events, last %+v", len(events), events[len(events)-1])
	}
	if h.daemon.Outbox.Dropped(job.ID) == 0 {
		t.Fatal("no log event was dropped beyond the budget")
	}
}

func TestReceiptFitsTheProtocolBound(t *testing.T) {
	job := hostproto.Job{ID: strings.Repeat("1", 32), TargetID: testTarget, LaunchID: testLaunch, SpecDigest: strings.Repeat("a", 64), PolicyDigest: strings.Repeat("b", 64)}
	effective := launcherJob{LaunchID: testLaunch, SpecDigest: job.SpecDigest, ProfilePolicyDigest: job.PolicyDigest}
	var receipt map[string]any
	_ = json.Unmarshal(launcherReceiptFor(effective, "stopped", "exited", true, nil), &receipt)
	denials := make([]any, 2000)
	for i := range denials {
		denials[i] = map[string]any{"path": strings.Repeat("x", 150), "sequence": i}
	}
	receipt["evidence"].(map[string]any)["host"] = map[string]any{"filesystem": map[string]any{"denials": denials, "raw_sha256": "keep"}, "process": map[string]any{"denials": denials}}
	raw, _ := json.Marshal(receipt)
	out, _, _, err := convertReceipt(job, testTarget, raw, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(out)
	if len(encoded) > hostproto.MaxReceiptBytes || !bytes.Contains(out.HostControlEvidence, []byte("raw_sha256")) {
		t.Fatalf("receipt %d bytes", len(encoded))
	}
	receipt["launch_id"] = strings.Repeat("9", 32)
	raw, _ = json.Marshal(receipt)
	if _, _, _, err = convertReceipt(job, testTarget, raw, nil, nil); err == nil {
		t.Fatal("a receipt for another launch was forwarded")
	}
	receipt["launch_id"] = testLaunch
	receipt["kernel_verified"] = true
	raw, _ = json.Marshal(receipt)
	if _, _, _, err = convertReceipt(job, testTarget, raw, nil, nil); err == nil {
		t.Fatal("a receipt claiming kernel verification was forwarded")
	}
}

func TestServiceOriginRules(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://agentgate.example": true, "https://agentgate.example:8443/": true, "http://agentgate.example": false,
		"https://agentgate.example/api": false, "https://user@agentgate.example": false, "ftp://x": false,
		"https://agentgate.example?x=1": false, "http://127.0.0.1:8080": false, "": false,
	} {
		if _, err := ServiceOrigin(raw, false); (err == nil) != ok {
			t.Errorf("%q: %v", raw, err)
		}
	}
	if _, err := ServiceOrigin("http://127.0.0.1:8080", true); err != nil {
		t.Fatal(err)
	}
	if _, err := ServiceOrigin("http://10.0.0.1:8080", true); err == nil {
		t.Fatal("http to a non-loopback address was allowed")
	}
	bad := testConfig()
	bad.Launcher = []string{"python3", "launch.py"}
	if bad.Validate() == nil {
		t.Fatal("a relative launcher was accepted")
	}
	bad = testConfig()
	bad.Instance = "../x"
	if bad.Validate() == nil {
		t.Fatal("a hostile instance name was accepted")
	}
}

func TestStateFilesRefuseLooseCustody(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	_ = os.WriteFile(path, []byte("x"), 0o644)
	if _, err := readPrivateFile(path, 10); err == nil {
		t.Fatal("a group-readable file was trusted")
	}
	_ = os.Chmod(path, 0o600)
	link := filepath.Join(dir, "l")
	_ = os.Symlink(path, link)
	if _, err := readPrivateFile(link, 10); err == nil {
		t.Fatal("a symlink was followed")
	}
	loose := filepath.Join(dir, "loose")
	_ = os.Mkdir(loose, 0o755)
	if err := ensurePrivateDir(loose); err == nil {
		t.Fatal("a 0755 state directory was accepted")
	}
	if err := writeFileAtomic(filepath.Join(dir, "seed"), []byte("not base64!"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateSeed(filepath.Join(dir, "seed"), rand.Reader); err == nil {
		t.Fatal("a damaged key was replaced")
	}
}

func TestLedgerIsAtMostOnce(t *testing.T) {
	c := &clock{t: time.Now()}
	dir := filepath.Join(t.TempDir(), "s")
	_ = ensurePrivateDir(dir)
	ledger, err := openLedger(dir, c.now)
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 32)
	if _, fresh, _ := ledger.Begin(LedgerEntry{JobID: id, Type: "launch"}); !fresh {
		t.Fatal("first begin not fresh")
	}
	if _, fresh, _ := ledger.Begin(LedgerEntry{JobID: id, Type: "launch"}); fresh {
		t.Fatal("a job id began twice")
	}
	if _, _, err = ledger.Begin(LedgerEntry{JobID: "../../x"}); err == nil {
		t.Fatal("a hostile job id reached the file system")
	}
	if _, err = ledger.Update(id, JobDone, &hostproto.JobResult{Status: "failed", Reason: "x"}); err != nil {
		t.Fatal(err)
	}
	if _, err = ledger.Update(id, JobRunning, nil); err == nil {
		t.Fatal("a finished job changed")
	}
}

func TestReasonCodesAndMessagesAreBounded(t *testing.T) {
	if got := reasonCode("Setup Failed: /etc; rm -rf"); got != "setup_failed:__etc_rm_-rf" {
		t.Fatalf("reason %q", got)
	}
	if len(reasonCode(strings.Repeat("a", 200))) > 64 || reasonCode("!!!") != "unspecified" {
		t.Fatal("reason bound")
	}
	for _, piece := range logMessages(bytes.Repeat([]byte("é\xff"), 9000)) {
		if len(piece) > hostproto.MaxEventMessage || !strings.Contains(piece, "é") {
			t.Fatal("log message bound")
		}
	}
}

// TestLauncherJobMatchesThePythonValidator proves the Go launcher job is
// exactly what launch_job.py accepts, so the two sides cannot drift: a plain
// launch and a launch with a broker block.
func TestLauncherJobMatchesThePythonValidator(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable; the cross-language check did not run")
	}
	h := newHarness(t)
	job := h.launchJob(specBytes("session", 7200, `{"EDITOR":"vi"}`), []hostproto.LaunchMount{{Name: "repo", Source: "/srv/repos/app", Mode: "snapshot", Path: hostproto.MountRoot + "/repo"}}, nil)
	var payload hostproto.LaunchPayload
	_ = json.Unmarshal(job.Payload, &payload)
	prepared, code, err := prepareLaunch(job, payload, []string{hostproto.CapabilitySnapshots}, h.clock.now(), testTarget, nil)
	if err != nil {
		t.Fatalf("%s: %v", code, err)
	}
	raw := prepared.raw
	script := `import json, sys
sys.path.insert(0, sys.argv[1])
import launch_job
launch = launch_job.check_job(sys.stdin.buffer.read(), ['snapshots'])
print(json.dumps({'mode': launch['mode'], 'lifetime': launch['lifetime_seconds'], 'mounts': launch['mounts'], 'workdir': launch['workdir'],
                  'env': launch['env'], 'broker': launch['broker']}))`
	run := func(raw []byte) []byte {
		cmd := exec.Command(python, "-I", "-c", script, "../../poc/ssh-diagnostic")
		cmd.Stdin = bytes.NewReader(raw)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("launch_job.py refused the Go launcher job: %s", out)
		}
		return out
	}
	out := run(raw)
	if !bytes.Contains(out, []byte(`"mode": "session"`)) || !bytes.Contains(out, []byte(`"mode": "snapshot"`)) || !bytes.Contains(out, []byte(`"broker": null`)) {
		t.Fatalf("python view %s", out)
	}
	// A launch with a secret: the Go broker plan and the Python broker check agree.
	spec := specWithSecret("oneshot", 30)
	policy := brokerPolicy(t, "oneshot", 30, "172.30.9.2")
	now := h.clock.now()
	secretPayload, _ := json.Marshal(hostproto.LaunchPayload{Spec: spec, Policy: policy, ExpiresAtMS: now.Add(30 * time.Second).UnixMilli(),
		HeartbeatSeconds: 10, Mounts: []hostproto.LaunchMount{}, Secrets: []hostproto.LaunchSecret{testLaunchSecret()}})
	secretJob := hostproto.Job{Version: hostproto.JobVersion, ID: nextJobID(), Type: hostproto.JobLaunch, TargetID: testTarget, LaunchID: testLaunch,
		SpecDigest: hostproto.SHA256Hex(spec), PolicyDigest: hostproto.SHA256Hex(policy), IssuedAtMS: now.UnixMilli(), DeadlineMS: now.Add(time.Hour).UnixMilli(), Payload: secretPayload}
	if _, err := secretJob.Check(testTarget, now); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(secretJob.Payload, &payload)
	cfg := &BrokerConfig{Image: "agentgate-broker@sha256:" + strings.Repeat("b", 64), UID: 10002, GID: 10002, EgressNetwork: "agentgate-egress"}
	prepared, code, err = prepareLaunch(secretJob, payload, []string{hostproto.CapabilityBrokeredSecrets}, now, testTarget, cfg)
	if err != nil {
		t.Fatalf("%s: %v", code, err)
	}
	out = run(prepared.raw)
	if !bytes.Contains(out, []byte(`"MODEL_BASE_URL": "http://172.30.9.2:8443/model-api"`)) || !bytes.Contains(out, []byte(`"network": "agentgate-`+testLaunch+`-broker"`)) ||
		!bytes.Contains(out, []byte(`"target_address": "172.30.9.3"`)) {
		t.Fatalf("python view of a broker launch %s", out)
	}
	if _, err := broker.ParseConfig(prepared.config); err != nil || bytes.Contains(prepared.raw, []byte("/run/agentgate/secrets")) {
		t.Fatalf("broker config %v", err)
	}
}

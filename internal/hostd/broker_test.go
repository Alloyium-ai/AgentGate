// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/broker"
	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/pocpolicy"
	"alloyium.local/kernel-poc/internal/secretseal"
)

const (
	fakeValue      = "sk-test-FAKE-hostd-0123456789abcdef"
	brokerAddr     = "172.30.7.2"
	testBrokerUID  = 10002
	testBrokerGID  = 10002
	brokerImage    = "agentgate-broker@sha256:" + "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0"
	brokerUpstream = "api.model.example"
)

// fakeBroker stands in for the broker container: it writes the stats a real
// broker writes (running at start, final counts at stop) and records calls.
type fakeBroker struct {
	mu        sync.Mutex
	calls     []string
	checkErr  error
	startErr  error
	removeErr error
	noStats   bool
	forwarded uint64
	running   bool
	launches  []*BrokerLaunch
}

func (f *fakeBroker) record(call string) {
	f.mu.Lock()
	f.calls = append(f.calls, call)
	f.mu.Unlock()
}

func (f *fakeBroker) called() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeBroker) Check(context.Context, BrokerConfig) error { f.record("check"); return f.checkErr }

func writeFakeStats(b *BrokerLaunch, state string, forwarded uint64) error {
	config := b.Config
	if config == nil {
		// A broker recovered after a restart: its configuration is on disk.
		config, _ = os.ReadFile(b.ConfigPath)
	}
	cfg, err := broker.ParseConfig(config)
	if err != nil {
		return fmt.Errorf("the broker got a configuration it cannot parse: %v", err)
	}
	doc := broker.StatsDocument{Version: broker.StatsVersion, LaunchID: b.LaunchID, TargetID: b.TargetID, ConfigSHA256: b.ConfigSHA256,
		Listen: "tcp:" + net.JoinHostPort(b.Address.String(), fmt.Sprint(b.Port)), StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), Deadline: cfg.Deadline, State: state, Complete: state == "stopped",
		Hardening: broker.Hardening{UID: testBrokerUID, GID: testBrokerGID, NotDumpable: true, CoreLimitZero: true, NoNewPrivs: true, NoCapabilities: true},
		Denied:    map[string]uint64{"path_not_allowed": 1}, Routes: map[string]*broker.RouteStats{}, Denials: []broker.DenialRecord{}}
	if state == "stopped" {
		doc.StopReason = "signal"
	}
	doc.Requests = broker.RequestTotals{Total: forwarded + 1, Denied: 1, Forwarded: forwarded}
	for i, r := range cfg.Routes {
		route := &broker.RouteStats{Upstream: fmt.Sprintf("%s:%d", r.Upstream.Host, r.Upstream.Port), Status: map[string]uint64{}, Errors: map[string]uint64{}}
		if i == 0 {
			route.Requests, route.Forwarded, route.Status["2xx"] = forwarded, forwarded, forwarded
		}
		doc.Routes[r.Name] = route
	}
	raw, _ := json.Marshal(doc)
	return os.WriteFile(b.StatsPath(), raw, 0o600)
}

func (f *fakeBroker) Start(_ context.Context, b *BrokerLaunch) error {
	f.record("start " + b.LaunchID)
	f.mu.Lock()
	f.launches = append(f.launches, b)
	err, noStats := f.startErr, f.noStats
	f.running = err == nil
	f.mu.Unlock()
	if err != nil {
		return err
	}
	if !noStats {
		return writeFakeStats(b, "running", 0)
	}
	return nil
}

func (f *fakeBroker) Stop(_ context.Context, b *BrokerLaunch, grace time.Duration) error {
	f.record(fmt.Sprintf("stop %s %s", b.LaunchID, grace))
	f.mu.Lock()
	running, forwarded, noStats := f.running, f.forwarded, f.noStats
	f.running = false
	f.mu.Unlock()
	if running && !noStats {
		return writeFakeStats(b, "stopped", forwarded)
	}
	return nil
}

func (f *fakeBroker) Remove(_ context.Context, b *BrokerLaunch) error {
	f.record("remove " + b.LaunchID)
	return f.removeErr
}

func (f *fakeBroker) isRunning() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

type brokerHarness struct {
	*harness
	broker *fakeBroker
	root   string
}

func newBrokerHarness(t *testing.T) *brokerHarness {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the broker stats directory is chowned to the broker identity, which needs root")
	}
	h := newHarness(t)
	root := filepath.Join(t.TempDir(), "secrets")
	cfg := h.daemon.Config
	cfg.SecretRoot = root
	cfg.Broker = &BrokerConfig{Image: brokerImage, UID: testBrokerUID, GID: testBrokerGID, EgressNetwork: "agentgate-egress"}
	if err := saveConfig(h.dir, cfg); err != nil {
		t.Fatal(err)
	}
	h.open()
	fb := &fakeBroker{forwarded: 3}
	h.daemon.Broker = fb
	return &brokerHarness{harness: h, broker: fb, root: root}
}

func (h *brokerHarness) reopen() {
	h.open()
	h.daemon.Broker = h.broker
}

// sealedPut is what a client does: take the seal key the host published in
// its heartbeat, verify it against the host key pinned out of band, seal.
func (h *brokerHarness) sealedPut(name, value string, at time.Time) (hostproto.Job, *secretseal.Sealed) {
	h.t.Helper()
	h.cycle()
	h.service.mu.Lock()
	beat := h.service.polls[len(h.service.polls)-1].Heartbeat
	h.service.mu.Unlock()
	rec, err := secretseal.ParseSignedKeyRecord(beat.SealKey)
	if err != nil {
		h.t.Fatal(err)
	}
	hostPub := h.daemon.Keys.Signing.Public().(ed25519.PublicKey)
	pub, err := secretseal.VerifyKeyRecord(rec, hostPub, secretseal.HostKeyFingerprint(hostPub), testTarget, at)
	if err != nil {
		h.t.Fatal(err)
	}
	sealed, err := secretseal.SealAt(pub, testTarget, name, []byte(value), at)
	if err != nil {
		h.t.Fatal(err)
	}
	raw, _ := json.Marshal(sealed.Envelope)
	payload, _ := json.Marshal(hostproto.SecretPutPayload{SecretID: strings.Repeat("1", 32), Name: name, Upstreams: []string{brokerUpstream},
		Header: "x-api-key", Ciphertext: sealed.Envelope.Encode(), CiphertextSHA256: hostproto.SHA256Hex(raw)})
	now := h.clock.now()
	return hostproto.Job{Version: hostproto.JobVersion, ID: nextJobID(), Type: hostproto.JobSecretPut, TargetID: testTarget,
		IssuedAtMS: now.UnixMilli(), DeadlineMS: now.Add(time.Hour).UnixMilli(), Payload: payload}, sealed
}

func (h *brokerHarness) store(name, value string) {
	h.t.Helper()
	job, sealed := h.sealedPut(name, value, h.clock.now())
	h.service.send(h.t, job)
	h.cycle()
	r := h.service.results(job.ID)
	if len(r) != 1 || r[0].Status != hostproto.ResultSucceeded || r[0].SecretReceipt == nil {
		h.t.Fatalf("secret-put %+v", r)
	}
	receipt := secretseal.Receipt(*r[0].SecretReceipt)
	if _, err := sealed.VerifyReceipt(&receipt); err != nil {
		h.t.Fatalf("the client cannot verify the host's receipt: %v", err)
	}
}

func brokerPolicy(t testing.TB, mode string, lifetime int, address string) []byte {
	raw, err := os.ReadFile("../../poc/ssh-diagnostic/policy.full.example.json")
	if err != nil {
		t.Fatal(err)
	}
	d, err := pocpolicy.Parse(raw)
	if err == nil {
		d, err = d.ForLaunch(mode, lifetime)
	}
	if err == nil && address != "" {
		d, err = d.WithBroker(address, 8443)
	}
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(d)
	return out
}

func (h *brokerHarness) brokerLaunchJob(launchID string, secrets []hostproto.LaunchSecret, policy []byte) hostproto.Job {
	spec := specWithSecret("oneshot", 30)
	if secrets == nil {
		secrets = []hostproto.LaunchSecret{testLaunchSecret()}
	}
	now := h.clock.now()
	payload, _ := json.Marshal(hostproto.LaunchPayload{Spec: spec, Policy: policy, ExpiresAtMS: now.Add(30 * time.Second).UnixMilli(),
		HeartbeatSeconds: 10, Mounts: []hostproto.LaunchMount{}, Secrets: secrets})
	return hostproto.Job{Version: hostproto.JobVersion, ID: nextJobID(), Type: hostproto.JobLaunch, TargetID: testTarget,
		LaunchID: launchID, SpecDigest: hostproto.SHA256Hex(spec), PolicyDigest: hostproto.SHA256Hex(policy),
		IssuedAtMS: now.UnixMilli(), DeadlineMS: now.Add(time.Hour).UnixMilli(), Payload: payload}
}

func TestHeartbeatPublishesASealKeySignedByTheHostKey(t *testing.T) {
	h := newHarness(t)
	h.cycle()
	beat := h.service.polls[0].Heartbeat
	rec, err := secretseal.ParseSignedKeyRecord(beat.SealKey)
	if err != nil {
		t.Fatal(err)
	}
	hostPub := h.daemon.Keys.Signing.Public().(ed25519.PublicKey)
	if _, err := secretseal.VerifyKeyRecord(rec, hostPub, secretseal.HostKeyFingerprint(hostPub), testTarget, h.clock.now()); err != nil {
		t.Fatalf("the published seal key does not verify: %v", err)
	}
	// The seal key is the enrollment X25519 key, so clients that saw the
	// enrollment encryption key see the same public key here.
	if rec.Record.PublicKey != hostproto.EncodeKey(h.daemon.Keys.Encryption.PublicKey().Bytes()) {
		t.Fatal("the seal key is not the host's enrollment key")
	}
	first := rec.Record
	h.clock.add(24 * time.Hour)
	h.cycle()
	again, _ := secretseal.ParseSignedKeyRecord(h.service.polls[len(h.service.polls)-1].Heartbeat.SealKey)
	if again.Record != first {
		t.Fatal("a seal key far from expiry was re-signed")
	}
	h.clock.add(sealKeyLifetime - sealKeyRenew)
	h.cycle()
	renewed, _ := secretseal.ParseSignedKeyRecord(h.service.polls[len(h.service.polls)-1].Heartbeat.SealKey)
	if renewed.Record.NotAfter == first.NotAfter || renewed.Record.KeyID != first.KeyID {
		t.Fatal("the seal key was not re-signed before expiry, or its key id changed")
	}
	for _, c := range h.daemon.capabilities(context.Background()) {
		if c == hostproto.CapabilityBrokeredSecrets {
			t.Fatal("a host without a broker reported brokered-secrets")
		}
	}
}

func TestSecretPutStoresTheValueAndRefusesReplayRollbackAndBadValues(t *testing.T) {
	h := newBrokerHarness(t)
	put, sealed := h.sealedPut("model-api", fakeValue, h.clock.now())
	h.service.send(t, put)
	h.cycle()
	r := h.service.results(put.ID)
	if len(r) != 1 || r[0].Status != hostproto.ResultSucceeded || r[0].SecretReceipt == nil {
		t.Fatalf("secret-put %+v", r)
	}
	receipt := secretseal.Receipt(*r[0].SecretReceipt)
	fp, err := sealed.VerifyReceipt(&receipt)
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	path := filepath.Join(h.root, testTarget, "model-api")
	got, err := os.ReadFile(path)
	info, _ := os.Stat(path)
	if err != nil || string(got) != fakeValue || info.Mode().Perm() != 0o600 {
		t.Fatalf("stored value: %v %v", err, info)
	}
	if dir, _ := os.Stat(filepath.Join(h.root, testTarget)); dir.Mode().Perm() != 0o700 {
		t.Fatal("the secret store is not 0700")
	}
	// The same job id is never run again; the same envelope in a new job is a replay.
	h.service.send(t, put)
	replay := put
	replay.ID = nextJobID()
	h.service.send(t, replay)
	h.cycle()
	if r := h.service.results(replay.ID); len(r) != 1 || r[0].Status != hostproto.ResultRejected || r[0].Reason != "replayed_or_rolled_back" {
		t.Fatalf("replay %+v", r)
	}
	// An older envelope (a rotated secret's previous value) is a rollback.
	old, _ := h.sealedPut("model-api", fakeValue+"-old", h.clock.now().Add(-time.Minute))
	h.service.send(t, old)
	h.cycle()
	if r := h.service.results(old.ID); len(r) != 1 || r[0].Reason != "replayed_or_rolled_back" {
		t.Fatalf("rollback %+v", r)
	}
	if got, _ := os.ReadFile(path); string(got) != fakeValue {
		t.Fatal("a refused envelope changed the stored value")
	}
	// A value the broker cannot inject is refused at secret-put time.
	bad, _ := h.sealedPut("other-api", "has spaces in it", h.clock.now())
	h.service.send(t, bad)
	h.cycle()
	if r := h.service.results(bad.ID); len(r) != 1 || r[0].Reason != "value_refused" {
		t.Fatalf("bad value %+v", r)
	}
	// Nothing the host wrote or sent holds the value.
	h.service.mu.Lock()
	events, _ := json.Marshal(h.service.events)
	h.service.mu.Unlock()
	if bytes.Contains(events, []byte(fakeValue)) || !bytes.Contains(events, []byte(fp)) {
		t.Fatal("events hold the value, or lack the fingerprint")
	}
	filepath.Walk(h.dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if raw, _ := os.ReadFile(p); bytes.Contains(raw, []byte(fakeValue)) {
				t.Errorf("%s holds the value", p)
			}
		}
		return nil
	})
	// Delete zeroes and removes; the envelope cannot set it again.
	del, _ := json.Marshal(hostproto.SecretDeletePayload{SecretID: strings.Repeat("1", 32), Name: "model-api"})
	now := h.clock.now()
	delJob := hostproto.Job{Version: hostproto.JobVersion, ID: nextJobID(), Type: hostproto.JobSecretDelete, TargetID: testTarget,
		IssuedAtMS: now.UnixMilli(), DeadlineMS: now.Add(time.Hour).UnixMilli(), Payload: del}
	h.service.send(t, delJob)
	h.cycle()
	if r := h.service.results(delJob.ID); len(r) != 1 || r[0].Reason != "deleted" {
		t.Fatalf("delete %+v", r)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the deleted value remains")
	}
	again := put
	again.ID = nextJobID()
	h.service.send(t, again)
	h.cycle()
	if r := h.service.results(again.ID); len(r) != 1 || r[0].Reason != "replayed_or_rolled_back" {
		t.Fatalf("a replay after delete %+v", r)
	}
}

func TestBrokerLaunchStartsTheBrokerFirstAndReportsItsEvidence(t *testing.T) {
	h := newBrokerHarness(t)
	h.store("model-api", fakeValue)
	h.daemon.caps = nil
	if !containsString(h.daemon.capabilities(context.Background()), hostproto.CapabilityBrokeredSecrets) {
		t.Fatal("a host with a broker does not report brokered-secrets")
	}
	var launcher launcherJob
	h.runtime.lines = func(job launcherJob, emit func(LauncherEvent), _ context.Context) {
		launcher = job
		if !h.broker.isRunning() {
			t.Error("the agent started before the broker was serving")
		}
		emit(LauncherEvent{Event: "state", State: "running"})
		zero := 0
		receipt := launcherReceiptFor(job, "stopped", "exited", true, &zero)
		h.runtime.mu.Lock()
		h.runtime.receipts[job.LaunchID] = receipt
		h.runtime.mu.Unlock()
		emit(LauncherEvent{Event: "receipt", Receipt: receipt})
	}
	job := h.brokerLaunchJob(testLaunch, nil, brokerPolicy(t, "oneshot", 30, brokerAddr))
	h.service.send(t, job)
	h.cycle()
	results := h.service.results(job.ID)
	if len(results) != 1 || results[0].Status != hostproto.ResultSucceeded || results[0].Receipt == nil {
		t.Fatalf("launch %+v", results)
	}
	receipt := results[0].Receipt
	if err := receipt.Check(job); err != nil {
		t.Fatal(err)
	}
	if receipt.BrokerCounts[brokerUpstream] != 3 || receipt.BrokerEvidence == nil || receipt.BrokerEvidence.Missing != "" ||
		receipt.BrokerEvidence.Listen != "tcp:"+brokerAddr+":8443" || receipt.BrokerEvidence.Denied["path_not_allowed"] != 1 || receipt.KernelVerified {
		t.Fatalf("broker evidence %+v counts %v", receipt.BrokerEvidence, receipt.BrokerCounts)
	}
	calls := h.broker.called()
	want := []string{"start " + testLaunch, "stop " + testLaunch + " 5s", "remove " + testLaunch}
	if strings.Join(filter(calls, "check"), ",") != strings.Join(want, ",") {
		t.Fatalf("broker calls %v", calls)
	}
	// The launcher job: the target joins only the launch network and the agent
	// gets the base URL, never the value or a path.
	if launcher.Broker == nil || launcher.Broker.Network != "agentgate-"+testLaunch+"-broker" || launcher.Broker.Address != brokerAddr ||
		launcher.Broker.TargetAddress != "172.30.7.3" || launcher.Broker.Env["MODEL_BASE_URL"] != "http://"+brokerAddr+":8443/model-api" {
		t.Fatalf("launcher broker %+v", launcher.Broker)
	}
	raw, _ := json.Marshal(launcher)
	if bytes.Contains(raw, []byte(fakeValue)) || bytes.Contains(raw, []byte(h.root)) || bytes.Contains(raw, []byte("/run/agentgate/secrets")) {
		t.Fatal("the launcher job names the secret or its file")
	}
	b := h.broker.launches[0]
	if b.Secrets[0].HostPath != filepath.Join(h.root, testTarget, "model-api") || b.Secrets[0].ContainerPath != "/run/agentgate/secrets/model-api" {
		t.Fatalf("secret mounts %+v", b.Secrets)
	}
	if bytes.Contains(b.Config, []byte(fakeValue)) {
		t.Fatal("the broker configuration holds the value")
	}
	if _, err := os.Stat(b.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the broker configuration outlived the launch")
	}
	state, _ := os.ReadFile(filepath.Join(b.Dir, brokerStateName))
	if !bytes.Contains(state, []byte(`"stopped":true`)) {
		t.Fatalf("broker state %s", state)
	}
	// A stop job afterwards returns a receipt with the same evidence.
	stop := h.boundJob(hostproto.JobStop, hostproto.StopPayload{Reason: "operator-stop", GraceSeconds: 1})
	stop.SpecDigest, stop.PolicyDigest = job.SpecDigest, job.PolicyDigest
	h.service.send(t, stop)
	h.cycle()
	if r := h.service.results(stop.ID); len(r) != 1 || r[0].Receipt == nil || r[0].Receipt.BrokerCounts[brokerUpstream] != 3 {
		t.Fatalf("stop %+v", r)
	}
}

func filter(values []string, drop string) []string {
	var out []string
	for _, v := range values {
		if v != drop {
			out = append(out, v)
		}
	}
	return out
}

func containsString(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

func TestBrokerFailuresAbortTheLaunchAndCleanUp(t *testing.T) {
	h := newBrokerHarness(t)
	h.store("model-api", fakeValue)
	// The broker cannot start: nothing runs, and what was made is removed.
	h.broker.startErr = errors.New("docker create failed")
	job := h.brokerLaunchJob(testLaunch, nil, brokerPolicy(t, "oneshot", 30, brokerAddr))
	h.service.send(t, job)
	h.cycle()
	if r := h.service.results(job.ID); len(r) != 1 || r[0].Status != hostproto.ResultFailed || r[0].Reason != "broker_start_failed" || r[0].EvidenceMissing != "not_started" {
		t.Fatalf("start failure %+v", r)
	}
	if h.runtime.called("run") != 0 || !containsString(h.broker.called(), "remove "+testLaunch) {
		t.Fatalf("calls %v %v", h.runtime.calls, h.broker.called())
	}
	// The broker starts but never reports running within the bound.
	saved := brokerStartWait
	brokerStartWait = 300 * time.Millisecond
	t.Cleanup(func() { brokerStartWait = saved })
	h.broker.startErr, h.broker.noStats = nil, true
	second := h.brokerLaunchJob(strings.Repeat("d", 32), nil, brokerPolicy(t, "oneshot", 30, "172.30.7.10"))
	h.service.send(t, second)
	h.cycle()
	if r := h.service.results(second.ID); len(r) != 1 || r[0].Reason != "broker_not_running" {
		t.Fatalf("not running %+v", r)
	}
	if h.runtime.called("run") != 0 {
		t.Fatal("the agent ran without a serving broker")
	}
	h.broker.noStats = false
	// Refusals before anything starts.
	cases := map[string]hostproto.Job{
		"secret_unavailable":    h.brokerLaunchJob(strings.Repeat("e", 32), []hostproto.LaunchSecret{func() hostproto.LaunchSecret { s := testLaunchSecret(); s.SecretID = strings.Repeat("2", 32); return s }()}, brokerPolicy(t, "oneshot", 30, "172.30.7.18")),
		"broker_config_refused": h.brokerLaunchJob(strings.Repeat("f", 32), nil, brokerPolicy(t, "oneshot", 30, "")),
	}
	outside := h.brokerLaunchJob(strings.Repeat("c", 32), nil, brokerPolicy(t, "oneshot", 30, "10.9.9.2"))
	cases["broker_config_refused "] = outside
	noSecrets := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	var p hostproto.LaunchPayload
	json.Unmarshal(noSecrets.Payload, &p)
	p.Policy = brokerPolicy(t, "oneshot", 30, "172.30.7.26")
	noSecrets.Payload, _ = json.Marshal(p)
	noSecrets.PolicyDigest = hostproto.SHA256Hex(p.Policy)
	noSecrets.LaunchID = strings.Repeat("b", 32)
	cases["policy_invalid"] = noSecrets
	for want, job := range cases {
		h.service.send(t, job)
		h.cycle()
		if r := h.service.results(job.ID); len(r) != 1 || r[0].Reason != strings.TrimSpace(want) || r[0].Status != hostproto.ResultRejected {
			t.Errorf("%s: %+v", want, r)
		}
	}
	if h.runtime.called("run") != 0 {
		t.Fatal("a refused launch ran")
	}
}

func TestACrashMidLaunchStopsAndRemovesTheBrokerAtRestart(t *testing.T) {
	h := newBrokerHarness(t)
	h.store("model-api", fakeValue)
	job := h.brokerLaunchJob(testLaunch, nil, brokerPolicy(t, "oneshot", 30, brokerAddr))
	var p hostproto.LaunchPayload
	json.Unmarshal(job.Payload, &p)
	prepared, code, err := prepareLaunch(job, p, []string{hostproto.CapabilityBrokeredSecrets}, h.clock.now(), testTarget, h.daemon.Config.Broker)
	if err != nil {
		t.Fatalf("%s: %v", code, err)
	}
	b, err := h.daemon.newBrokerLaunch(job, p, prepared.broker, prepared.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = h.daemon.Ledger.Begin(LedgerEntry{JobID: job.ID, Type: job.Type, LaunchID: job.LaunchID, SpecDigest: job.SpecDigest, PolicyDigest: job.PolicyDigest, DeadlineMS: job.DeadlineMS}); err != nil {
		t.Fatal(err)
	}
	_, _ = h.daemon.Ledger.Update(job.ID, JobRunning, nil)
	if code, err := h.daemon.startBroker(context.Background(), b); err != nil {
		t.Fatalf("%s: %v", code, err)
	}
	// The host agent dies here; the reconcile receipt for the launch exists.
	effective := launcherJob{LaunchID: job.LaunchID, JobID: job.ID, SpecDigest: job.SpecDigest, ProfilePolicyDigest: job.PolicyDigest, PolicyDigest: strings.Repeat("c", 64), LifetimeSeconds: 29}
	h.runtime.receipts[job.LaunchID] = launcherReceiptFor(effective, "failed", "host_restarted", true, nil)
	h.reopen()
	h.daemon.Recover(context.Background())
	calls := h.broker.called()
	if !containsString(calls, "stop "+testLaunch+" 5s") || !containsString(calls, "remove "+testLaunch) {
		t.Fatalf("the broker a crash left was not stopped and removed: %v", calls)
	}
	_ = h.daemon.FlushOutbox(context.Background())
	r := h.service.results(job.ID)
	if len(r) != 1 || r[0].Status != hostproto.ResultFailed || r[0].Reason != "host_restarted" || r[0].Receipt == nil ||
		r[0].Receipt.BrokerEvidence == nil || r[0].Receipt.BrokerCounts[brokerUpstream] != 3 {
		t.Fatalf("recovered result %+v", r)
	}
	// A broker whose removal failed is enforcement not released.
	h.broker.removeErr = errors.New("the broker network remains")
	outcome := h.daemon.teardownBroker(b, time.Now())
	receipt, status, _, err := convertReceipt(job, testTarget, launcherReceiptFor(effective, "stopped", "exited", true, nil), nil, &outcome)
	if err != nil || receipt.EnforcementReleased || status != hostproto.ResultFailed {
		t.Fatalf("a broker cleanup failure was reported clean: %v %+v", err, receipt)
	}
}

func TestBrokerEndpointMustBeTheDotTwoOfAPoolSubnet(t *testing.T) {
	pool := netip.MustParsePrefix(DefaultBrokerPool)
	subnet, gateway, addr, target, err := brokerEndpoint(&pocpolicy.Broker{Address: brokerAddr, Protocol: "tcp", Port: 8443}, pool)
	if err != nil || subnet.String() != "172.30.7.0/29" || gateway.String() != "172.30.7.1" || addr.String() != brokerAddr || target.String() != "172.30.7.3" {
		t.Fatalf("%v %v %v %v %v", subnet, gateway, addr, target, err)
	}
	for _, bad := range []string{"172.30.7.3", "172.30.7.1", "10.0.0.2", "172.30.0.2", "172.31.0.2", "192.168.1.2"} {
		if _, _, _, _, err := brokerEndpoint(&pocpolicy.Broker{Address: bad, Protocol: "tcp", Port: 8443}, pool); err == nil {
			t.Errorf("endpoint %s accepted", bad)
		}
	}
}

func TestDockerBrokerFollowsTheHardenedRecipeAndProvesRemoval(t *testing.T) {
	var argv [][]string
	inspected := map[string]bool{}
	d := &DockerBroker{Interfaces: func() ([]net.Addr, error) {
		_, n, _ := net.ParseCIDR("192.168.10.5/24")
		return []net.Addr{n}, nil
	}}
	d.Exec = func(_ context.Context, args []string) ([]byte, error) {
		argv = append(argv, args)
		joined := strings.Join(args[1:], " ")
		switch {
		case strings.HasPrefix(joined, "network ls"):
			return []byte("aaa\nbbb\n"), nil
		case strings.HasPrefix(joined, "network inspect --format {{range"):
			return []byte("172.17.0.0/16 172.18.0.0/16 \n"), nil
		case strings.HasPrefix(joined, "container inspect"), strings.HasPrefix(joined, "network inspect --format {{.Id}}"):
			inspected[args[len(args)-1]] = true
			return nil, errors.New("Error: No such object")
		}
		return nil, nil
	}
	subnet := netip.MustParsePrefix("172.30.7.0/29")
	b := &BrokerLaunch{LaunchID: testLaunch, Network: "agentgate-" + testLaunch + "-broker", Container: "agentgate-" + testLaunch + "-broker",
		Subnet: subnet, Gateway: netip.MustParseAddr("172.30.7.1"), Address: netip.MustParseAddr(brokerAddr), Port: 8443,
		ConfigPath: "/var/lib/agentgate-hostd/brokers/" + testLaunch + "/broker.json", ConfigSHA256: strings.Repeat("c", 64),
		StatsDir: "/var/lib/agentgate-hostd/brokers/" + testLaunch + "/stats", Image: brokerImage, Egress: "agentgate-egress",
		Secrets: []BrokerSecretFile{{Ref: "model-api", HostPath: "/var/lib/agentgate/secrets/" + testTarget + "/model-api", ContainerPath: "/run/agentgate/secrets/model-api"}}}
	if err := d.Start(context.Background(), b); err != nil {
		t.Fatal(err)
	}
	all := ""
	for _, a := range argv {
		all += strings.Join(a, " ") + "\n"
	}
	for _, want := range []string{
		"network create --internal --driver bridge --subnet 172.30.7.0/29 --gateway 172.30.7.1",
		"create --name agentgate-" + testLaunch + "-broker --network agentgate-" + testLaunch + "-broker --ip 172.30.7.2 --read-only --cap-drop ALL --cap-add SETUID --cap-add SETGID --security-opt no-new-privileges --ulimit core=0 --memory 256m --pids-limit 64 --cpus 1 --restart no --pull never",
		"type=bind,source=/var/lib/agentgate-hostd/brokers/" + testLaunch + "/broker.json,target=/etc/agentgate/broker.json,readonly",
		"type=bind,source=/var/lib/agentgate/secrets/" + testTarget + "/model-api,target=/run/agentgate/secrets/model-api,readonly",
		brokerImage + " run --config-sha256 " + strings.Repeat("c", 64) + " /etc/agentgate/broker.json",
		"network connect agentgate-egress agentgate-" + testLaunch + "-broker",
		"start agentgate-" + testLaunch + "-broker",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	for _, forbidden := range []string{"docker.sock", "--privileged", "--network host", "/var/lib/agentgate/secrets/" + testTarget + ":", "--env", " -e "} {
		if strings.Contains(all, forbidden) {
			t.Errorf("the broker recipe contains %q", forbidden)
		}
	}
	if err := d.Stop(context.Background(), b, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove(context.Background(), b); err != nil || !inspected[b.Container] {
		t.Fatalf("remove: %v", err)
	}
	if !strings.Contains(strings.Join(argv[len(argv)-5], " "), "stop --time 5") {
		t.Fatalf("stop argv %v", argv[len(argv)-5])
	}
	// A subnet that overlaps a Docker network or a host address is refused.
	b.Subnet = netip.MustParsePrefix("172.18.3.0/29")
	if err := d.Start(context.Background(), b); err == nil || !strings.Contains(err.Error(), "overlaps the Docker network") {
		t.Fatalf("an overlapping subnet started: %v", err)
	}
	b.Subnet = netip.MustParsePrefix("192.168.10.0/29")
	if err := d.Start(context.Background(), b); err == nil || !strings.Contains(err.Error(), "host address") {
		t.Fatalf("a subnet over a host address started: %v", err)
	}
	// A removal Docker cannot confirm is reported.
	d.Exec = func(_ context.Context, args []string) ([]byte, error) { return []byte("{}"), nil }
	if err := d.Remove(context.Background(), b); err == nil {
		t.Fatal("a broker whose container and network remain was reported removed")
	}
}

func TestHostEnvelopeCheckAgreesWithSecretseal(t *testing.T) {
	if hostproto.SealedFormat != secretseal.EnvelopeFormat || hostproto.SecretReceiptFormat != secretseal.ReceiptFormat ||
		hostproto.MaxSealedValueBytes != secretseal.MaxValueBytes || hostproto.MaxSecretBytes != broker.MaxSecretBytes {
		t.Fatal("hostproto's copy of the secretseal constants drifted")
	}
	h := newHarness(t)
	key, err := h.daemon.currentSealKey()
	if err != nil {
		t.Fatal(err)
	}
	rec := key.Published()
	hostPub := h.daemon.Keys.Signing.Public().(ed25519.PublicKey)
	pub, err := secretseal.VerifyKeyRecord(&rec, hostPub, secretseal.HostKeyFingerprint(hostPub), testTarget, h.clock.now())
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{8, 100, broker.MaxSecretBytes, secretseal.MaxValueBytes} {
		sealed, err := secretseal.SealAt(pub, testTarget, "model-api", bytes.Repeat([]byte("x"), size), h.clock.now())
		if err != nil {
			t.Fatal(err)
		}
		raw, err := hostproto.DecodeSealed(sealed.Envelope.Encode())
		if err != nil {
			t.Fatalf("size %d: hostproto refused a secretseal envelope: %v", size, err)
		}
		if env, err := secretseal.ParseEnvelope(raw); err != nil || env.Nonce != sealed.Envelope.Nonce {
			t.Fatal("the decoded bytes are not the envelope")
		}
	}
}

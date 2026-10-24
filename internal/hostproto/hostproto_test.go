// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Fixed inputs so every golden file is reproducible. Ed25519 signatures are
// deterministic, so the sealed envelopes are too.
var (
	fixedNow     = time.UnixMilli(1_790_000_000_000)
	serviceSeed  = bytes.Repeat([]byte{0x11}, 32)
	hostSeed     = bytes.Repeat([]byte{0x22}, 32)
	targetID     = "0123456789abcdef0123456789abcdef"
	launchID     = "fedcba9876543210fedcba9876543210"
	fixedNonce   = "AAECAwQFBgcICQoLDA0ODw"
	fixedPolicy  = []byte(`{"version":"agentgate.poc.v2"}`)
	fixedSpecRaw = []byte(`{"version":"agentgate.launch.v1","name":"repo-fixer","target":"local","mode":"session","lifetime_seconds":3600,"agent":{"image":"agentgate-coding@sha256:` + strings.Repeat("a", 64) + `","command":["sh"],"env":{},"workdir":"/var/lib/agentgate/workspace"},"access":{"profile":"python-dev","version":3},"mounts":[],"secrets":[],"approval":"auto"}`)
)

func serviceKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(serviceSeed) }
func hostKey() ed25519.PrivateKey    { return ed25519.NewKeyFromSeed(hostSeed) }

func raw(t *testing.T, v any) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func sealedFixture(t *testing.T) []byte {
	t.Helper()
	priv, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x33}, 32))
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := SealSecret(priv.PublicKey().Bytes(), []byte("synthetic-value"), SecretAAD(targetID, "model-api"), bytes.NewReader(bytes.Repeat([]byte{0x44}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func sampleJobs(t *testing.T) map[string]Job {
	t.Helper()
	base := func(id, kind string, payload any) Job {
		return Job{Version: JobVersion, ID: id, Type: kind, TargetID: targetID, IssuedAtMS: fixedNow.UnixMilli(), DeadlineMS: fixedNow.Add(2 * time.Hour).UnixMilli(), Payload: raw(t, payload)}
	}
	bound := func(j Job) Job {
		j.LaunchID, j.SpecDigest, j.PolicyDigest = launchID, SHA256Hex(fixedSpecRaw), SHA256Hex(fixedPolicy)
		return j
	}
	sealed := sealedFixture(t)
	apply := base("00000000000000000000000000000002", JobApplyProfile, ApplyProfilePayload{ProfileID: "abcdefabcdefabcdefabcdefabcdefab", ProfileVersion: 3, Policy: fixedPolicy})
	apply.PolicyDigest = SHA256Hex(fixedPolicy)
	jobs := map[string]Job{
		JobProvision:    base("00000000000000000000000000000001", JobProvision, ProvisionPayload{Images: []string{"agentgate-coding@sha256:" + strings.Repeat("a", 64)}, Reason: "operator-request"}),
		JobApplyProfile: apply,
		JobLaunch: bound(base("00000000000000000000000000000003", JobLaunch, LaunchPayload{Spec: fixedSpecRaw, Policy: fixedPolicy, ExpiresAtMS: fixedNow.Add(time.Hour).UnixMilli(), HeartbeatSeconds: 10,
			Mounts:  []LaunchMount{{Name: "repo", Source: "/srv/repos/app", Mode: "read-only", Path: MountRoot + "/repo"}},
			Secrets: []LaunchSecret{{Ref: "model-api", SecretID: "11111111111111111111111111111111", Env: "MODEL_API_BASE_URL", Upstreams: []string{"api.model.example"}, Header: "x-api-key"}}})),
		JobStop:          bound(base("00000000000000000000000000000004", JobStop, StopPayload{Reason: "operator-stop", GraceSeconds: 10})),
		JobCollect:       bound(base("00000000000000000000000000000005", JobCollect, CollectPayload{Reason: "receipt-missing"})),
		JobSecretPut:     base("00000000000000000000000000000006", JobSecretPut, SecretPutPayload{SecretID: "11111111111111111111111111111111", Name: "model-api", Upstreams: []string{"api.model.example"}, Header: "x-api-key", Ciphertext: EncodeSealed(sealed), CiphertextSHA256: SHA256Hex(sealed)}),
		JobSecretDelete:  base("00000000000000000000000000000007", JobSecretDelete, SecretDeletePayload{SecretID: "11111111111111111111111111111111", Name: "model-api"}),
		JobSnapshotMount: base("00000000000000000000000000000008", JobSnapshotMount, SnapshotMountPayload{Name: "repo", Source: "/srv/repos/app", MaxBytes: SnapshotMaxBytes, MaxEntries: SnapshotMaxEntries}),
	}
	return jobs
}

func golden(t *testing.T, name string, value any) {
	t.Helper()
	got, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	file := filepath.Join("testdata", name)
	if *update {
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/hostproto -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs from its golden file:\n%s", name, got)
	}
}

func TestJobGoldenFilesSignAndVerify(t *testing.T) {
	key := serviceKey()
	for _, kind := range JobTypes {
		job := sampleJobs(t)[kind]
		env, err := Seal(DomainJob, key, job)
		if err != nil {
			t.Fatal(err)
		}
		golden(t, "jobs/"+kind+".json", env)
		golden(t, "jobs/"+kind+".job.json", job)
		var opened Job
		if err := Open(env, DomainJob, key.Public().(ed25519.PublicKey), &opened); err != nil {
			t.Fatal(kind, err)
		}
		if _, err := opened.Check(targetID, fixedNow.Add(time.Minute)); err != nil {
			t.Fatal(kind, err)
		}
	}
	golden(t, "keys.json", map[string]string{"service_job_key": EncodeKey(key.Public().(ed25519.PublicKey)), "service_job_key_id": KeyID(key.Public().(ed25519.PublicKey)), "host_key": EncodeKey(hostKey().Public().(ed25519.PublicKey)), "host_key_id": KeyID(hostKey().Public().(ed25519.PublicKey))})
}

func TestHostRequestGoldenFiles(t *testing.T) {
	enc, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x33}, 32))
	enroll := EnrollRequest{Token: "agtenr_" + strings.Repeat("A", 43), PublicKey: EncodeKey(hostKey().Public().(ed25519.PublicKey)), EncryptionKey: EncodeKey(enc.PublicKey().Bytes()), Hostname: "host-1", Capabilities: []string{CapabilityDocker, CapabilityPOCPolicyV2}, AgentVersion: "0.1.0", Nonce: fixedNonce, TimestampMS: fixedNow.UnixMilli()}
	env, err := Seal(DomainEnroll, hostKey(), enroll)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "enroll.json", env)
	poll := PollRequest{Header: Header{HostID: targetID, Nonce: fixedNonce, TimestampMS: fixedNow.UnixMilli(), Sequence: 7}, Heartbeat: Heartbeat{Capabilities: []string{CapabilityDocker}, RunningLaunches: []string{launchID}, AgentVersion: "0.1.0"}, MaxJobs: 4}
	if err := poll.Check(fixedNow); err != nil {
		t.Fatal(err)
	}
	env, _ = Seal(DomainPoll, hostKey(), poll)
	golden(t, "poll.json", env)
	exit := 0
	jobs := sampleJobs(t)
	receipt := Receipt{Version: ReceiptVersion, LaunchID: launchID, TargetID: targetID, SpecDigest: jobs[JobLaunch].SpecDigest, PolicyDigest: jobs[JobLaunch].PolicyDigest, BPFObjects: map[string]string{"network.bpf.o": strings.Repeat("b", 64)}, GuardDigest: strings.Repeat("c", 64), Mounts: []MountIdentity{{Name: "repo", Mode: "read-only", Identity: "2049:131"}}, BrokerCounts: map[string]uint64{"api.model.example": 3}, StartedAtMS: fixedNow.UnixMilli(), EndedAtMS: fixedNow.Add(time.Minute).UnixMilli(), ExitCode: &exit, Reason: "exited", DomainEmpty: true, EnforcementReleased: true}
	if err := receipt.Check(jobs[JobLaunch]); err != nil {
		t.Fatal(err)
	}
	events := EventsRequest{Header: Header{HostID: targetID, Nonce: fixedNonce, TimestampMS: fixedNow.UnixMilli(), Sequence: 8}, JobID: jobs[JobLaunch].ID, Events: []Event{
		{Seq: 1, TimeMS: fixedNow.UnixMilli(), Kind: EventState, State: "running"},
		{Seq: 2, TimeMS: fixedNow.UnixMilli(), Kind: EventLog, Stream: "stdout", Message: "tests pass"},
		{Seq: 3, TimeMS: fixedNow.UnixMilli(), Kind: EventResult, Result: &JobResult{Status: ResultSucceeded, Reason: "exited", Receipt: &receipt}},
	}}
	if err := events.Check(fixedNow); err != nil {
		t.Fatal(err)
	}
	env, _ = Seal(DomainEvents, hostKey(), events)
	golden(t, "events.json", env)
}

func TestEnvelopeRejectsTamperDomainAndKey(t *testing.T) {
	key := serviceKey()
	job := sampleJobs(t)[JobStop]
	env, _ := Seal(DomainJob, key, job)
	pub := key.Public().(ed25519.PublicKey)
	tampered := env
	payload, _ := b64.DecodeString(env.Payload)
	payload = bytes.Replace(payload, []byte("operator-stop"), []byte("operator-stoq"), 1)
	tampered.Payload = b64.EncodeToString(payload)
	if _, err := Verify(tampered, DomainJob, pub); err == nil {
		t.Fatal("tampered payload verified")
	}
	cross := env
	cross.Domain = DomainPoll
	if _, err := Verify(cross, DomainPoll, pub); err == nil {
		t.Fatal("a job signature verified as a poll")
	}
	if _, err := Verify(env, DomainJob, hostKey().Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("verified with another key")
	}
	relabel := env
	relabel.KeyID = KeyID(hostKey().Public().(ed25519.PublicKey))
	if _, err := Verify(relabel, DomainJob, hostKey().Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("a relabelled envelope verified")
	}
	if _, err := Seal("agentgate.unknown", key, job); err == nil {
		t.Fatal("sealed an unknown domain")
	}
	big := make([]byte, MaxPayloadBytes+1)
	if _, err := SealBytes(DomainJob, key, big); err == nil {
		t.Fatal("sealed an oversize payload")
	}
}

func TestStrictDecodingRejectsDuplicatesUnknownAndTrailing(t *testing.T) {
	var job Job
	for _, bad := range []string{
		`{"version":"a","version":"b"}`,
		`{"version":"a","surprise":1}`,
		`{"version":"a"} {}`,
		strings.Repeat("[", 40) + strings.Repeat("]", 40),
	} {
		if err := DecodeStrict([]byte(bad), &job); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestJobCheckFailsClosed(t *testing.T) {
	now := fixedNow.Add(time.Minute)
	jobs := sampleJobs(t)
	mutate := map[string]func(Job) Job{
		"other target":    func(j Job) Job { j.TargetID = launchID; return j },
		"expired":         func(j Job) Job { j.DeadlineMS = fixedNow.UnixMilli(); return j },
		"future issue":    func(j Job) Job { j.IssuedAtMS = now.Add(time.Hour).UnixMilli(); return j },
		"unbounded":       func(j Job) Job { j.DeadlineMS = fixedNow.Add(48 * time.Hour).UnixMilli(); return j },
		"unknown type":    func(j Job) Job { j.Type = "exec"; return j },
		"policy digest":   func(j Job) Job { j.PolicyDigest = strings.Repeat("0", 64); return j },
		"spec digest":     func(j Job) Job { j.SpecDigest = strings.Repeat("0", 64); return j },
		"missing launch":  func(j Job) Job { j.LaunchID = ""; return j },
		"wrong version":   func(j Job) Job { j.Version = "agentgate.hostd.job.v0"; return j },
		"unknown payload": func(j Job) Job { j.Payload = json.RawMessage(`{"surprise":true}`); return j },
	}
	for name, fn := range mutate {
		if _, err := fn(jobs[JobLaunch]).Check(targetID, now); err == nil {
			t.Fatalf("launch job accepted with %s", name)
		}
	}
	put := jobs[JobSecretPut]
	var p SecretPutPayload
	json.Unmarshal(put.Payload, &p)
	p.CiphertextSHA256 = strings.Repeat("0", 64)
	put.Payload = raw(t, p)
	if _, err := put.Check(targetID, now); err == nil {
		t.Fatal("secret-put accepted a ciphertext that differs from its fingerprint")
	}
	unbound := jobs[JobSecretDelete]
	unbound.LaunchID = launchID
	if _, err := unbound.Check(targetID, now); err == nil {
		t.Fatal("an unbound job type accepted a launch binding")
	}
	snap := jobs[JobSnapshotMount]
	for _, source := range []string{"/etc", "/home/alice", "/srv/../etc", "/home/alice/.ssh/keys", "/var/lib/agentgate/workspace", "/srv/a b"} {
		var sp SnapshotMountPayload
		json.Unmarshal(jobs[JobSnapshotMount].Payload, &sp)
		sp.Source = source
		snap.Payload = raw(t, sp)
		if _, err := snap.Check(targetID, now); err == nil {
			t.Fatalf("snapshot accepted source %s", source)
		}
	}
	launch := jobs[JobLaunch]
	var lp LaunchPayload
	json.Unmarshal(launch.Payload, &lp)
	lp.ExpiresAtMS = fixedNow.Add(90 * time.Minute).UnixMilli()
	launch.Payload = raw(t, lp)
	if _, err := launch.Check(targetID, now); err == nil {
		t.Fatal("launch accepted an expiry beyond the spec lifetime")
	}
}

func TestEventBatchRules(t *testing.T) {
	h := Header{HostID: targetID, Nonce: fixedNonce, TimestampMS: fixedNow.UnixMilli(), Sequence: 1}
	ok := EventsRequest{Header: h, JobID: launchID, Events: []Event{{Seq: 1, TimeMS: 1, Kind: EventProgress, Message: "pulling"}}}
	if err := ok.Check(fixedNow); err != nil {
		t.Fatal(err)
	}
	bad := []EventsRequest{
		{Header: h, JobID: launchID, Events: []Event{{Seq: 2, TimeMS: 1, Kind: EventProgress}, {Seq: 4, TimeMS: 1, Kind: EventProgress}}},
		{Header: h, JobID: launchID, Events: []Event{{Seq: 1, TimeMS: 1, Kind: EventResult, Result: &JobResult{Status: ResultSucceeded, Reason: "ok"}}, {Seq: 2, TimeMS: 1, Kind: EventProgress}}},
		{Header: h, JobID: launchID, Events: []Event{{Seq: 1, TimeMS: 1, Kind: EventLog, Stream: "stdin"}}},
		{Header: h, JobID: launchID, Events: []Event{{Seq: 1, TimeMS: 1, Kind: EventProgress, Message: strings.Repeat("x", MaxEventMessage+1)}}},
		{Header: h, JobID: launchID, Events: []Event{{Seq: 1, TimeMS: 1, Kind: EventState, State: "stopped"}}},
		{Header: h, JobID: launchID, Events: []Event{}},
		{Header: Header{HostID: targetID, Nonce: fixedNonce, TimestampMS: fixedNow.Add(-2 * time.Minute).UnixMilli(), Sequence: 1}, JobID: launchID, Events: ok.Events},
		{Header: Header{HostID: targetID, Nonce: "short", TimestampMS: fixedNow.UnixMilli(), Sequence: 1}, JobID: launchID, Events: ok.Events},
		{Header: Header{HostID: targetID, Nonce: fixedNonce, TimestampMS: fixedNow.UnixMilli(), Sequence: 0}, JobID: launchID, Events: ok.Events},
	}
	for i, b := range bad {
		if err := b.Check(fixedNow); err == nil {
			t.Fatalf("bad batch %d accepted", i)
		}
	}
}

func TestReceiptRejectsKernelClaimAndForeignBinding(t *testing.T) {
	job := sampleJobs(t)[JobLaunch]
	r := Receipt{Version: ReceiptVersion, LaunchID: launchID, TargetID: targetID, SpecDigest: job.SpecDigest, PolicyDigest: job.PolicyDigest, BPFObjects: map[string]string{}, Mounts: []MountIdentity{}, BrokerCounts: map[string]uint64{}, Reason: "exited"}
	if err := r.Check(job); err != nil {
		t.Fatal(err)
	}
	claim := r
	claim.KernelVerified = true
	if claim.Check(job) == nil {
		t.Fatal("receipt claimed kernel verification")
	}
	foreign := r
	foreign.PolicyDigest = strings.Repeat("0", 64)
	if foreign.Check(job) == nil {
		t.Fatal("receipt for another policy accepted")
	}
	nilMaps := r
	nilMaps.BrokerCounts = nil
	if nilMaps.Check(job) == nil {
		t.Fatal("receipt with implicit maps accepted")
	}
}

func TestEnrollmentBindingAndSecretBox(t *testing.T) {
	token := "agtenr_" + strings.Repeat("B", 43)
	pub := serviceKey().Public().(ed25519.PublicKey)
	r := EnrollResponse{TargetID: targetID, TargetName: "local", HostKeyID: KeyID(hostKey().Public().(ed25519.PublicKey)), JobKey: EncodeKey(pub), JobKeyID: KeyID(pub), PollIntervalSeconds: 10}
	r.TokenMAC = EnrollResponseMAC(token, r)
	if err := VerifyEnrollResponse(token, r); err != nil {
		t.Fatal(err)
	}
	swapped := r
	other := hostKey().Public().(ed25519.PublicKey)
	swapped.JobKey, swapped.JobKeyID = EncodeKey(other), KeyID(other)
	if VerifyEnrollResponse(token, swapped) == nil {
		t.Fatal("a substituted job key passed the token binding")
	}
	priv, _ := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{0x33}, 32))
	sealed := sealedFixture(t)
	value, err := OpenSecret(priv, sealed, SecretAAD(targetID, "model-api"))
	if err != nil || string(value) != "synthetic-value" {
		t.Fatal("sealed secret did not round trip", err)
	}
	if _, err = OpenSecret(priv, sealed, SecretAAD(targetID, "other")); err == nil {
		t.Fatal("sealed secret opened under another name")
	}
	flipped := append([]byte{}, sealed...)
	flipped[len(flipped)-1] ^= 1
	if _, err = OpenSecret(priv, flipped, SecretAAD(targetID, "model-api")); err == nil {
		t.Fatal("tampered ciphertext opened")
	}
	if _, err = DecodeSealed(EncodeSealed(sealed[:10])); err == nil {
		t.Fatal("truncated ciphertext framed")
	}
}

func TestResyncRequestRules(t *testing.T) {
	r := ResyncRequest{HostID: targetID, Nonce: fixedNonce, TimestampMS: fixedNow.UnixMilli(), Reason: "counter-lost"}
	if err := r.Check(fixedNow); err != nil {
		t.Fatal(err)
	}
	env, _ := Seal(DomainResync, hostKey(), r)
	golden(t, "resync.json", env)
	stale := r
	stale.TimestampMS = fixedNow.Add(-2 * time.Minute).UnixMilli()
	if stale.Check(fixedNow) == nil {
		t.Fatal("stale resync accepted")
	}
	if _, err := Verify(env, DomainPoll, hostKey().Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("a resync verified as a poll")
	}
}

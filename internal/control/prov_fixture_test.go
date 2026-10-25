// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

type provFixture struct {
	t     *testing.T
	s     *Store
	a     *Auth
	srv   *Server
	http  *httptest.Server
	dir   string
	mu    sync.Mutex
	clock time.Time
}

func newProv(t *testing.T) *provFixture {
	t.Helper()
	f := &provFixture{t: t, dir: filepath.Join(t.TempDir(), "store"), clock: time.Now()}
	s, err := OpenStore(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	s.Now = f.now
	a, err := NewAuth(context.Background(), s, AuthConfig{AuthMode: "local", Instance: "synthetic-instance", PublicURL: "https://community.example.test", SessionLifetime: time.Hour,
		GroupRoles: map[string][]string{"admins": {"admin"}, "editors": {"editor"}, "launchers": {"launcher"}, "approvers": {"approver"}, "viewers": {"viewer"}}})
	if err != nil {
		t.Fatal(err)
	}
	web := t.TempDir()
	os.WriteFile(filepath.Join(web, "index.html"), []byte("<!doctype html>"), 0600)
	f.s, f.a = s, a
	f.srv = NewServer(s, a, t.TempDir(), web)
	f.http = httptest.NewServer(f.srv.Handler())
	t.Cleanup(func() { f.http.Close(); s.DB.Close() })
	return f
}

func (f *provFixture) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clock
}

func (f *provFixture) advance(d time.Duration) {
	f.mu.Lock()
	f.clock = f.clock.Add(d)
	f.mu.Unlock()
}

// human seeds a browser session for an OIDC-style subject whose groups map
// to roles, and returns the operation a request from it would carry.
func (f *provFixture) human(subject string, groups ...string) Operation {
	actor := Actor{Subject: subject, Kind: "human", Groups: groups, Roles: f.a.roles(groups)}
	sid := "session-" + subject
	if _, err := f.s.DB.Exec("INSERT OR REPLACE INTO sessions VALUES(?,?,?,?)", digest([]byte(sid)), jsonText(sessionActor{actor, f.s.LoginAuthority}), "csrf", time.Now().Add(48*time.Hour).Unix()); err != nil {
		f.t.Fatal(err)
	}
	return Operation{SessionHash: digest([]byte(sid)), Actor: actor, RequestID: newID(), BodyDigest: "fixture-" + newID()}
}

func (f *provFixture) admin() Operation    { return f.human("oidc:ada", "admins") }
func (f *provFixture) editor() Operation   { return f.human("oidc:eve", "editors") }
func (f *provFixture) launcher() Operation { return f.human("oidc:lin", "launchers") }
func (f *provFixture) approver() Operation { return f.human("oidc:app", "approvers") }
func (f *provFixture) viewer() Operation   { return f.human("oidc:vic", "viewers") }

// must panics on error; a panic fails the running test with its message.
func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func errCode(err error) string {
	_, code, _ := errorResult(err)
	if err == nil {
		return ""
	}
	return code
}

type fakeHost struct {
	f      *provFixture
	key    ed25519.PrivateKey
	enc    *ecdh.PrivateKey
	id     string
	seq    uint64
	jobKey ed25519.PublicKey
	caps   []string
	// sealKey is the host's signed seal key (HostKeyFromECDH of enc), sent
	// in every heartbeat like agentgate-hostd does.
	sealKey *secretseal.HostKey
}

func newHost(f *provFixture, caps ...string) *fakeHost {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	enc, _ := ecdh.X25519().GenerateKey(rand.Reader)
	if caps == nil {
		caps = []string{hostproto.CapabilityDocker, hostproto.CapabilityLiveMounts, hostproto.CapabilitySnapshots, hostproto.CapabilityBrokeredSecrets, hostproto.CapabilityPOCPolicyV2}
	}
	return &fakeHost{f: f, key: key, enc: enc, caps: caps}
}

func nonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *fakeHost) seal(domain string, v any) []byte {
	env, err := hostproto.Seal(domain, h.key, v)
	if err != nil {
		h.f.t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	return raw
}

func (h *fakeHost) enroll(token string) (hostproto.EnrollResponse, error) {
	req := hostproto.EnrollRequest{Token: token, PublicKey: hostproto.EncodeKey(h.key.Public().(ed25519.PublicKey)), EncryptionKey: hostproto.EncodeKey(h.enc.PublicKey().Bytes()), Hostname: "host-1", Capabilities: h.caps, AgentVersion: "0.1.0", Nonce: nonce(), TimestampMS: h.f.now().UnixMilli()}
	resp, err := h.f.s.EnrollHost(h.seal(hostproto.DomainEnroll, req), newID())
	if err == nil {
		if verr := hostproto.VerifyEnrollResponse(token, resp); verr != nil {
			h.f.t.Fatal(verr)
		}
		key, _ := hostproto.DecodeKey(resp.JobKey)
		h.jobKey, h.id = key, resp.TargetID
		if h.sealKey, err = secretseal.HostKeyFromECDH(resp.TargetID, h.enc, h.key, h.f.now(), 30*24*time.Hour); err != nil {
			h.f.t.Fatal(err)
		}
	}
	return resp, err
}

func (h *fakeHost) sealRecord() json.RawMessage {
	if h.sealKey == nil {
		return nil
	}
	raw, _ := json.Marshal(h.sealKey.Published())
	return raw
}

func (h *fakeHost) header() hostproto.Header {
	h.seq++
	return hostproto.Header{HostID: h.id, Nonce: nonce(), TimestampMS: h.f.now().UnixMilli(), Sequence: h.seq}
}

func (h *fakeHost) pollRaw(running ...string) []byte {
	if running == nil {
		running = []string{}
	}
	return h.seal(hostproto.DomainPoll, hostproto.PollRequest{Header: h.header(), Heartbeat: hostproto.Heartbeat{Capabilities: h.caps, RunningLaunches: running, AgentVersion: "0.1.0", SealKey: h.sealRecord()}, MaxJobs: 16})
}

// poll returns the verified, checked jobs.
func (h *fakeHost) poll(running ...string) []hostproto.Job {
	h.f.t.Helper()
	resp, err := h.f.s.HostPoll(h.pollRaw(running...), newID())
	if err != nil {
		h.f.t.Fatal(err)
	}
	out := []hostproto.Job{}
	for _, env := range resp.Jobs {
		var job hostproto.Job
		if err := hostproto.Open(env, hostproto.DomainJob, h.jobKey, &job); err != nil {
			h.f.t.Fatal(err)
		}
		if _, err := job.Check(h.id, h.f.now()); err != nil {
			h.f.t.Fatal(err)
		}
		out = append(out, job)
	}
	return out
}

func (h *fakeHost) eventsRaw(jobID string, events ...hostproto.Event) []byte {
	return h.seal(hostproto.DomainEvents, hostproto.EventsRequest{Header: h.header(), JobID: jobID, Events: events})
}

func (h *fakeHost) events(jobID string, events ...hostproto.Event) (hostproto.EventsResponse, error) {
	return h.f.s.HostEvents(jobID, h.eventsRaw(jobID, events...), newID())
}

func (h *fakeHost) receipt(job hostproto.Job, clean bool) *hostproto.Receipt {
	exit := 0
	return &hostproto.Receipt{Version: hostproto.ReceiptVersion, LaunchID: job.LaunchID, TargetID: job.TargetID, SpecDigest: job.SpecDigest, PolicyDigest: job.PolicyDigest,
		BPFObjects: map[string]string{"network.bpf.o": strings.Repeat("b", 64)}, Mounts: []hostproto.MountIdentity{}, BrokerCounts: map[string]uint64{},
		StartedAtMS: h.f.now().UnixMilli(), EndedAtMS: h.f.now().UnixMilli(), ExitCode: &exit, Reason: "exited", DomainEmpty: clean, EnforcementReleased: clean}
}

func ev(seq uint32, f *provFixture, kind string) hostproto.Event {
	return hostproto.Event{Seq: seq, TimeMS: f.now().UnixMilli(), Kind: kind}
}

// enrolledTarget creates and enrolls a target named local.
func (f *provFixture) enrolledTarget(caps ...string) (*fakeHost, Target) {
	f.t.Helper()
	value := must(f.s.CreateTarget(f.admin(), TargetInput{Name: "local", Reason: "Enroll the synthetic host"}))
	token := value.(map[string]any)["enrollment"].(map[string]any)["token"].(string)
	h := newHost(f, caps...)
	resp, err := h.enroll(token)
	if err != nil {
		f.t.Fatal(err)
	}
	must(f.s.ApproveTargetKey(f.admin(), resp.TargetID, KeyApprovalInput{HostKeyID: resp.HostKeyID, Reason: "The fingerprint matches the host console"}))
	return h, must(f.s.TargetDetail("local"))
}

// mountRoots lets launches on target mount or snapshot the given host folders.
func (f *provFixture) mountRoots(target string, roots ...string) {
	f.t.Helper()
	if roots == nil {
		roots = []string{}
	}
	must(f.s.SetTargetMountRoots(f.admin(), target, TargetMountRootsInput{MountRoots: roots, Reason: "Allow the synthetic host folders"}))
}

// profile creates a locked-down (no web) profile. Approval false needs an admin.
func (f *provFixture) profile(name string, requireApproval bool) Profile {
	return f.profileFrom(name, "locked-down", requireApproval)
}

func (f *provFixture) profileFrom(name, preset string, requireApproval bool) Profile {
	f.t.Helper()
	op := f.editor()
	if !requireApproval {
		op = f.admin()
	}
	value := must(f.s.CreateProfile(op, ProfileInput{Name: name, Preset: preset, RequireApproval: &requireApproval, Reason: "Create a synthetic profile"}))
	return value.(map[string]any)["profile"].(Profile)
}

func specMap(profile string) map[string]any {
	return map[string]any{
		"version": "agentgate.launch.v1", "name": "repo-fixer", "target": "local", "mode": "session", "lifetime_seconds": 3600,
		"agent":  map[string]any{"image": "agentgate-coding@sha256:" + strings.Repeat("a", 64), "command": []string{"agent", "--print", "fix the failing tests"}, "env": map[string]string{"EDITOR": "vi"}, "workdir": "/var/lib/agentgate/workspace"},
		"access": map[string]any{"profile": profile, "version": 1}, "mounts": []any{}, "secrets": []any{}, "approval": "auto",
	}
}

func specBytes(t *testing.T, m map[string]any) []byte {
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f *provFixture) launch(op Operation, m map[string]any) (Launch, LaunchPlan) {
	f.t.Helper()
	value := must(f.s.CreateLaunch(op, specBytes(f.t, m)))
	out := value.(map[string]any)
	return out["launch"].(Launch), out["plan"].(LaunchPlan)
}

func (f *provFixture) state(id string) Launch {
	f.t.Helper()
	return must(f.s.LaunchDetail(id))
}

// apiRequest calls the HTTP API with a bearer token.
func (f *provFixture) apiRequest(method, path, token string, body []byte) (*http.Response, map[string]any) {
	f.t.Helper()
	r, _ := http.NewRequest(method, f.http.URL+path, bytes.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := f.http.Client().Do(r)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func (f *provFixture) token(op Operation, roles ...string) string {
	f.t.Helper()
	value := must(f.s.CreateAPIToken(op, APITokenInput{Name: "cli", Roles: roles, ExpiresInSeconds: 86400, Reason: "Use the CLI"}))
	return value.(map[string]any)["token"].(string)
}

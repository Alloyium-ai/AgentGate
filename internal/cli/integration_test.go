// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/control"
	"alloyium.local/kernel-poc/internal/hostproto"
)

// The end-to-end test runs the real control service (internal/control) in
// process behind TLS and drives it only through the CLI, except for the host
// side, which a fake agentgate-hostd plays over the real host protocol.

const (
	adaPassword = "ada-password-0123456789"
	appPassword = "app-password-0123456789"
)

type realService struct {
	t     *testing.T
	srv   *httptest.Server
	store *control.Store
	ca    string
}

func startRealService(t *testing.T) *realService {
	t.Helper()
	store, err := control.OpenStore(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Skipf("the control service cannot be constructed in-process: %v", err)
	}
	t.Cleanup(func() { store.DB.Close() })
	var handler atomic.Value
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	auth, err := control.NewAuth(context.Background(), store, control.AuthConfig{AuthMode: "local", Instance: "cli-end-to-end", PublicURL: srv.URL, SessionLifetime: time.Hour})
	if err != nil {
		t.Skipf("the control service cannot be constructed in-process: %v", err)
	}
	store.LocalIdentity, store.CustomerPolicy = true, true
	web := t.TempDir()
	os.WriteFile(filepath.Join(web, "index.html"), []byte("<!doctype html>"), 0o600)
	app := control.NewServer(store, auth, t.TempDir(), web)
	handler.Store(app.Handler())
	if err = store.BootstrapAdmin("ada", "Ada", adaPassword); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	return &realService{t: t, srv: srv, store: store, ca: ca}
}

// fakeHostd plays agentgate-hostd over the real host protocol.
type fakeHostd struct {
	t      *testing.T
	url    string
	client *http.Client
	key    ed25519.PrivateKey
	box    *ecdh.PrivateKey
	id     string
	jobKey ed25519.PublicKey
	seq    uint64
}

func (h *fakeHostd) post(path string, domain string, v any, out any) {
	h.t.Helper()
	env, err := hostproto.Seal(domain, h.key, v)
	if err != nil {
		h.t.Fatal(err)
	}
	raw, _ := json.Marshal(env)
	resp, err := h.client.Post(h.url+path, "application/json", bytes.NewReader(raw))
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		h.t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
	}
	if out != nil {
		if err := json.Unmarshal(body, out); err != nil {
			h.t.Fatal(err)
		}
	}
}

func hostNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (h *fakeHostd) header() hostproto.Header {
	h.seq++
	return hostproto.Header{HostID: h.id, Nonce: hostNonce(), TimestampMS: time.Now().UnixMilli(), Sequence: h.seq}
}

func (h *fakeHostd) enroll(token string) hostproto.EnrollResponse {
	caps := []string{hostproto.CapabilityDocker, hostproto.CapabilityLiveMounts, hostproto.CapabilitySnapshots, hostproto.CapabilityBroker, hostproto.CapabilityPOCPolicyV2}
	req := hostproto.EnrollRequest{Token: token, PublicKey: hostproto.EncodeKey(h.key.Public().(ed25519.PublicKey)), EncryptionKey: hostproto.EncodeKey(h.box.PublicKey().Bytes()),
		Hostname: "host-1", Capabilities: caps, AgentVersion: "0.1.0", Nonce: hostNonce(), TimestampMS: time.Now().UnixMilli()}
	var resp hostproto.EnrollResponse
	h.post(hostproto.PathEnroll, hostproto.DomainEnroll, req, &resp)
	if err := hostproto.VerifyEnrollResponse(token, resp); err != nil {
		h.t.Fatal(err)
	}
	h.id = resp.TargetID
	h.jobKey, _ = hostproto.DecodeKey(resp.JobKey)
	return resp
}

func (h *fakeHostd) poll(running ...string) []hostproto.Job {
	if running == nil {
		running = []string{}
	}
	caps := []string{hostproto.CapabilityDocker, hostproto.CapabilityLiveMounts, hostproto.CapabilitySnapshots, hostproto.CapabilityBroker, hostproto.CapabilityPOCPolicyV2}
	var resp hostproto.PollResponse
	h.post(hostproto.PathPoll, hostproto.DomainPoll, hostproto.PollRequest{Header: h.header(), Heartbeat: hostproto.Heartbeat{Capabilities: caps, RunningLaunches: running, AgentVersion: "0.1.0"}, MaxJobs: 16}, &resp)
	jobs := []hostproto.Job{}
	for _, env := range resp.Jobs {
		var job hostproto.Job
		if err := hostproto.Open(env, hostproto.DomainJob, h.jobKey, &job); err != nil {
			h.t.Fatal(err)
		}
		if _, err := job.Check(h.id, time.Now()); err != nil {
			h.t.Fatal(err)
		}
		jobs = append(jobs, job)
	}
	return jobs
}

func (h *fakeHostd) events(job hostproto.Job, events ...hostproto.Event) {
	path := strings.Replace(hostproto.PathEvents, "{id}", job.ID, 1)
	h.post(path, hostproto.DomainEvents, hostproto.EventsRequest{Header: h.header(), JobID: job.ID, Events: events}, nil)
}

func (h *fakeHostd) receipt(job hostproto.Job) *hostproto.Receipt {
	exit := 0
	now := time.Now().UnixMilli()
	return &hostproto.Receipt{Version: hostproto.ReceiptVersion, LaunchID: job.LaunchID, TargetID: job.TargetID, SpecDigest: job.SpecDigest, PolicyDigest: job.PolicyDigest,
		BPFObjects: map[string]string{"network.bpf.o": strings.Repeat("b", 64)}, Mounts: []hostproto.MountIdentity{}, BrokerCounts: map[string]uint64{},
		StartedAtMS: now - 1000, EndedAtMS: now, ExitCode: &exit, Reason: "stopped", DomainEmpty: true, EnforcementReleased: true}
}

func TestEndToEndAgainstTheRealService(t *testing.T) {
	svc := startRealService(t)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "agentgate")
	run := func(stdin string, args ...string) result {
		t.Helper()
		var out, errOut bytes.Buffer
		a := &App{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errOut, Getenv: func(k string) string {
			return map[string]string{"AGENTGATE_CONFIG_DIR": dir, "HOME": dir}[k]
		}, Term: &fakeTerm{}, Hostname: func() (string, error) { return "e2e", nil }, Version: "test"}
		code := a.Main(ctx, args)
		return result{out.String(), errOut.String(), code}
	}
	must := func(r result, code int, contains ...string) result {
		t.Helper()
		if r.code != code {
			t.Fatalf("want exit %d: %v", code, r)
		}
		for _, c := range contains {
			if !strings.Contains(r.stdout+r.stderr, c) {
				t.Fatalf("output lacks %q: %v", c, r)
			}
		}
		return r
	}

	// Sign in with a password; the CLI mints and saves an admin token.
	must(run(adaPassword+"\n", "login", svc.srv.URL, "--ca-file", svc.ca, "--username", "ada", "--password-stdin"), 0, "Signed in to "+svc.srv.URL+" as local:ada")
	if r := must(run("", "whoami", "--json"), 0); !strings.Contains(r.stdout, `"local:ada"`) || strings.Contains(r.stdout, "agt_") {
		t.Fatalf("%v", r)
	}

	// A second human with the approver role, created by the administrator.
	c, _ := (&env{app: &App{}, g: &globals{}, p: &printer{out: io.Discard, err: io.Discard}}).clientFor(mustURL(t, svc.srv.URL), "", transportOptions{caFile: svc.ca})
	s, err := signIn(ctx, c, "ada", []byte(adaPassword))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.call(ctx, "POST", apiPrefix+"/users", map[string]any{"username": "app", "name": "App Rover", "roles": []string{"approver"}, "enabled": true, "password": appPassword, "parent_revision": 0, "reason": "An approver for the test"}, nil); err != nil {
		t.Fatal(err)
	}
	s.close(ctx)
	// The approver mints a token with a password sign-in and saves it with login --token-stdin.
	tok := must(run(appPassword+"\n", "token", "create", "--username", "app", "--password-stdin", "--role", "approver", "--expires", "2h", "-q"), 0)
	token := strings.TrimSpace(tok.stdout)
	if !apiTokenFormat.MatchString(token) {
		t.Fatalf("token create -q prints the token: %q", tok.stdout)
	}
	must(run(token+"\n", "login", svc.srv.URL, "--ca-file", svc.ca, "--token-stdin", "--save-as", "approver"), 0, "Saved to context \"approver\"")
	must(run("", "context", "use", "default"), 0)
	if r := must(run("", "context", "ls"), 0); strings.Contains(r.stdout, token) {
		t.Fatal("context ls printed a token")
	}

	// Add a target; a fake host agent enrolls with the one-time token.
	tokenFile := filepath.Join(t.TempDir(), "enroll-token")
	must(run("", "target", "add", "local", "--token-file", tokenFile), 0, "agentgate-hostd install --service-url "+svc.srv.URL+" --token-file "+tokenFile)
	raw, _ := os.ReadFile(tokenFile)
	host := &fakeHostd{t: t, url: svc.srv.URL, client: svc.srv.Client()}
	host.key = func() ed25519.PrivateKey { _, k, _ := ed25519.GenerateKey(rand.Reader); return k }()
	host.box, _ = ecdh.X25519().GenerateKey(rand.Reader)
	enrolled := host.enroll(strings.TrimSpace(string(raw)))
	must(run("", "target", "status", "local"), 0, "awaiting_key_approval", enrolled.HostKeyID)
	must(run("", "target", "approve-key", "local", "--host-key-id", "ed25519:"+strings.Repeat("0", 32)), ExitTrust, "fingerprint_mismatch")
	must(run("", "target", "approve-key", "local", "--host-key-id", enrolled.HostKeyID, "--reason", "Matches the host console"), 0, "Pinned it on this machine")
	host.poll()
	must(run("", "target", "ls"), 0, "pinned, matches")

	// A profile, a grant preview and a grant.
	must(run("", "profile", "new", "dev", "--preset", access.PresetNames()[0], "--description", "End to end"), 0, "Created profile dev (version 1")
	before := must(run("", "profile", "versions", "dev", "-q"), 0).stdout
	must(run("", "grant", "dev", "read", "/srv/data", "--dry-run"), 0, "+ filesystem.read_only[] /srv/data", "nothing was stored")
	if after := must(run("", "profile", "versions", "dev", "-q"), 0).stdout; after != before {
		t.Fatal("grant --dry-run stored a version")
	}
	must(run("", "grant", "dev", "read", "/srv/data", "--reason", "Read the data set"), 0, "version 1 -> 2", "+ filesystem.read_only[] /srv/data")
	must(run("", "grant", "dev", "mount", "repo"), 0, "version 2 -> 3")
	must(run("", "grant", "dev", "read", "/srv/data"), 0, "no change")

	// The plan: exactly what the agent may do, without creating anything.
	image := "agentgate-coding@sha256:" + strings.Repeat("c", 64)
	launchArgs := func(flags ...string) []string {
		args := append([]string{"launch", "--name", "repo-fixer", "--mode", "session", "--lifetime", "1h", "--profile", "dev", "--image", image, "--mount", "/srv/repos/app:repo:ro"}, flags...)
		return append(args, "--", "agent", "--print", "fix the tests")
	}
	must(run("", launchArgs("--dry-run")...), 0, "dry run: nothing was created", "/srv/data", "mount repo", "live host folder repo", "kernel_verified is false")
	var dry PlanResult
	if err := json.Unmarshal([]byte(must(run("", launchArgs("--dry-run", "--json")...), 0).stdout), &dry); err != nil || dry.Plan.PolicyDigest == "" || dry.Plan.Approval != "required" || len(dry.Plan.Mounts) != 1 {
		t.Fatalf("dry run JSON: %+v %v", dry.Plan, err)
	}
	if r := must(run("", "ps", "-q"), 0); strings.TrimSpace(r.stdout) != "" {
		t.Fatalf("a dry run created a launch: %v", r)
	}

	// Create the launch; it waits for a different human.
	created := must(run("", launchArgs("-q")...), ExitApprovalPending)
	id := strings.TrimSpace(created.stdout)
	if len(id) != 32 {
		t.Fatalf("launch id %q", id)
	}
	must(run("", "approve", id, "--reason", "My own launch", "--yes"), ExitForbidden, "never lets the requester decide")
	must(run("", "--context", "approver", "approve", id, "--reason", "Reviewed the plan", "--yes"), 0, "approved: queued")
	must(run("", "show", id), 0, "queued", "decided by", "local:app")

	// The host runs it; the CLI follows it over the real event stream.
	jobs := host.poll()
	if len(jobs) != 1 || jobs[0].Type != hostproto.JobLaunch || jobs[0].LaunchID != id {
		t.Fatalf("jobs %+v", jobs)
	}
	running := hostproto.Event{Seq: 1, TimeMS: time.Now().UnixMilli(), Kind: hostproto.EventState, State: "running"}
	host.events(jobs[0], running, hostproto.Event{Seq: 2, TimeMS: time.Now().UnixMilli(), Kind: hostproto.EventLog, Stream: "stdout", Message: "agent started"})
	must(run("", "ps", "--active"), 0, id, "running")
	must(run("", "logs", id), 0, "agent started")
	must(run("", "stop", id), ExitUsage, "--yes")
	done := make(chan result, 1)
	go func() { done <- run("", "stop", id, "--yes", "--wait", "--wait-timeout", "30s") }()
	var stop []hostproto.Job
	for deadline := time.Now().Add(20 * time.Second); len(stop) == 0 && time.Now().Before(deadline); {
		time.Sleep(50 * time.Millisecond)
		stop = host.poll(id)
	}
	if len(stop) != 1 || stop[0].Type != hostproto.JobStop {
		t.Fatalf("no stop job: %+v", stop)
	}
	host.events(stop[0], hostproto.Event{Seq: 1, TimeMS: time.Now().UnixMilli(), Kind: hostproto.EventResult, Result: &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stopped", Receipt: host.receipt(stop[0])}})
	select {
	case r := <-done:
		must(r, 0, "is stopping; waiting", "stopping -> stopped", "ended stopped")
	case <-time.After(30 * time.Second):
		t.Fatal("stop --wait did not see the launch end")
	}
	must(run("", "events", id), 0, "approval_pending -> approved", "stopping -> stopped")
	must(run("", "show", id), 0, "Evidence receipt", "domain empty          true")

	// The audit trail names both humans and the digests.
	audit := must(run("", "audit", "--launch", id, "--json"), 0)
	for _, want := range []string{"launch.approved", "local:app", "launch.state.changed", dry.Plan.PolicyDigest} {
		if !strings.Contains(audit.stdout, want) {
			t.Errorf("audit lacks %q", want)
		}
	}

	// A secret: the service does not publish the target's signed seal key
	// yet, so secret set refuses before it reads the value.
	secretArgs := []string{"secret", "set", "model-api", "--upstream", "api.model.example", "--allow-profile", "dev", "--allow-launcher", "local:ada"}
	r := run("sk-e2e-value-0123456789\n", secretArgs...)
	if r.code == ExitUsage && strings.Contains(r.stderr, "forwards nothing by default") {
		// A service that enforces broker rules needs them first.
		r = run("sk-e2e-value-0123456789\n", append(secretArgs, "--rule", "POST:/v1/messages")...)
	}
	must(r, ExitTrust, "seal_key_unpublished")
	must(run("", "secret", "ls", "-q"), 0)
	must(run("", "target", "retire", "local"), ExitUsage, "--yes")
}

func mustURL(t *testing.T, raw string) *url.URL {
	u, err := serverURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

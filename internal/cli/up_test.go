// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"alloyium.local/kernel-poc/internal/control"
)

const (
	upPassword = "correct-horse-battery-staple"
	hostdPath  = "/opt/test/agentgate-hostd"
	dockerPath = "/usr/bin/docker"
)

// fakeRunner records delegated commands and answers them from a script.
type fakeRunner struct {
	mu      sync.Mutex
	calls   []Cmd
	respond func(c Cmd) Result
}

func (f *fakeRunner) LookPath(name string) (string, error) {
	switch name {
	case "docker":
		return dockerPath, nil
	case "agentgate-hostd":
		return hostdPath, nil
	}
	return "", errors.New("not found")
}

func (f *fakeRunner) Run(ctx context.Context, c Cmd) (Result, error) {
	f.mu.Lock()
	c.Stdin = append([]byte(nil), c.Stdin...)
	f.calls = append(f.calls, c)
	f.mu.Unlock()
	return f.respond(c), nil
}

func (f *fakeRunner) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{}
	for _, c := range f.calls {
		out = append(out, filepath.Base(c.Path)+" "+strings.Join(c.Args, " "))
	}
	return out
}

type upWorld struct {
	h          *harness
	runner     *fakeRunner
	compose    string
	target     control.Target
	targetGets atomic.Int32
	approveAt  int32
	hostKey    string
	installed  bool
	tokenSeen  string
	tokenMode  os.FileMode
	adminStdin []byte
}

func newUpWorld(t *testing.T) *upWorld {
	h := newHarness(t)
	w := &upWorld{h: h, hostKey: hostKey, approveAt: 2}
	w.compose = filepath.Join(t.TempDir(), "compose.yaml")
	os.WriteFile(w.compose, []byte("services: {}\n"), 0o600)
	h.euid = 0
	h.env["AGENTGATE_IMAGE"] = "agentgate@sha256:" + strings.Repeat("1", 64)
	h.api.health = 503
	h.api.enableSessions("ada", upPassword, []string{"admin"})
	h.api.handle("POST /api/v1/api-tokens", func(rw http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		if r.Header.Get("X-CSRF-Token") != "session-csrf" || r.Header.Get("Authorization") != "" {
			apiError(rw, 403, "session_required", "Create API tokens from a signed-in browser session.")
			return
		}
		var in control.APITokenInput
		json.Unmarshal(body, &in)
		writeJSON(rw, 200, map[string]any{"id": "tokup", "name": in.Name, "roles": in.Roles, "expires_at": "2026-10-31T12:00:00Z", "token": testToken})
	})
	h.api.reply("GET /api/v1/launch-spec-schema", 200, map[string]any{})
	w.target = sampleTarget("pending")
	h.api.handle("GET /api/v1/targets/{id}", func(rw http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		switch {
		case w.target.ID == "":
			apiError(rw, 404, "not_found", "The target does not exist.")
			return
		case w.installed && w.target.State == "pending":
			w.target.State, w.target.HostKeyID = "awaiting_key_approval", w.hostKey
		case w.target.State == "awaiting_key_approval" && w.targetGets.Add(1) >= w.approveAt:
			w.target.State, w.target.Online = "active", true
		}
		writeJSON(rw, 200, w.target)
	})
	h.api.handle("POST /api/v1/targets", func(rw http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		w.target = sampleTarget("pending")
		w.target.HostKeyID = ""
		writeJSON(rw, 200, map[string]any{"target": w.target, "enrollment": map[string]any{"token": "agtenr_" + strings.Repeat("Q", 43), "expires_at": "2026-10-24T12:15:00Z", "single_use": true, "enroll_path": "/api/v1/hostd/enroll"}})
	})
	h.api.handle("POST /api/v1/targets/{id}/approve-key", func(rw http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		var in control.KeyApprovalInput
		json.Unmarshal(body, &in)
		if in.HostKeyID != w.target.HostKeyID {
			apiError(rw, 409, "fingerprint_mismatch", "The fingerprint differs.")
			return
		}
		w.target.State, w.target.Online = "active", true
		writeJSON(rw, 200, w.target)
	})
	w.target.ID = ""
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: h.api.srv.Certificate().Raw})
	w.runner = &fakeRunner{respond: func(c Cmd) Result {
		args := strings.Join(c.Args, " ")
		switch {
		case strings.HasSuffix(args, "control job-key"):
			return Result{Exit: 1, Stderr: []byte("open config: no such file")}
		case strings.Contains(args, "control init"):
			return Result{Stdout: []byte(`{"result":"initialized"}`)}
		case strings.HasSuffix(args, "control first-admin"):
			w.adminStdin = append([]byte(nil), c.Stdin...)
			return Result{Stdout: []byte("FIRST_ADMIN_READY\n")}
		case strings.HasSuffix(args, " up -d"):
			h.api.mu.Lock()
			h.api.health = 200
			h.api.mu.Unlock()
			return Result{}
		case strings.Contains(args, "exec -T tls cat"):
			return Result{Stdout: pemCA}
		case strings.HasPrefix(args, "status"):
			if !w.installed {
				return Result{Exit: 1, Stderr: []byte("state directory missing")}
			}
			raw, _ := json.Marshal(map[string]any{"enrolled": true, "target_id": w.target.ID, "host_key_id": w.hostKey, "unfinished_jobs": []string{}})
			return Result{Stdout: raw}
		case strings.HasPrefix(args, "install"):
			for i, a := range c.Args {
				if a == "--token-file" {
					raw, _ := os.ReadFile(c.Args[i+1])
					info, _ := os.Stat(c.Args[i+1])
					w.tokenSeen, w.tokenMode = strings.TrimSpace(string(raw)), info.Mode().Perm()
				}
			}
			w.installed = true
			return Result{Stdout: []byte("enrolled as target " + w.target.ID + " (local)\nhost key " + hostKey + "\nagentgate-hostd is running\n")}
		}
		return Result{Exit: 99, Stderr: []byte("unexpected command " + args)}
	}}
	h.runner = w.runner
	return w
}

func (w *upWorld) up(stdin string, extra ...string) result {
	args := append([]string{"up", "--service-url", w.h.api.URL(), "--compose-file", w.compose, "--admin-user", "ada", "--password-stdin", "--hostd", hostdPath, "--wait-timeout", "5s"}, extra...)
	return w.h.run(stdin, args...)
}

func TestUpBringsAFreshMachineOnline(t *testing.T) {
	w := newUpWorld(t)
	r := w.up(upPassword + "\n")
	if r.code != 0 {
		t.Fatalf("%v", r)
	}
	want := []string{
		"docker compose -f " + w.compose + " run --rm -T control job-key",
		"docker compose -f " + w.compose + " run --rm -T control init /bootstrap/settings.json",
		"docker compose -f " + w.compose + " run --rm -T control first-admin",
		"docker compose -f " + w.compose + " up -d",
		"docker compose -f " + w.compose + " exec -T tls cat " + caddyRootPath,
		"agentgate-hostd status --state-dir " + defaultHostdState,
	}
	got := w.runner.commands()
	for i, cmd := range want {
		if i >= len(got) || got[i] != cmd {
			t.Fatalf("command %d: want %q\ngot %q", i, cmd, got)
		}
	}
	install := got[len(want)]
	if !strings.HasPrefix(install, "agentgate-hostd install --service-url "+w.h.api.URL()+" --token-file ") || !strings.Contains(install, "--ca-file") || !strings.Contains(install, "--runtime docker-host") {
		t.Fatalf("install: %q", install)
	}
	if w.tokenSeen != "agtenr_"+strings.Repeat("Q", 43) || w.tokenMode != 0o600 {
		t.Fatalf("the enrollment token reaches hostd only through a 0600 file: %q %v", w.tokenSeen, w.tokenMode)
	}
	for _, c := range w.runner.calls {
		for _, a := range c.Args {
			if strings.Contains(a, upPassword) || strings.Contains(a, "agtenr_") {
				t.Fatalf("a credential is on a command line: %v", c.Args)
			}
			if strings.Contains(a, "--token-file") {
				continue
			}
		}
	}
	var admin map[string]string
	if err := json.Unmarshal(w.adminStdin, &admin); err != nil || admin["password"] != upPassword || admin["username"] != "ada" {
		t.Fatalf("first-admin reads the password from stdin: %s %v", w.adminStdin, err)
	}
	if strings.Contains(r.stdout+r.stderr, upPassword) || strings.Contains(r.stdout+r.stderr, testToken) || strings.Contains(r.stdout, "agtenr_QQ") {
		t.Fatalf("a credential was printed: %v", r)
	}
	for _, step := range []string{"[1/7] service", "created the first administrator ada", "trusting the local TLS front's CA", "signed in as local:ada", "created target local", "this machine's host key: " + hostKey, "approved by an administrator", "pinned host key", "is online", "UI:      " + w.h.api.URL()} {
		if !strings.Contains(r.stdout, step) {
			t.Errorf("output lacks %q:\n%s", step, r.stdout)
		}
	}
	st := store{dir: w.h.dir, euid: os.Geteuid()}
	cfg, _ := st.load()
	if c := cfg.Contexts["default"]; c == nil || c.Token != testToken || !containsString(c.Roles, "admin") || c.CAFile == "" {
		t.Fatalf("saved context %+v", c)
	}
	k, _ := st.loadTrust()
	if pin := k.find(w.h.api.URL(), w.target.ID); pin == nil || pin.HostKeyID != hostKey || pin.Source != "up" {
		t.Fatalf("pin %+v", pin)
	}
	if len(w.h.api.requestsTo("POST /api/v1/targets/{id}/approve-key")) != 0 {
		t.Fatal("up approved the key without --approve")
	}

	// Running it again finds every step done and changes nothing.
	before := len(w.runner.calls)
	r = w.up("")
	if r.code != 0 {
		t.Fatalf("re-run: %v", r)
	}
	again := w.runner.commands()[before:]
	if len(again) != 1 || !strings.HasPrefix(again[0], "agentgate-hostd status") {
		t.Fatalf("a re-run delegated more than a status read: %q", again)
	}
	for _, s := range []string{"running at", "using the saved admin token", "target local is active", "installed and enrolled", "approved (host key"} {
		if !strings.Contains(r.stdout, s) {
			t.Errorf("re-run output lacks %q:\n%s", s, r.stdout)
		}
	}
	if n := len(w.h.api.requestsTo("POST /api/v1/targets")); n != 1 {
		t.Fatalf("the re-run created another target (%d)", n)
	}
}

func TestUpRefusesRootStepsWithoutRoot(t *testing.T) {
	w := newUpWorld(t)
	w.h.euid = 1000
	w.h.api.health = 200
	r := w.up(upPassword + "\n")
	if r.code != ExitForbidden || !strings.Contains(r.stderr, "needs root") || !strings.Contains(r.stderr, "sudo agentgate up") || !strings.Contains(r.stderr, "agentgate-hostd install") {
		t.Fatalf("%v", r)
	}
	if len(w.h.api.requestsTo("POST /api/v1/targets")) != 0 {
		t.Fatal("a one-time token was minted before the root check")
	}
	if !strings.Contains(r.stderr, "run agentgate up again") {
		t.Fatalf("no retry instruction: %v", r)
	}
	// --skip-host needs no root and stops before the host steps.
	if r = w.up(upPassword+"\n", "--skip-host"); r.code != 0 || !strings.Contains(r.stdout, "skipped (--skip-host)") {
		t.Fatalf("%v", r)
	}
}

func TestUpApprovalRules(t *testing.T) {
	w := newUpWorld(t)
	if r := w.up(upPassword+"\n", "--approve", "--yes"); r.code != ExitUsage || !strings.Contains(r.stderr, "never takes --yes") {
		t.Fatalf("%v", r)
	}
	w.approveAt = 1 << 30
	r := w.up(upPassword+"\n", "--approve")
	if r.code != ExitUsage || !strings.Contains(r.stderr, "interactive terminal") {
		t.Fatalf("--approve without a terminal: %v", r)
	}
	if len(w.h.api.requestsTo("POST /api/v1/targets/{id}/approve-key")) != 0 {
		t.Fatal("approved without confirmation")
	}
	w.h.term.tty = [3]bool{true, true, true}
	if r = w.up("wrongchr\n", "--approve"); r.code != ExitUsage || !strings.Contains(r.stderr, "not approved") {
		t.Fatalf("a wrong confirmation: %v", r)
	}
	if r = w.up(hostKey[len(hostKey)-8:]+"\n", "--approve"); r.code != 0 || !strings.Contains(r.stdout, "approved host key "+hostKey) {
		t.Fatalf("%v", r)
	}
	if n := len(w.h.api.requestsTo("POST /api/v1/targets/{id}/approve-key")); n != 1 {
		t.Fatalf("approve-key calls %d", n)
	}
}

func TestUpStopsOnAFingerprintMismatch(t *testing.T) {
	w := newUpWorld(t)
	w.approveAt = 1 << 30
	w.h.api.handle("GET /api/v1/targets/{id}", func(rw http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		if w.target.ID == "" {
			apiError(rw, 404, "not_found", "The target does not exist.")
			return
		}
		if w.installed {
			w.target.State, w.target.HostKeyID = "awaiting_key_approval", "ed25519:"+strings.Repeat("6", 32)
		}
		writeJSON(rw, 200, w.target)
	})
	r := w.up(upPassword + "\n")
	if r.code != ExitTrust || !strings.Contains(r.stderr, "Do not approve") {
		t.Fatalf("%v", r)
	}
	st := store{dir: w.h.dir, euid: os.Geteuid()}
	k, _ := st.loadTrust()
	if len(k.Targets) != 0 {
		t.Fatal("a mismatching key was pinned")
	}
}

func TestUpWaitsForApprovalThenTimesOut(t *testing.T) {
	w := newUpWorld(t)
	w.approveAt = 1 << 30
	r := w.up(upPassword+"\n", "--wait-timeout", "50ms")
	if r.code != ExitApprovalPending || !strings.Contains(r.stdout, "agentgate target approve-key local --host-key-id") || !strings.Contains(r.stderr, "run agentgate up again") {
		t.Fatalf("%v", r)
	}
}

func TestUpApprovesOnlyTheIDTheHostAgentPrinted(t *testing.T) {
	w := newUpWorld(t)
	w.approveAt = 1 << 30
	if r := w.up(upPassword+"\n", "--wait-timeout", "50ms"); r.code != ExitApprovalPending {
		t.Fatalf("first run: %v", r)
	}
	w.h.term.tty = [3]bool{true, true, true}
	if r := w.up(hostKey+"\n", "--approve"); r.code != 0 || !strings.Contains(r.stdout, "agentgate-hostd on this machine printed host key id "+hostKey) || !strings.Contains(r.stdout, "approved host key "+hostKey) {
		t.Fatalf("the whole id: %v", r)
	}
	var in control.KeyApprovalInput
	mustDecode(t, w.h.api.requestsTo("POST /api/v1/targets/{id}/approve-key")[0].Body, &in)
	if in.HostKeyID != hostKey {
		t.Fatalf("approved %q", in.HostKeyID)
	}
	// A host agent that prints no host key id gives nothing to confirm.
	w = newUpWorld(t)
	w.approveAt = 1 << 30
	respond := w.runner.respond
	w.runner.respond = func(c Cmd) Result {
		if strings.HasPrefix(strings.Join(c.Args, " "), "status") && w.installed {
			return Result{Stdout: []byte(`{"enrolled":true,"target_id":"` + w.target.ID + `","unfinished_jobs":[]}`)}
		}
		return respond(c)
	}
	if r := w.up(upPassword+"\n", "--wait-timeout", "50ms"); r.code != ExitApprovalPending {
		t.Fatalf("first run: %v", r)
	}
	w.h.term.tty = [3]bool{true, true, true}
	if r := w.up(hostKey[len(hostKey)-8:]+"\n", "--approve"); r.code != ExitTrust || !strings.Contains(r.stderr, "did not report its fingerprint") {
		t.Fatalf("no printed id: %v", r)
	}
	if len(w.h.api.requestsTo("POST /api/v1/targets/{id}/approve-key")) != 0 {
		t.Fatal("approved a key the host agent never printed")
	}
}

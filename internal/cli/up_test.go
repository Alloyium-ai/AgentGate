// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
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
	// What this machine's fake agentgate-hostd was installed with.
	hostBroker map[string]any
	hostRoots  []string
	secretRoot string
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
			status := map[string]any{"enrolled": true, "target_id": w.target.ID, "host_key_id": w.hostKey, "unfinished_jobs": []string{},
				"mount_roots": w.hostRoots, "secret_root": firstNonEmpty(w.secretRoot, "/var/lib/agentgate/secrets"), "broker": w.hostBroker}
			raw, _ := json.Marshal(status)
			return Result{Stdout: raw}
		case strings.HasPrefix(args, "mount-roots"):
			w.hostRoots = nil
			for i, a := range c.Args {
				if a == "--root" {
					w.hostRoots = append(w.hostRoots, c.Args[i+1])
				}
			}
			return Result{Stdout: []byte(`{"mount_roots":[]}`)}
		case strings.HasPrefix(args, "install"):
			value := func(name string) string {
				for i, a := range c.Args {
					if a == name && i+1 < len(c.Args) {
						return c.Args[i+1]
					}
				}
				return ""
			}
			for i, a := range c.Args {
				if a == "--token-file" {
					raw, _ := os.ReadFile(c.Args[i+1])
					info, _ := os.Stat(c.Args[i+1])
					w.tokenSeen, w.tokenMode = strings.TrimSpace(string(raw)), info.Mode().Perm()
				}
				if a == "--mount-root" {
					w.hostRoots = append(w.hostRoots, c.Args[i+1])
				}
			}
			if image := value("--broker-image"); image != "" {
				uid, gid := 10002, 10002
				fmt.Sscan(firstNonEmpty(value("--broker-uid"), "10002"), &uid)
				fmt.Sscan(firstNonEmpty(value("--broker-gid"), "10002"), &gid)
				w.hostBroker = map[string]any{"image": image, "uid": uid, "gid": gid, "egress_network": firstNonEmpty(value("--broker-egress-network"), "agentgate-egress"), "pool": value("--broker-pool")}
			}
			w.secretRoot = firstNonEmpty(value("--secret-root"), w.secretRoot)
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

const brokerImage = "registry.example/agentgate-broker@sha256:" + "2222222222222222222222222222222222222222222222222222222222222222"

// up passes the broker and mount root settings to agentgate-hostd install,
// reconfigures an enrolled host that lacks them, and says why brokered
// secrets are unavailable.
func TestUpForwardsBrokerAndMountRootSettings(t *testing.T) {
	w := newUpWorld(t)
	flags := []string{"--broker-image", brokerImage, "--broker-egress-network", "egress-1", "--broker-uid", "10005", "--broker-gid", "10006",
		"--broker-pool", "172.31.0.0/16", "--secret-root", "/srv/agentgate-secrets", "--mount-root", "/srv/repos", "--mount-root", "/srv/data"}
	r := w.up(upPassword+"\n", flags...)
	if r.code != 0 {
		t.Fatalf("%v", r)
	}
	var install string
	for _, c := range w.runner.commands() {
		if strings.HasPrefix(c, "agentgate-hostd install") {
			install = c
		}
	}
	for _, want := range []string{"--token-file ", "--broker-image " + brokerImage, "--broker-egress-network egress-1", "--broker-uid 10005", "--broker-gid 10006",
		"--broker-pool 172.31.0.0/16", "--secret-root /srv/agentgate-secrets", "--mount-root /srv/repos --mount-root /srv/data"} {
		if !strings.Contains(install, want) {
			t.Fatalf("install %q lacks %q", install, want)
		}
	}
	// The sample target does not report brokered-secrets: up says why, from the local status.
	if !strings.Contains(r.stderr, "brokered secrets are not available on local") || !strings.Contains(r.stderr, "configured with broker image "+brokerImage) ||
		!strings.Contains(r.stderr, "docker network inspect egress-1") {
		t.Fatalf("no broker report: %s", r.stderr)
	}
	// The same settings again: nothing is reinstalled.
	before := len(w.runner.calls)
	if r = w.up("", flags...); r.code != 0 {
		t.Fatalf("re-run %v", r)
	}
	if again := w.runner.commands()[before:]; len(again) != 1 || !strings.HasPrefix(again[0], "agentgate-hostd status") {
		t.Fatalf("matching settings reinstalled: %q", again)
	}
	// Another broker image: install again, without a token (the host stays enrolled).
	other := strings.Replace(brokerImage, "2222", "3333", 1)
	before = len(w.runner.calls)
	if r = w.up("", "--broker-image", other); r.code != 0 {
		t.Fatalf("%v", r)
	}
	again := w.runner.commands()[before:]
	if len(again) != 3 || !strings.HasPrefix(again[1], "agentgate-hostd install --service-url") || strings.Contains(again[1], "--token-file") ||
		!strings.Contains(again[1], "--broker-image "+other) || len(w.h.api.requestsTo("POST /api/v1/targets/{id}/enrollment")) != 0 {
		t.Fatalf("reconfiguration %q", again)
	}
	// Other mount roots only: agentgate-hostd mount-roots, no reinstall.
	before = len(w.runner.calls)
	if r = w.up("", "--mount-root", "/opt/projects"); r.code != 0 {
		t.Fatalf("%v", r)
	}
	again = w.runner.commands()[before:]
	if len(again) != 3 || again[1] != "agentgate-hostd mount-roots --state-dir "+defaultHostdState+" --root /opt/projects" || strings.Join(w.hostRoots, ",") != "/opt/projects" {
		t.Fatalf("mount roots %q %v", again, w.hostRoots)
	}
	// A target that reports brokered-secrets: nothing to warn about.
	w.target.Capabilities = append(w.target.Capabilities, "brokered-secrets")
	if r = w.up(""); r.code != 0 || strings.Contains(r.stderr, "brokered secrets are not available") {
		t.Fatalf("%v", r)
	}
	// --json carries the same report.
	w.target.Capabilities = []string{"docker"}
	r = w.up("", "--json")
	var out map[string]any
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &out) != nil {
		t.Fatalf("%v", r)
	}
	if b, _ := out["brokered_secrets"].(map[string]any); b == nil || b["available"] != false || !strings.Contains(fmt.Sprint(b["fix"]), "docker image inspect "+other) {
		t.Fatalf("json report %v", out["brokered_secrets"])
	}
}

func TestUpWithoutABrokerSaysHowToAddOne(t *testing.T) {
	w := newUpWorld(t)
	r := w.up(upPassword + "\n")
	if r.code != 0 || !strings.Contains(r.stderr, "installed without a credential broker (--broker-image)") || !strings.Contains(r.stderr, "agentgate up --broker-image") {
		t.Fatalf("%v", r)
	}
}

func TestUpRefusesUnsafeHostSettings(t *testing.T) {
	w := newUpWorld(t)
	cases := map[string][]string{
		"uid without image":       {"--broker-uid", "10003"},
		"network without image":   {"--broker-egress-network", "egress"},
		"pool without image":      {"--broker-pool", "172.31.0.0/16"},
		"mutable image":           {"--broker-image", "agentgate-broker:latest"},
		"root uid":                {"--broker-image", brokerImage, "--broker-uid", "-1"},
		"host network":            {"--broker-image", brokerImage, "--broker-egress-network", "host"},
		"odd network":             {"--broker-image", brokerImage, "--broker-egress-network", "a b"},
		"public pool":             {"--broker-image", brokerImage, "--broker-pool", "8.8.0.0/16"},
		"uncanonical pool":        {"--broker-image", brokerImage, "--broker-pool", "172.31.1.0/16"},
		"relative secret root":    {"--secret-root", "srv/secrets"},
		"dot dot secret root":     {"--secret-root", "/srv/../etc"},
		"protected mount root":    {"--mount-root", "/etc"},
		"home mount root":         {"--mount-root", "/home/alice"},
		"dot dot mount root":      {"--mount-root", "/srv/data/../../etc"},
		"appliance with a broker": {"--runtime", "appliance", "--broker-image", brokerImage},
		"skip host with settings": {"--skip-host", "--mount-root", "/srv/data"},
	}
	for name, extra := range cases {
		if r := w.up(upPassword+"\n", extra...); r.code != ExitUsage {
			t.Errorf("%s: %v", name, r)
		}
	}
	if len(w.runner.calls) != 0 {
		t.Fatalf("a refused command line ran %q", w.runner.commands())
	}
}

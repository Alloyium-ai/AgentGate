// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/control"
	"alloyium.local/kernel-poc/internal/hostproto"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

func golden(t *testing.T, h *harness, name, got string) {
	t.Helper()
	got = strings.ReplaceAll(got, h.api.URL(), "https://SERVER")
	path := filepath.Join("testdata", name+".golden")
	if *update {
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/cli -run %s -update to create it)", err, t.Name())
	}
	if string(want) != got {
		t.Errorf("%s differs from the golden file (rerun with -update if intended)\n--- want\n%s\n--- got\n%s", path, want, got)
	}
}

const (
	hostKey  = "ed25519:0123456789abcdef0123456789abcdef"
	digestA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	imageRef = "agentgate-coding@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func sampleTarget(state string) control.Target {
	return control.Target{ID: "6f1d2c3b4a5968778695a4b3c2d1e0f1", Name: "local", State: state, Capabilities: []string{"docker", "live-mounts", "snapshot-mounts", "broker", "pocpolicy-v2"},
		Hostname: "build-1", AgentVersion: "0.1.0", HostKeyID: hostKey, EncryptionKey: hostproto.EncodeKey(make([]byte, 32)), JobKeyID: "ed25519:" + strings.Repeat("e", 32),
		LastSeen: "2026-10-24T11:59:50Z", Online: state == "active", HeartbeatSeconds: 10, Created: "2026-10-24T10:00:00Z", CreatedBy: "local:ada", Updated: "2026-10-24T10:05:00Z", Revision: 3}
}

func samplePlan() control.LaunchPlan {
	return control.LaunchPlan{SpecDigest: digestA, PolicyDigest: digestB, Target: map[string]string{"id": "6f1d2c3b4a5968778695a4b3c2d1e0f1", "name": "local"},
		Profile: map[string]any{"id": "p1", "name": "python-dev", "version": 3, "version_id": "v3", "digest": strings.Repeat("f", 64)},
		Mode:    "session", LifetimeSeconds: 3600, ExpiresAt: "2026-10-24T13:00:00Z", ExpiryRule: "the lifetime starts when the launch is queued; the host and the kernel policy end it at expires_at",
		Image: imageRef, Command: []string{"claude", "--print", "fix the failing tests"}, Workdir: "/var/lib/agentgate/workspace",
		Approval: "required", ApprovalReasons: []string{"brokered secrets anthropic", "live host folder repo", "the profile requires approval"},
		Permissions: control.Permissions{Network: "deny", IPv6: "deny", Web: []string{"https"}, DNS: []string{"1.1.1.1"}, Taskboard: "10.0.0.1:8443",
			ReadOnly: []string{"/usr", "/lib", "/var/lib/agentgate/mounts/repo"}, Writable: []string{"/var/lib/agentgate/workspace", "/tmp"}, Execute: []string{"/usr/bin", "/usr/local/bin"},
			Deny: []string{"/etc/shadow"}, Devices: []string{"/dev/null", "/dev/urandom"}, Signals: []string{"SIGTERM"}},
		Mounts:  []hostproto.LaunchMount{{Name: "repo", Source: "/srv/repos/app", Mode: "read-only", Path: "/var/lib/agentgate/mounts/repo"}},
		Secrets: []control.PlanSecret{{Ref: "anthropic", SecretID: "s1", Env: "ANTHROPIC_BASE_URL", Upstreams: []string{"api.anthropic.com"}, Header: "x-api-key"}},
		Notices: []string{"kernel_verified is false: this enforcement has not been verified on a BPF LSM kernel"}}
}

func sampleLaunch(state string) control.Launch {
	plan, _ := json.Marshal(samplePlan())
	return control.Launch{ID: "9a8b7c6d5e4f30211203f4e5d6c7b8a9", Name: "repo-fixer", SpecDigest: digestA, TargetID: "6f1d2c3b4a5968778695a4b3c2d1e0f1", ProfileVersionID: "v3", PolicyDigest: digestB,
		Mode: "session", LifetimeSeconds: 3600, ApprovalRequired: true, State: state, RequestedBy: "local:lin", Created: "2026-10-24T11:30:00Z", Updated: "2026-10-24T11:31:00Z", Revision: 2, Plan: plan}
}

func TestTargetCommands(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	h.api.reply("GET /api/v1/targets", 200, map[string]any{"items": []control.Target{sampleTarget("active")}})
	r := h.run("", "target", "ls")
	if r.code != 0 {
		t.Fatalf("%v", r)
	}
	golden(t, h, "target-ls", r.stdout)
	if r = h.run("", "target", "ls", "--json"); r.code != 0 || !strings.Contains(r.stdout, `"host_key_id": "`+hostKey+`"`) {
		t.Fatalf("--json keeps the API field names: %v", r)
	}

	h.api.reply("POST /api/v1/targets", 200, map[string]any{"target": sampleTarget("pending"), "enrollment": map[string]any{"token": "agtenr_" + strings.Repeat("Z", 43), "expires_at": "2026-10-24T12:15:00Z", "single_use": true, "enroll_path": "/api/v1/hostd/enroll"}})
	tokenFile := filepath.Join(t.TempDir(), "token")
	r = h.run("", "target", "add", "local", "--token-file", tokenFile)
	raw, err := os.ReadFile(tokenFile)
	info, _ := os.Stat(tokenFile)
	if r.code != 0 || err != nil || !strings.HasPrefix(string(raw), "agtenr_") || info.Mode().Perm() != 0o600 || strings.Contains(r.stdout, "agtenr_ZZ") {
		t.Fatalf("token file: %v", r)
	}
	if r = h.run("", "target", "add", "local", "--token-file", tokenFile); r.code != ExitUsage {
		t.Fatalf("an existing token file must not be overwritten: %v", r)
	}
	var body map[string]string
	mustDecode(t, h.api.requestsTo("POST /api/v1/targets")[0].Body, &body)
	if body["name"] != "local" || len(body["reason"]) < 3 {
		t.Fatalf("%v", body)
	}

	pending := sampleTarget("awaiting_key_approval")
	h.api.reply("GET /api/v1/targets/{id}", 200, pending)
	r = h.run("", "target", "status", "local")
	if r.code != 0 || !strings.Contains(r.stdout, "approve-key local") {
		t.Fatalf("%v", r)
	}
	if r = h.run("", "target", "approve-key", "local"); r.code != ExitUsage {
		t.Fatalf("approval without a fingerprint in a script: %v", r)
	}
	h.api.handle("POST /api/v1/targets/{id}/approve-key", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		var in control.KeyApprovalInput
		json.Unmarshal(body, &in)
		if in.HostKeyID != hostKey {
			apiError(w, 409, "fingerprint_mismatch", "The fingerprint differs from the key the host presented. Do not approve; issue a new token.")
			return
		}
		writeJSON(w, 200, sampleTarget("active"))
	})
	r = h.run("", "target", "approve-key", "local", "--host-key-id", "ed25519:"+strings.Repeat("9", 32))
	if r.code != ExitTrust || !strings.Contains(r.stderr, "Do not approve") {
		t.Fatalf("a mismatching fingerprint is a trust failure: %v", r)
	}
	r = h.run("", "target", "approve-key", "local", "--host-key-id", hostKey)
	if r.code != 0 || !strings.Contains(r.stdout, "Pinned") {
		t.Fatalf("%v", r)
	}
	st := store{dir: h.dir, euid: os.Geteuid()}
	k, _ := st.loadTrust()
	if pin := k.find(h.api.URL(), pending.ID); pin == nil || pin.HostKeyID != hostKey || pin.Source != "approve-key" {
		t.Fatalf("pin %+v", pin)
	}

	h.api.reply("GET /api/v1/targets/{id}", 200, sampleTarget("active"))
	r = h.run("", "target", "pin", "local", "--host-key-id", "ed25519:"+strings.Repeat("1", 32))
	if r.code != ExitTrust {
		t.Fatalf("pinning a key the service does not report: %v", r)
	}
	h.api.reply("DELETE /api/v1/targets/{id}", 200, sampleTarget("retired"))
	if r = h.run("", "target", "retire", "local"); r.code != ExitUsage || !strings.Contains(r.stderr, "--yes") {
		t.Fatalf("retire without a terminal needs --yes: %v", r)
	}
	if len(h.api.requestsTo("DELETE /api/v1/targets/{id}")) != 0 {
		t.Fatal("retire ran without confirmation")
	}
	if r = h.run("", "target", "retire", "local", "--yes"); r.code != 0 || !strings.Contains(r.stdout, "retired") {
		t.Fatalf("%v", r)
	}
	h.term.tty = [3]bool{true, true, true}
	if r = h.run("n\n", "target", "retire", "local"); r.code != ExitUsage || !strings.Contains(r.stderr, "Not confirmed") {
		t.Fatalf("a no answer: %v", r)
	}
	if r = h.run("y\n", "target", "retire", "local"); r.code != 0 {
		t.Fatalf("a yes answer: %v", r)
	}
}

func profileFixtures(h *harness) access.Edit {
	doc, _ := access.NewFromPreset("locked-down")
	raw, _ := json.Marshal(doc)
	v := control.ProfileVersion{ID: "v1", ProfileID: "p1", Number: 1, Document: raw, Digest: doc.Digest(), Edits: json.RawMessage(`[{"action":"preset","values":["locked-down"]}]`), Actor: "local:eve", Reason: "Create", Created: "2026-10-24T10:00:00Z"}
	h.api.reply("GET /api/v1/profiles", 200, map[string]any{"items": []control.Profile{{ID: "p1", Name: "dev", Description: "Python work", RequireApproval: true, CreatedBy: "local:eve", LatestVersion: 1, Revision: 1}}})
	h.api.reply("GET /api/v1/profiles/{id}", 200, control.Profile{ID: "p1", Name: "dev", Description: "Python work", RequireApproval: true, CreatedBy: "local:eve", LatestVersion: 1, Revision: 1})
	h.api.reply("GET /api/v1/profiles/{id}/versions/{n}", 200, v)
	h.api.reply("GET /api/v1/profiles/{id}/versions", 200, map[string]any{"items": []control.ProfileVersion{v}})
	edit := access.Edit{Action: "read", Values: []string{"/srv/data"}}
	res, _ := access.Apply(doc, edit)
	after, _ := json.Marshal(res.Document)
	h.api.handle("POST /api/v1/profiles/{id}/versions/{n}/grants", func(w http.ResponseWriter, r *http.Request, body []byte, p []string) {
		if p[0] != "p1" || p[1] != "1" {
			apiError(w, 409, "stale_parent", "Grants apply to the latest profile version only.")
			return
		}
		var in control.GrantInput
		json.Unmarshal(body, &in)
		answer := map[string]any{"changed": true, "from_version": 1, "from_digest": doc.Digest(), "digest": res.Document.Digest(),
			"changes": []control.PolicyChange{{Area: "Files", Field: "read", Change: "added", After: "/srv/data"}}, "messages": []string{res.Message}, "notices": res.Notices}
		if in.DryRun {
			answer["dry_run"], answer["document"] = true, json.RawMessage(after)
		} else {
			answer["version"] = control.ProfileVersion{ID: "v2", ProfileID: "p1", Number: 2, ParentID: "v1", Document: after, Digest: res.Document.Digest(), Actor: "local:eve", Reason: "x", Created: "2026-10-24T12:00:00Z"}
		}
		writeJSON(w, 200, answer)
	})
	return edit
}

func TestProfileAndGrantCommands(t *testing.T) {
	h := newHarness(t)
	h.login("local:eve", "editor")
	profileFixtures(h)
	r := h.run("", "profile", "ls")
	if r.code != 0 {
		t.Fatalf("%v", r)
	}
	golden(t, h, "profile-ls", r.stdout)
	if r = h.run("", "profile", "show", "dev"); r.code != 0 || !strings.Contains(r.stdout, "filesystem.") {
		t.Fatalf("%v", r)
	}
	if r = h.run("", "profile", "versions", "dev"); r.code != 0 || !strings.Contains(r.stdout, "preset locked-down") {
		t.Fatalf("%v", r)
	}
	r = h.run("", "grant", "dev", "read", "/srv/data", "--dry-run")
	if r.code != 0 || !strings.Contains(r.stdout, "+ filesystem.read_only[] /srv/data") || !strings.Contains(r.stdout, "nothing was stored") || !strings.Contains(r.stdout, "version 1 -> 2 would store") {
		t.Fatalf("dry run: %v", r)
	}
	var dry control.GrantInput
	if reqs := h.api.requestsTo("POST /api/v1/profiles/{id}/versions/{n}/grants"); len(reqs) != 1 {
		t.Fatal("--dry-run did not ask the service")
	} else if mustDecode(t, reqs[0].Body, &dry); !dry.DryRun || dry.Edits[0].Values[0] != "/srv/data" {
		t.Fatalf("the preview request %+v", dry)
	}
	r = h.run("", "grant", "dev", "read", "/srv/data", "--dry-run", "--json")
	var preview grantOutcome
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &preview) != nil || !preview.DryRun || preview.Version != nil || len(preview.Changes) != 1 || preview.Digest == "" {
		t.Fatalf("dry run --json: %v", r)
	}
	r = h.run("", "grant", "dev", "read", "/srv/data", "--reason", "Read the data set")
	if r.code != 0 || !strings.Contains(r.stdout, "version 1 -> 2") || !strings.Contains(r.stdout, "+ filesystem.read_only[] /srv/data") {
		t.Fatalf("grant: %v", r)
	}
	var in control.GrantInput
	mustDecode(t, h.api.requestsTo("POST /api/v1/profiles/{id}/versions/{n}/grants")[2].Body, &in)
	if len(in.Edits) != 1 || in.Edits[0].Action != "read" || in.Edits[0].Values[0] != "/srv/data" || in.Reason != "Read the data set" {
		t.Fatalf("%+v", in)
	}
	r = h.run("", "grant", "dev", "read", "/srv/data", "--json")
	var out grantOutcome
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &out) != nil || !out.Changed || out.Version.Number != 2 || len(out.Added) == 0 {
		t.Fatalf("grant --json: %v", r)
	}
	for _, bad := range [][]string{{"grant", "dev", "read"}, {"grant", "dev", "fly", "x"}, {"grant", "dev", "dns", "1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1"}, {"grant", "dev", "mount", "repo", "--mode", "exec"}} {
		if r = h.run("", bad...); r.code != ExitUsage {
			t.Errorf("%v: %v", bad, r)
		}
	}
	edits := map[string]access.Edit{}
	for _, c := range [][]string{{"web", "https", "quic"}, {"web", "deny", "quic"}, {"dns", "1.1.1.1"}, {"signal", "TERM"}, {"anon-exec"}, {"mount", "repo", "--mode", "read-write"}, {"unmount", "repo"}, {"revoke", "web", "quic"}, {"preset", "python-dev"}, {"device", "/dev/urandom"}, {"revoke", "device", "/dev/tty"}} {
		args := append([]string{"grant", "dev"}, c...)
		before := len(h.api.requestsTo("POST /api/v1/profiles/{id}/versions/{n}/grants"))
		if r = h.run("", args...); r.code != 0 {
			t.Fatalf("%v: %v", c, r)
		}
		reqs := h.api.requestsTo("POST /api/v1/profiles/{id}/versions/{n}/grants")
		if len(reqs) != before+1 {
			t.Fatalf("%v sent no request", c)
		}
		var in control.GrantInput
		mustDecode(t, reqs[len(reqs)-1].Body, &in)
		edits[strings.Join(c, " ")] = in.Edits[0]
	}
	if e := edits["web https quic"]; e.Action != "allow-web" || len(e.Values) != 2 {
		t.Errorf("%+v", e)
	}
	if e := edits["web deny quic"]; e.Action != "deny-web" || e.Values[0] != "quic" {
		t.Errorf("%+v", e)
	}
	if e := edits["mount repo --mode read-write"]; e.Mode != "read-write" || e.Values[0] != "repo" {
		t.Errorf("%+v", e)
	}
	if e := edits["device /dev/urandom"]; e.Action != "device" || e.Values[0] != "/dev/urandom" {
		t.Errorf("%+v", e)
	}
	if e := edits["revoke device /dev/tty"]; e.Action != "revoke" || e.Kind != "device" || e.Values[0] != "/dev/tty" {
		t.Errorf("%+v", e)
	}
	if e := edits["revoke web quic"]; e.Kind != "web" || e.Values[0] != "quic" {
		t.Errorf("%+v", e)
	}
	h.api.reply("GET /api/v1/access-presets", 200, map[string]any{"items": []map[string]any{{"name": "python-dev", "description": "Python", "web": []string{"https"}, "filesystem": map[string]any{}, "process": map[string]any{}}}, "actions": access.Actions, "revoke_kinds": access.RevokeKinds})
	if r = h.run("", "preset", "ls"); r.code != 0 || !strings.Contains(r.stdout, "python-dev") || !strings.Contains(r.stdout, "anon-exec") {
		t.Fatalf("%v", r)
	}
	h.api.handle("POST /api/v1/profiles", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		var in map[string]any
		json.Unmarshal(body, &in)
		if in["require_approval"] == false {
			apiError(w, 403, "approval_policy_forbidden", "Only an administrator creates a profile whose launches skip approval.")
			return
		}
		writeJSON(w, 200, map[string]any{"profile": control.Profile{ID: "p2", Name: "web", RequireApproval: true, LatestVersion: 1}, "version": control.ProfileVersion{Number: 1, Digest: digestA}})
	})
	if r = h.run("", "profile", "new", "web", "--no-approval"); r.code != ExitForbidden || !strings.Contains(r.stderr, "drop --no-approval") {
		t.Fatalf("%v", r)
	}
	docFile := filepath.Join(t.TempDir(), "doc.json")
	os.WriteFile(docFile, []byte(`{"version":"agentgate.poc.v2"}`), 0o600)
	if r = h.run("", "profile", "new", "web", "--file", docFile); r.code != 0 {
		t.Fatalf("%v", r)
	}
	reqs := h.api.requestsTo("POST /api/v1/profiles")
	var created map[string]json.RawMessage
	mustDecode(t, reqs[len(reqs)-1].Body, &created)
	if string(created["document"]) != `{"version":"agentgate.poc.v2"}` {
		t.Fatalf("the document must be sent as given, not edited: %s", created["document"])
	}
}

func TestLaunchDryRunShowsEverything(t *testing.T) {
	h := newHarness(t)
	h.login("local:lin", "launcher")
	h.api.handle("POST /api/v1/launch-plans", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		writeJSON(w, 200, map[string]any{"dry_run": true, "plan": samplePlan(), "spec": json.RawMessage(body), "policy": json.RawMessage(`{"version":"agentgate.poc.v2"}`)})
	})
	spec := filepath.Join(t.TempDir(), "spec.json")
	os.WriteFile(spec, []byte(`{"version":"agentgate.launch.v1","name":"repo-fixer","target":"local","mode":"session","lifetime_seconds":3600,
	 "agent":{"image":"`+imageRef+`","command":["claude","--print","fix the failing tests"]},"access":{"profile":"python-dev","version":3},
	 "mounts":[{"name":"repo","source":"/srv/repos/app","mode":"read-only"}],"secrets":[{"ref":"anthropic","expose":{"env":"ANTHROPIC_BASE_URL"}}],"approval":"auto"}`), 0o600)
	r := h.run("", "launch", "-f", spec, "--dry-run")
	if r.code != 0 {
		t.Fatalf("%v", r)
	}
	golden(t, h, "launch-dry-run", r.stdout)
	if len(h.api.requestsTo("POST /api/v1/launches")) != 0 {
		t.Fatal("--dry-run created a launch")
	}
	r = h.run("", "launch", "-f", spec, "--dry-run", "--json")
	var out PlanResult
	if r.code != 0 || json.Unmarshal([]byte(r.stdout), &out) != nil || out.Plan.PolicyDigest != digestB || !out.DryRun {
		t.Fatalf("--json: %v", r)
	}
	if r = h.run("", "launch", "-f", spec, "--name", "x"); r.code != ExitUsage {
		t.Fatalf("-f with spec flags: %v", r)
	}
	if r = h.run("{}", "launch", "-f", "-", "--dry-run", "--wait"); r.code != ExitUsage {
		t.Fatalf("--dry-run --wait: %v", r)
	}
}

func TestLaunchFromFlagsBuildsTheSpec(t *testing.T) {
	h := newHarness(t)
	h.login("local:lin", "launcher")
	h.api.reply("GET /api/v1/profiles/{id}", 200, control.Profile{ID: "p1", Name: "python-dev", LatestVersion: 3, RequireApproval: true})
	h.api.reply("GET /api/v1/targets/{id}", 200, control.Target{ID: strings.Repeat("7", 32), Name: "local", State: "active"})
	usable := func(name string) control.LauncherSecret {
		yes := true
		return control.LauncherSecret{Name: name, State: "stored", Upstreams: []string{"api.example.com"}, RuleCount: 1, LauncherAllowed: true, ProfileAllowed: &yes, Usable: true}
	}
	no := false
	h.api.reply("GET /api/v1/targets/{id}/secrets", 200, map[string]any{"target_id": strings.Repeat("7", 32), "target": "local", "profile": "python-dev", "items": []control.LauncherSecret{usable("anthropic"), usable("gh"),
		{Name: "ops-key", State: "stored", Upstreams: []string{"api.example.com"}, RuleCount: 1, LauncherAllowed: false, ProfileAllowed: &no, Reason: "it is not scoped to you"}}})
	for _, c := range []struct {
		secret string
		code   int
		text   string
	}{{"missing", ExitUsage, "holds no secret of that name (usable: anthropic, gh)"}, {"ops-key", ExitForbidden, "not scoped to you"}} {
		if r := h.run("", "launch", "--profile", "python-dev", "--image", imageRef, "--secret", c.secret, "--", "true"); r.code != c.code || !strings.Contains(r.stderr, c.text) {
			t.Fatalf("--secret %s: %v", c.secret, r)
		}
	}
	if len(h.api.requestsTo("POST /api/v1/launches")) != 0 || len(h.api.requestsTo("POST /api/v1/launch-plans")) != 0 {
		t.Fatal("a launch with an unusable --secret was sent")
	}
	if q := h.api.requestsTo("GET /api/v1/targets/{id}/secrets")[0].Query.Get("profile"); q != "python-dev" {
		t.Fatalf("the secret check asked about profile %q", q)
	}
	created := sampleLaunch("approval_pending")
	h.api.reply("POST /api/v1/launches", 200, map[string]any{"launch": created, "plan": samplePlan()})
	r := h.run("", "launch", "--name", "repo-fixer", "--mode", "session", "--lifetime", "2h", "--profile", "python-dev", "--image", imageRef,
		"--mount", "/srv/repos/app:repo:ro", "--mount", "/srv/cache:cache:snapshot", "--secret", "anthropic", "--secret", "gh:GITHUB_PROXY_URL", "--env", "EDITOR=vi", "--", "claude", "--print", "fix it")
	if r.code != ExitApprovalPending || !strings.Contains(r.stdout, "agentgate approve "+created.ID) || !strings.Contains(r.stdout, "cannot approve your own launch") {
		t.Fatalf("%v", r)
	}
	var spec hostproto.LaunchSpec
	req := h.api.requestsTo("POST /api/v1/launches")[0]
	if err := hostproto.DecodeStrict(req.Body, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Version != "agentgate.launch.v1" || spec.Name != "repo-fixer" || spec.Target != "local" || spec.Mode != "session" || spec.LifetimeSeconds != 7200 ||
		spec.Access.Profile != "python-dev" || spec.Access.Version != 3 || strings.Join(spec.Agent.Command, " ") != "claude --print fix it" || spec.Agent.Env["EDITOR"] != "vi" ||
		len(spec.Mounts) != 2 || spec.Mounts[0].Mode != "read-only" || spec.Mounts[1].Mode != "snapshot" ||
		len(spec.Secrets) != 2 || spec.Secrets[0].Expose.Env != "ANTHROPIC_BASE_URL" || spec.Secrets[1].Expose.Env != "GITHUB_PROXY_URL" || spec.Approval != "auto" {
		t.Fatalf("%+v", spec)
	}
	if _, _, _, err := control.ValidateLaunchSpec(req.Body); err != nil {
		t.Fatalf("the service validator rejects the CLI's spec: %v", err)
	}
	if req.Header.Get("Idempotency-Key") == "" {
		t.Fatal("launch creation must carry an idempotency key")
	}
	queued := sampleLaunch("queued")
	queued.ExpiresAt = "2026-10-24T13:00:00Z"
	h.api.reply("POST /api/v1/launches", 200, map[string]any{"launch": queued, "plan": samplePlan()})
	r = h.run("", "launch", "--profile", "python-dev@2", "--image", imageRef, "-q", "--", "pytest")
	if r.code != 0 || strings.TrimSpace(r.stdout) != queued.ID {
		t.Fatalf("--quiet prints the id: %v", r)
	}
	reqs := h.api.requestsTo("POST /api/v1/launches")
	mustDecode(t, reqs[len(reqs)-1].Body, &spec)
	if spec.Mode != "oneshot" || spec.LifetimeSeconds != 600 || spec.Access.Version != 2 || spec.Name != "agentgate-coding" {
		t.Fatalf("defaults: %+v", spec)
	}
	for _, bad := range [][]string{{"launch", "--image", imageRef}, {"launch", "--profile", "p@x", "--image", imageRef}, {"launch", "--profile", "p@1", "--image", imageRef, "--mount", "/a"}, {"launch", "--profile", "p@1", "--image", imageRef, "--env", "NOEQUALS"}, {"launch", "--profile", "p@1", "--image", imageRef, "pytest"}} {
		if r = h.run("", bad...); r.code != ExitUsage {
			t.Errorf("%v: %v", bad, r)
		}
	}
	h.api.handle("POST /api/v1/launches", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		apiError(w, 422, "invalid_launch_spec", "agent.env name \"API_KEY\" looks like a credential; deliver secrets through the secrets list")
	})
	h.api.lenient = true
	r = h.run("", "launch", "--profile", "p@1", "--image", imageRef, "--env", "API_KEY=x", "--", "true")
	if r.code != ExitRejected || !strings.Contains(r.stderr, "looks like a credential") || !strings.Contains(r.stderr, "schema launch-spec") {
		t.Fatalf("the server's validation message must surface: %v", r)
	}
}

func TestPsShowLogsAuditGolden(t *testing.T) {
	h := newHarness(t)
	h.login("local:vic", "viewer")
	running := sampleLaunch("running")
	running.StartedAt, running.QueuedAt, running.ExpiresAt = "2026-10-24T11:32:00Z", "2026-10-24T11:31:00Z", "2026-10-24T12:31:00Z"
	ended := sampleLaunch("stopped")
	ended.ID, ended.Name, ended.Mode = "11112222333344445555666677778888", "tests", "oneshot"
	h.api.handle("GET /api/v1/launches", func(w http.ResponseWriter, r *http.Request, body []byte, p []string) {
		q := r.URL.Query()
		switch {
		case q.Get("state") == "active":
			writeJSON(w, 200, map[string]any{"items": []control.Launch{running}, "limit": 50})
		case q.Get("cursor") == "page-2":
			writeJSON(w, 200, map[string]any{"items": []control.Launch{ended}, "limit": 1})
		case q.Get("limit") == "1":
			writeJSON(w, 200, map[string]any{"items": []control.Launch{running}, "limit": 1, "next_cursor": "page-2"})
		default:
			writeJSON(w, 200, map[string]any{"items": []control.Launch{running, ended}, "limit": 50})
		}
	})
	h.api.reply("GET /api/v1/targets", 200, map[string]any{"items": []control.Target{sampleTarget("active")}})
	r := h.run("", "ps")
	if r.code != 0 {
		t.Fatalf("%v", r)
	}
	golden(t, h, "ps", r.stdout)
	if r = h.run("", "ps", "--active", "-q"); r.code != 0 || strings.TrimSpace(r.stdout) != running.ID {
		t.Fatalf("%v", r)
	}
	if r = h.run("", "ps", "--state", "running", "--target", "local", "--name", "fix", "--mine"); r.code != 0 {
		t.Fatalf("%v", r)
	}
	q := h.api.requestsTo("GET /api/v1/launches")[2].Query
	if q.Get("state") != "running" || q.Get("target") != "local" || q.Get("name") != "fix" || q.Get("mine") != "true" || q.Get("limit") != "50" {
		t.Fatalf("filters sent: %v", q)
	}
	if r = h.run("", "ps", "--limit", "1"); r.code != 0 || !strings.Contains(r.stderr, "agentgate ps --cursor page-2") || strings.Contains(r.stdout, ended.ID) {
		t.Fatalf("a full page names the next cursor: %v", r)
	}
	if r = h.run("", "ps", "--limit", "1", "--all", "-q"); r.code != 0 || strings.TrimSpace(r.stdout) != running.ID+"\n"+ended.ID {
		t.Fatalf("--all follows the cursor: %v", r)
	}
	if r = h.run("", "ps", "--limit", "1", "--cursor", "page-2", "-q"); r.code != 0 || strings.TrimSpace(r.stdout) != ended.ID {
		t.Fatalf("--cursor: %v", r)
	}
	for _, bad := range [][]string{{"ps", "--active", "--state", "stopped"}, {"ps", "--mine", "--requester", "local:ada"}, {"ps", "--all", "--cursor", "x"}, {"ps", "--limit", "500"}} {
		if r = h.run("", bad...); r.code != ExitUsage {
			t.Fatalf("%v: %v", bad, r)
		}
	}
	exit := 0
	rec, _ := json.Marshal(hostproto.Receipt{Version: hostproto.ReceiptVersion, LaunchID: ended.ID, BrokerCounts: map[string]uint64{"api.anthropic.com": 4}, ExitCode: &exit, Reason: "exited", DomainEmpty: true, EnforcementReleased: true})
	ended.Receipt = rec
	h.api.reply("GET /api/v1/launches/{id}", 200, map[string]any{"launch": ended, "jobs": []control.JobRecord{{ID: "j1", Type: "launch", TargetID: ended.TargetID, State: "completed", Attempts: 1, Created: "2026-10-24T11:31:00Z", Completed: "2026-10-24T11:40:00Z"}}})
	if r = h.run("", "show", ended.ID); r.code != 0 {
		t.Fatalf("%v", r)
	}
	golden(t, h, "show", r.stdout)
	h.api.reply("GET /api/v1/launches/{id}/logs", 200, map[string]any{"items": []control.LogLine{{Seq: 1, Stream: "stdout", Text: "collected 3 items"}, {Seq: 2, Stream: "stderr", Text: "warning: \x1b[31mred\x1b[0m"}}, "bytes": 40, "limit_bytes": 1 << 20, "truncated": false})
	r = h.run("", "logs", ended.ID)
	if r.code != 0 || r.stdout != "collected 3 items\nwarning: [31mred[0m\n" {
		t.Fatalf("logs must strip escape sequences: %q %v", r.stdout, r)
	}
	if r = h.run("", "logs", ended.ID, "--stream", "stderr", "--json"); r.code != 0 || strings.Contains(r.stdout, "collected") {
		t.Fatalf("%v", r)
	}
	h.api.handle("GET /api/v1/audit", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		if r.URL.Query().Get("run") != ended.ID || r.URL.Query().Get("after") != "2026-10-24T11:00:00Z" {
			apiError(w, 422, "invalid_filter", "wrong filter "+r.URL.RawQuery)
			return
		}
		writeJSON(w, 200, map[string]any{"items": []control.AuditEntry{{ID: 7, Time: "2026-10-24T11:31:00Z", Actor: "local:app", ActorKind: "human", Action: "launch.approved", Resource: "launch:" + ended.ID, Run: ended.ID, Reason: "Reviewed the plan", Result: "committed"}}})
	})
	if r = h.run("", "audit", "--launch", ended.ID, "--since", "1h"); r.code != 0 {
		t.Fatalf("%v", r)
	}
	golden(t, h, "audit", r.stdout)
}

func TestStopAndDecisions(t *testing.T) {
	h := newHarness(t)
	h.login("local:lin", "launcher", "approver")
	running := sampleLaunch("running")
	h.api.reply("GET /api/v1/launches/{id}", 200, map[string]any{"launch": running, "jobs": []any{}})
	stopping := running
	stopping.State = "stopping"
	h.api.reply("POST /api/v1/launches/{id}/stop", 200, stopping)
	if r := h.run("", "stop", running.ID); r.code != ExitUsage || !strings.Contains(r.stderr, "--yes") {
		t.Fatalf("stopping a running session needs confirmation: %v", r)
	}
	if len(h.api.requestsTo("POST /api/v1/launches/{id}/stop")) != 0 {
		t.Fatal("stop ran without confirmation")
	}
	if r := h.run("", "stop", running.ID, "--yes"); r.code != 0 || !strings.Contains(r.stdout, "stopping") {
		t.Fatalf("%v", r)
	}
	oneshot := sampleLaunch("running")
	oneshot.Mode = "oneshot"
	h.api.reply("GET /api/v1/launches/{id}", 200, map[string]any{"launch": oneshot, "jobs": []any{}})
	if r := h.run("", "stop", oneshot.ID); r.code != 0 {
		t.Fatalf("a oneshot stops without a prompt: %v", r)
	}

	pending := sampleLaunch("approval_pending")
	h.api.reply("GET /api/v1/launches/{id}", 200, map[string]any{"launch": pending, "jobs": []any{}})
	if r := h.run("", "approve", pending.ID); r.code != ExitUsage || !strings.Contains(r.stderr, "--reason") {
		t.Fatalf("%v", r)
	}
	h.api.handle("POST /api/v1/launches/{id}/approve", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		apiError(w, 403, "self_approval", "A different human must decide this launch.")
	})
	r := h.run("", "approve", pending.ID, "--reason", "Reviewed the plan", "--yes")
	if r.code != ExitForbidden || !strings.Contains(r.stderr, "never lets the requester decide") || !strings.Contains(r.stderr, "different human") {
		t.Fatalf("self approval must be surfaced clearly: %v", r)
	}
	approved := pending
	approved.State, approved.ExpiresAt = "queued", "2026-10-24T13:00:00Z"
	h.api.reply("POST /api/v1/launches/{id}/approve", 200, approved)
	if r = h.run("", "approve", pending.ID, "--reason", "Reviewed the plan"); r.code != ExitUsage {
		t.Fatalf("approve in a script needs --yes: %v", r)
	}
	if r = h.run("", "approve", pending.ID, "--reason", "Reviewed the plan", "--yes"); r.code != 0 || !strings.Contains(r.stdout, "approved: queued") {
		t.Fatalf("%v", r)
	}
	h.term.tty = [3]bool{true, true, true}
	if r = h.run("Reviewed it\ny\n", "approve", pending.ID); r.code != 0 || !strings.Contains(r.stdout, "What this agent may do") {
		t.Fatalf("interactive approval shows the plan first: %v", r)
	}
	h.term.tty = [3]bool{}
	rejected := pending
	rejected.State = "rejected"
	h.api.reply("POST /api/v1/launches/{id}/reject", 200, rejected)
	if r = h.run("", "reject", pending.ID, "--reason", "Too broad"); r.code != 0 || !strings.Contains(r.stdout, "rejected") {
		t.Fatalf("%v", r)
	}
	h.api.reply("GET /api/v1/launches/{id}", 200, map[string]any{"launch": running, "jobs": []any{}})
	if r = h.run("", "reject", running.ID, "--reason", "x y z"); r.code != ExitConflict {
		t.Fatalf("%v", r)
	}
}

func TestSchemaAndSecretList(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	h.api.reply("GET /api/v1/launch-spec-schema", 200, control.LaunchSpecSchema())
	if r := h.run("", "schema", "launch-spec"); r.code != 0 || !strings.Contains(r.stdout, "agentgate.launch.v1") {
		t.Fatalf("%v", r)
	}
	h.api.reply("GET /api/v1/targets", 200, map[string]any{"items": []control.Target{sampleTarget("active")}})
	sec := control.Secret{ID: "s1", Name: "anthropic", TargetID: sampleTarget("active").ID, Upstreams: []string{"api.anthropic.com"}, Header: "x-api-key", Fingerprint: digestA, AllowedProfiles: []string{"python-dev"}, AllowedLaunchers: []string{"local:lin"}, State: "stored"}
	h.api.reply("GET /api/v1/secrets", 200, map[string]any{"items": []control.Secret{sec}})
	if r := h.run("", "secret", "ls"); r.code != 0 || !strings.Contains(r.stdout, "anthropic") || !strings.Contains(r.stdout, "local") {
		t.Fatalf("%v", r)
	}
	h.api.reply("GET /api/v1/targets/{id}", 200, sampleTarget("active"))
	deleting := sec
	deleting.State = "deleting"
	h.api.reply("DELETE /api/v1/secrets/{id}", 200, deleting)
	if r := h.run("", "secret", "rm", "anthropic"); r.code != ExitUsage {
		t.Fatalf("secret rm needs confirmation: %v", r)
	}
	if r := h.run("", "secret", "rm", "anthropic", "--yes"); r.code != 0 || !strings.Contains(r.stdout, "deleting") {
		t.Fatalf("%v", r)
	}
	if r := h.run("", "secret", "rm", "nope", "--yes"); r.code != ExitNotFound {
		t.Fatalf("%v", r)
	}
}

func TestGrantPreviewNeedsTheServicesDryRun(t *testing.T) {
	h := newHarness(t)
	h.login("local:eve", "editor")
	profileFixtures(h)
	// A service that ignores dry_run and stores a version is reported, never
	// shown as a preview.
	h.api.handle("POST /api/v1/profiles/{id}/versions/{n}/grants", func(w http.ResponseWriter, r *http.Request, body []byte, p []string) {
		writeJSON(w, 200, map[string]any{"changed": true, "version": control.ProfileVersion{ID: "v2", Number: 2}, "messages": []string{}, "notices": []string{}})
	})
	if r := h.run("", "grant", "dev", "read", "/srv/data", "--dry-run"); r.code != ExitServer || !strings.Contains(r.stderr, "invalid_response") || strings.Contains(r.stdout, "Preview") {
		t.Fatalf("%v", r)
	}
}

func TestGrantBoundsMatchTheAccessEngine(t *testing.T) {
	if strings.Join(grantRevokeKinds, " ") != strings.Join(access.RevokeKinds, " ") || maxGrantValues != access.MaxValues {
		t.Fatalf("the CLI's grant bounds drifted from internal/access: %v %d", grantRevokeKinds, maxGrantValues)
	}
}

func TestSecretListForLaunchers(t *testing.T) {
	h := newHarness(t)
	h.login("local:lin", "launcher")
	h.api.reply("GET /api/v1/targets/{id}", 200, sampleTarget("active"))
	yes := true
	h.api.reply("GET /api/v1/targets/{id}/secrets", 200, map[string]any{"target_id": sampleTarget("active").ID, "target": "local", "items": []control.LauncherSecret{
		{Name: "model-api", State: "stored", Upstreams: []string{"api.model.example"}, RuleCount: 2, LauncherAllowed: true, ProfileAllowed: &yes, Usable: true},
		{Name: "bare-key", State: "stored", Upstreams: []string{"api.model.example"}, LauncherAllowed: true, Reason: "it has no broker rules, so no launch can use it (secret_rules_missing)"}}})
	r := h.run("", "secret", "ls")
	if r.code != 0 || !strings.Contains(r.stdout, "model-api") || !strings.Contains(r.stdout, "no: it has no broker rules") || len(h.api.requestsTo("GET /api/v1/secrets")) != 0 {
		t.Fatalf("%v", r)
	}
	if r = h.run("", "secret", "ls", "-q", "--profile", "dev"); r.code != 0 || strings.TrimSpace(r.stdout) != "model-api" {
		t.Fatalf("-q lists the usable names: %v", r)
	}
	if q := h.api.requestsTo("GET /api/v1/targets/{id}/secrets"); q[len(q)-1].Query.Get("profile") != "dev" {
		t.Fatal("--profile was not sent")
	}
}

func TestTargetRetireWaitsForTheHostOrForces(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	h.api.reply("GET /api/v1/targets/{id}", 200, sampleTarget("active"))
	retiring := sampleTarget("retiring")
	retiring.RetiringSince = "2026-10-24T12:00:00Z"
	h.api.reply("DELETE /api/v1/targets/{id}", 200, retiring)
	if r := h.run("", "target", "retire", "local", "--yes"); r.code != 0 || !strings.Contains(r.stdout, "is retiring: its host removes each secret") {
		t.Fatalf("%v", r)
	}
	var in control.TargetRetireInput
	mustDecode(t, h.api.requestsTo("DELETE /api/v1/targets/{id}")[0].Body, &in)
	if in.Force {
		t.Fatal("force was sent without --force")
	}
	h.api.handle("DELETE /api/v1/targets/{id}", func(w http.ResponseWriter, r *http.Request, body []byte, p []string) {
		var in control.TargetRetireInput
		json.Unmarshal(body, &in)
		if !in.Force {
			apiError(w, 409, "secrets_on_host", "The host may still hold 1 secret values but cannot collect removal jobs in state awaiting_key_approval.")
			return
		}
		writeJSON(w, 200, sampleTarget("retired"))
	})
	if r := h.run("", "target", "retire", "local", "--yes"); r.code != ExitConflict || !strings.Contains(r.stderr, "--force and wipe the host") {
		t.Fatalf("%v", r)
	}
	if r := h.run("", "target", "retire", "local", "--yes", "--force"); r.code != 0 || !strings.Contains(r.stdout, "is retired") {
		t.Fatalf("%v", r)
	}
}

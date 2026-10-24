// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/control"
)

const userPassword = "lin-password-0123456789"

func tokenRoutes(h *harness) {
	h.api.enableSessions("lin", userPassword, []string{"launcher", "approver"})
	h.api.handle("POST /api/v1/api-tokens", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-CSRF-Token") != "session-csrf" || r.Header.Get("Origin") != h.api.URL() {
			apiError(w, 403, "session_required", "Create API tokens from a signed-in browser session.")
			return
		}
		var in control.APITokenInput
		json.Unmarshal(body, &in)
		writeJSON(w, 200, map[string]any{"id": "tok9", "name": in.Name, "roles": in.Roles, "expires_at": "2026-11-23T12:00:00Z", "token": testToken})
	})
	h.api.reply("GET /api/v1/api-tokens", 200, map[string]any{"items": []control.APIToken{{ID: "tok9", Subject: "local:lin", Name: "agentgate-cli on testhost", Roles: []string{"launcher"}, Created: "2026-10-24T12:00:00Z", Expires: "2026-11-23T12:00:00Z"}}})
	h.api.reply("DELETE /api/v1/api-tokens/{id}", 200, map[string]string{"id": "tok9", "revoked_at": "2026-10-24T12:01:00Z"})
	h.api.reply("GET /api/v1/launch-spec-schema", 200, map[string]any{})
}

func TestLoginWithPasswordSavesATokenItNeverPrints(t *testing.T) {
	h := newHarness(t)
	tokenRoutes(h)
	r := h.run(userPassword+"\n", "login", h.api.URL(), "--username", "lin", "--password-stdin", "--role", "launcher")
	if r.code != 0 || strings.Contains(r.stdout+r.stderr, testToken) || strings.Contains(r.stdout+r.stderr, userPassword) || !strings.Contains(r.stdout, "as local:lin") {
		t.Fatalf("%v", r)
	}
	var in control.APITokenInput
	mustDecode(t, h.api.requestsTo("POST /api/v1/api-tokens")[0].Body, &in)
	if in.Roles[0] != "launcher" || in.ExpiresInSeconds != 30*86400 || in.Name != "agentgate-cli on testhost" {
		t.Fatalf("%+v", in)
	}
	if len(h.api.requestsTo("POST /auth/logout")) != 1 {
		t.Fatal("the session was not signed out after minting the token")
	}
	st := store{dir: h.dir, euid: os.Geteuid()}
	cfg, _ := st.load()
	if c := cfg.Contexts["default"]; c == nil || c.Token != testToken || c.Subject != "local:lin" || c.TokenID != "tok9" {
		t.Fatalf("%+v", c)
	}
	if r = h.run("wrong-password-123456\n", "login", h.api.URL(), "--username", "lin", "--password-stdin"); r.code != ExitAuth || !strings.Contains(r.stderr, "invalid_credentials") {
		t.Fatalf("%v", r)
	}
	if r = h.run(userPassword+"\n", "login", h.api.URL(), "--password-stdin"); r.code != ExitUsage {
		t.Fatalf("a scripted login needs --username: %v", r)
	}
	if r = h.run("", "login", h.api.URL(), "--username", "lin"); r.code != ExitUsage || !strings.Contains(r.stderr, "--password-stdin") {
		t.Fatalf("no terminal and no password source: %v", r)
	}
	if r = h.run("", "login", "ftp://x"); r.code != ExitUsage {
		t.Fatalf("%v", r)
	}
}

func TestLoginWithAnExistingToken(t *testing.T) {
	h := newHarness(t)
	tokenRoutes(h)
	if r := h.run("not-a-token\n", "login", h.api.URL(), "--token-stdin"); r.code != ExitUsage {
		t.Fatalf("%v", r)
	}
	r := h.run(testToken+"\n", "login", h.api.URL(), "--token-stdin", "--save-as", "lab")
	if r.code != 0 || strings.Contains(r.stdout+r.stderr, testToken) {
		t.Fatalf("%v", r)
	}
	h.term.tty = [3]bool{true, true, true}
	h.term.secrets = [][]byte{[]byte(testToken)}
	if r = h.run("", "login", h.api.URL(), "--token-stdin", "--save-as", "lab2"); r.code != 0 || !strings.Contains(strings.Join(h.term.prompts, ""), "input hidden") {
		t.Fatalf("%v", r)
	}
	h.api.handle("GET /api/v1/launch-spec-schema", func(w http.ResponseWriter, _ *http.Request, _ []byte, _ []string) {
		apiError(w, 401, "invalid_token", "The API token is unknown, expired or revoked.")
	})
	h.term.secrets = [][]byte{[]byte(testToken)}
	if r = h.run("", "login", h.api.URL(), "--token-stdin", "--save-as", "lab3"); r.code != ExitAuth {
		t.Fatalf("a rejected token is not saved: %v", r)
	}
	st := store{dir: h.dir, euid: os.Geteuid()}
	cfg, _ := st.load()
	if cfg.Contexts["lab3"] != nil || cfg.Contexts["lab"] == nil {
		t.Fatalf("%v", contextNames(cfg))
	}
}

func TestTokenCommandsUseAPasswordSession(t *testing.T) {
	h := newHarness(t)
	h.login("local:lin", "launcher")
	tokenRoutes(h)
	r := h.run(userPassword+"\n", "token", "create", "--username", "lin", "--password-stdin")
	if r.code != 0 || strings.Count(r.stdout, testToken) != 1 || !strings.Contains(r.stderr, "shown once") {
		t.Fatalf("token create prints the new token exactly once: %v", r)
	}
	r = h.run(userPassword+"\n", "token", "create", "--username", "lin", "--password-stdin", "--save", "--expires", "2h")
	if r.code != 0 || strings.Contains(r.stdout+r.stderr, testToken) {
		t.Fatalf("token create --save never prints it: %v", r)
	}
	if r = h.run(userPassword+"\n", "token", "create", "--username", "lin", "--password-stdin", "--expires", "100d"); r.code != ExitUsage {
		t.Fatalf("%v", r)
	}
	if r = h.run(userPassword+"\n", "token", "ls", "--username", "lin", "--password-stdin"); r.code != 0 || !strings.Contains(r.stdout, "tok9") || !strings.Contains(r.stdout, "active") {
		t.Fatalf("%v", r)
	}
	for _, req := range h.api.requestsTo("GET /api/v1/api-tokens") {
		if req.Header.Get("Authorization") != "" {
			t.Fatal("token ls sent the API token; it needs the session")
		}
	}
	if r = h.run(userPassword+"\n", "token", "revoke", "tok9", "--username", "lin", "--password-stdin"); r.code != 0 || !strings.Contains(r.stdout, "Revoked token tok9") {
		t.Fatalf("%v", r)
	}
	if r = h.run(userPassword+"\n", "logout", "--revoke", "--username", "lin", "--password-stdin"); r.code != 0 {
		t.Fatalf("%v", r)
	}
	if n := len(h.api.requestsTo("DELETE /api/v1/api-tokens/{id}")); n != 2 {
		t.Fatalf("logout --revoke revokes the saved token (%d revocations)", n)
	}
	st := store{dir: h.dir, euid: os.Geteuid()}
	cfg, _ := st.load()
	if c := cfg.Contexts["default"]; c == nil || c.Token != "" || c.Server != h.api.URL() {
		t.Fatalf("logout keeps the server and drops the token: %+v", c)
	}
}

func TestMoreTargetProfileAndAuditCommands(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	h.api.reply("POST /api/v1/targets/{id}/enrollment", 200, map[string]any{"target": sampleTarget("active"), "enrollment": map[string]any{"token": "agtenr_" + strings.Repeat("R", 43), "expires_at": "2026-10-24T12:15:00Z", "single_use": true, "enroll_path": "/api/v1/hostd/enroll"}})
	r := h.run("", "target", "enroll", "local")
	if r.code != 0 || !strings.Contains(r.stdout, "agtenr_RRRR") || !strings.Contains(r.stdout, "--token-file TOKEN-FILE") {
		t.Fatalf("%v", r)
	}
	tf := filepath.Join(t.TempDir(), "tok")
	if r = h.run("", "target", "enroll", "local", "--token-file", tf, "--json"); r.code != 0 || strings.Contains(r.stdout, "agtenr_") || !strings.Contains(r.stdout, `"token_file"`) {
		t.Fatalf("--json with --token-file keeps the token out of stdout: %v", r)
	}
	renamed := sampleTarget("active")
	renamed.Name = "edge"
	h.api.reply("PATCH /api/v1/targets/{id}", 200, renamed)
	if r = h.run("", "target", "rename", "local", "edge"); r.code != 0 || !strings.Contains(r.stdout, "to edge") {
		t.Fatalf("%v", r)
	}
	h.api.reply("PATCH /api/v1/profiles/{id}", 200, control.Profile{ID: "p1", Name: "dev", RequireApproval: false})
	if r = h.run("", "profile", "approval", "dev", "auto"); r.code != 0 || !strings.Contains(r.stdout, "launch approval auto") {
		t.Fatalf("%v", r)
	}
	if r = h.run("", "profile", "approval", "dev", "maybe"); r.code != ExitUsage {
		t.Fatalf("%v", r)
	}
	h.api.reply("GET /api/v1/audit-catalog", 200, map[string]any{"items": control.AuditCatalog})
	if r = h.run("", "audit", "catalog"); r.code != 0 || !strings.Contains(r.stdout, "launch.state.changed") {
		t.Fatalf("%v", r)
	}
	if r = h.run("", "audit", "--since", "yesterday"); r.code != ExitUsage {
		t.Fatalf("%v", r)
	}
	h.api.reply("GET /api/v1/launches/{id}/events", 200, map[string]any{"items": []control.LaunchEvent{stateEvent(1, "", "requested", "Launch requested"), stateEvent(2, "requested", "cancelled", "Stopped")}})
	if r = h.run("", "events", "x1"); r.code != 0 || !strings.Contains(r.stdout, "requested -> cancelled") {
		t.Fatalf("%v", r)
	}
	if r = h.run("", "version"); r.code != 0 || !strings.HasPrefix(r.stdout, "agentgate test") {
		t.Fatalf("%v", r)
	}
}

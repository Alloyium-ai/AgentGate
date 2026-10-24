// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigIsPrivateAndRoundTrips(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	info, err := os.Lstat(h.dir)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("config dir mode %v err %v", info.Mode(), err)
	}
	info, err = os.Lstat(filepath.Join(h.dir, configFileName))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("config file mode %v err %v", info.Mode(), err)
	}
	st := store{dir: h.dir, euid: os.Geteuid()}
	cfg, err := st.load()
	if err != nil || cfg.Contexts["default"].Token != testToken || cfg.CurrentContext != "default" {
		t.Fatalf("load: %+v %v", cfg, err)
	}
}

func TestConfigCustodyRefusals(t *testing.T) {
	cases := map[string]func(t *testing.T, h *harness){
		"group-readable file": func(t *testing.T, h *harness) {
			os.Chmod(filepath.Join(h.dir, configFileName), 0o640)
		},
		"world-readable directory": func(t *testing.T, h *harness) {
			os.Chmod(h.dir, 0o755)
		},
		"symlinked file": func(t *testing.T, h *harness) {
			real := filepath.Join(t.TempDir(), "elsewhere.json")
			raw, _ := os.ReadFile(filepath.Join(h.dir, configFileName))
			os.WriteFile(real, raw, 0o600)
			os.Remove(filepath.Join(h.dir, configFileName))
			os.Symlink(real, filepath.Join(h.dir, configFileName))
		},
		"symlinked directory": func(t *testing.T, h *harness) {
			real := filepath.Join(t.TempDir(), "realdir")
			os.Rename(h.dir, real)
			os.Symlink(real, h.dir)
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			h.login("local:ada", "admin")
			breakIt(t, h)
			r := h.run("", "target", "ls")
			if r.code != ExitTrust || !strings.Contains(r.stderr, "refuses to use it") {
				t.Fatalf("%v", r)
			}
			if strings.Contains(r.stdout+r.stderr, testToken) {
				t.Fatal("the token was printed")
			}
			if len(h.api.requests()) != 0 {
				t.Fatal("a request was sent with an untrusted configuration")
			}
		})
	}
}

func TestSavedTokenGoesOnlyToItsServer(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	other := newFakeAPI(t)
	other.reply("GET /api/v1/targets", 200, map[string]any{"items": []any{}})
	h.api = other
	h.env["AGENTGATE_URL"] = other.URL()
	r := h.run("", "target", "ls")
	if r.code != ExitAuth {
		t.Fatalf("a different server got a credential: %v", r)
	}
	for _, req := range other.requests() {
		if req.Header.Get("Authorization") != "" {
			t.Fatalf("the saved token was sent to %s", other.URL())
		}
	}
	h.env["AGENTGATE_TOKEN"] = testToken
	if r = h.run("", "target", "ls"); r.code != ExitOK {
		t.Fatalf("env token: %v", r)
	}
}

func TestInsecureOnlyForLoopbackHTTP(t *testing.T) {
	h := newHarness(t)
	h.env["AGENTGATE_TOKEN"] = testToken
	h.env["AGENTGATE_URL"] = "http://agentgate.example:8930"
	if r := h.run("", "ps", "--insecure"); r.code != ExitUsage || !strings.Contains(r.stderr, "loopback") {
		t.Fatalf("non-loopback http: %v", r)
	}
	h.env["AGENTGATE_URL"] = "http://127.0.0.1:1"
	if r := h.run("", "ps"); r.code != ExitUsage || !strings.Contains(r.stderr, "plain http is refused") {
		t.Fatalf("http without --insecure: %v", r)
	}
	r := h.run("", "ps", "--insecure", "--timeout", "1s")
	if !strings.Contains(r.stderr, "warning: plain http") || r.code != ExitNetwork {
		t.Fatalf("loopback http with --insecure: %v", r)
	}
}

func TestContextCommands(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	st := store{dir: h.dir, euid: os.Geteuid()}
	st.update(func(cfg *Config) error {
		cfg.Contexts["lab"] = &Context{Server: "https://lab.example:9443"}
		return nil
	})
	r := h.run("", "context", "ls")
	if r.code != 0 || !strings.Contains(r.stdout, "lab") || !strings.Contains(r.stdout, "*") || strings.Contains(r.stdout, testToken) {
		t.Fatalf("%v", r)
	}
	if r = h.run("", "context", "use", "lab"); r.code != 0 {
		t.Fatalf("%v", r)
	}
	if r = h.run("", "context", "use", "nope"); r.code != ExitNotFound {
		t.Fatalf("%v", r)
	}
	if r = h.run("", "context", "rm", "default"); r.code != 0 || !strings.Contains(r.stderr, "tok1") {
		t.Fatalf("%v", r)
	}
	cfg, _ := st.load()
	if cfg.Contexts["default"] != nil || cfg.CurrentContext != "lab" {
		t.Fatalf("%+v", cfg)
	}
}

func TestWhoamiAndLogout(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	h.api.reply("GET /api/v1/launch-spec-schema", 200, map[string]any{"title": "agentgate.launch.v1"})
	r := h.run("", "whoami")
	if r.code != 0 || !strings.Contains(r.stdout, "local:ada") || !strings.Contains(r.stdout, "accepts the token") || strings.Contains(r.stdout, testToken) {
		t.Fatalf("%v", r)
	}
	r = h.run("", "logout")
	if r.code != 0 || !strings.Contains(r.stdout, "agentgate token revoke tok1") {
		t.Fatalf("%v", r)
	}
	if r = h.run("", "whoami"); r.code != ExitAuth {
		t.Fatalf("after logout: %v", r)
	}
	h.api.handle("GET /api/v1/launch-spec-schema", func(w http.ResponseWriter, _ *http.Request, _ []byte, _ []string) {
		apiError(w, 401, "invalid_token", "The API token is unknown, expired or revoked.")
	})
	h.login("local:ada", "admin")
	r = h.run("", "whoami")
	if r.code != ExitAuth || !strings.Contains(r.stderr, "invalid_token") || !strings.Contains(r.stderr, "next:") {
		t.Fatalf("%v", r)
	}
}

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

// Under sudo the configuration never follows HOME or XDG_CONFIG_HOME, which
// the invoking user sets: root would create token files in a tree that user
// controls. Root's own home comes from the account database instead.
func TestConfigDirUnderSudoIgnoresTheCallersHome(t *testing.T) {
	env := func(vars map[string]string) func(string) string { return func(k string) string { return vars[k] } }
	rootHome := func(uid int) (string, error) {
		if uid != 0 {
			t.Fatalf("looked up uid %d", uid)
		}
		return "/root", nil
	}
	cases := []struct {
		name string
		vars map[string]string
		euid int
		dir  string
		note bool
	}{
		{"plain user", map[string]string{"HOME": "/home/alice"}, 1000, "/home/alice/.config/agentgate", false},
		{"plain user with XDG", map[string]string{"HOME": "/home/alice", "XDG_CONFIG_HOME": "/home/alice/.cfg"}, 1000, "/home/alice/.cfg/agentgate", false},
		{"sudo -E keeps the caller's HOME", map[string]string{"HOME": "/home/alice", "SUDO_USER": "alice", "SUDO_UID": "1000"}, 0, "/root/.config/agentgate", true},
		{"sudo with an attacker's XDG", map[string]string{"HOME": "/root", "XDG_CONFIG_HOME": "/etc", "SUDO_USER": "alice", "SUDO_UID": "1000"}, 0, "/root/.config/agentgate", true},
		{"sudo with root's HOME", map[string]string{"HOME": "/root", "SUDO_USER": "alice", "SUDO_UID": "1000"}, 0, "/root/.config/agentgate", false},
		{"sudo with no HOME", map[string]string{"SUDO_UID": "1000"}, 0, "/root/.config/agentgate", true},
		{"root itself", map[string]string{"HOME": "/srv/roothome", "SUDO_USER": "root", "SUDO_UID": "0"}, 0, "/srv/roothome/.config/agentgate", false},
		{"sudo to a non-root user", map[string]string{"HOME": "/home/alice", "SUDO_USER": "alice", "SUDO_UID": "1000"}, 1001, "/home/alice/.config/agentgate", false},
		{"explicit directory under sudo", map[string]string{"HOME": "/home/alice", "SUDO_USER": "alice", "AGENTGATE_CONFIG_DIR": "/root/agentgate"}, 0, "/root/agentgate", false},
	}
	owned := func(string) (int, bool) { return 0, false } // nothing exists: no ownership to compare
	for _, c := range cases {
		dir, note, err := configDir(env(c.vars), c.euid, rootHome, owned)
		if err != nil || dir != c.dir || (note != "") != c.note {
			t.Errorf("%s: %q %q %v", c.name, dir, note, err)
		}
	}
	// No usable account entry: refuse, and say how to choose a directory.
	for _, bad := range []func(int) (string, error){
		func(int) (string, error) { return "", os.ErrNotExist },
		func(int) (string, error) { return "relative/home", nil },
		func(int) (string, error) { return "/root/../home/alice", nil },
	} {
		_, _, err := configDir(env(map[string]string{"HOME": "/home/alice", "SUDO_USER": "alice"}), 0, bad, owned)
		if err == nil || !strings.Contains(err.Error(), "AGENTGATE_CONFIG_DIR") {
			t.Errorf("an unusable account home: %v", err)
		}
	}
	if _, _, err := configDir(env(map[string]string{"AGENTGATE_CONFIG_DIR": "relative"}), 0, rootHome, owned); err == nil {
		t.Fatal("a relative AGENTGATE_CONFIG_DIR was accepted")
	}
	// Outside sudo, a HOME or XDG_CONFIG_HOME that belongs to someone else is refused
	// (root after su without a login shell, review finding 12); one's own is used.
	owners := map[string]int{"/home/alice": 1000, "/home/alice/.cfg": 1000, "/root": 0}
	ownerOf := func(p string) (int, bool) { uid, ok := owners[p]; return uid, ok }
	for _, c := range []struct {
		vars map[string]string
		euid int
		ok   bool
	}{
		{map[string]string{"HOME": "/home/alice"}, 0, false},
		{map[string]string{"HOME": "/root", "XDG_CONFIG_HOME": "/home/alice/.cfg"}, 0, false},
		{map[string]string{"HOME": "/home/alice"}, 1000, true},
		{map[string]string{"HOME": "/root"}, 0, true},
		{map[string]string{"HOME": "/home/alice"}, 1001, false},
		{map[string]string{"HOME": "/home/new-user"}, 1002, true},
		{map[string]string{"HOME": "/home/alice", "AGENTGATE_CONFIG_DIR": "/srv/agentgate"}, 0, true},
	} {
		_, _, err := configDir(env(c.vars), c.euid, rootHome, ownerOf)
		if (err == nil) != c.ok || err != nil && !strings.Contains(err.Error(), "belongs to uid") {
			t.Errorf("%v as uid %d: %v", c.vars, c.euid, err)
		}
	}
}

// The note reaches standard error when a command runs under sudo.
func TestSudoNoteIsShown(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the sudo path applies to root only")
	}
	dir := t.TempDir()
	var stderr strings.Builder
	app := &App{Stdout: &strings.Builder{}, Stderr: &stderr, Getenv: func(k string) string {
		return map[string]string{"HOME": "/home/alice", "SUDO_USER": "alice", "SUDO_UID": "1000"}[k]
	}, HomeOf: func(int) (string, error) { return dir, nil }}
	e := &env{app: app, g: &globals{}, p: &printer{out: app.Stdout, err: app.Stderr}}
	st, err := e.store()
	if err != nil || st.dir != filepath.Join(dir, ".config", "agentgate") || !strings.Contains(stderr.String(), "not the directory HOME") {
		t.Fatalf("store %q %v, stderr %q", st.dir, err, stderr.String())
	}
}

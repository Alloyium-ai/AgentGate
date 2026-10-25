// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fakeSecret = "sk-test-FAKE-cmd-0123456789abcdefXYZ"

type files struct {
	dir, config, secret string
}

func setup(t *testing.T, mutate func(m map[string]any)) files {
	t.Helper()
	dir := t.TempDir()
	f := files{dir: dir, config: filepath.Join(dir, "broker.json"), secret: filepath.Join(dir, "anthropic.secret")}
	if err := os.WriteFile(f.secret, []byte(fakeSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := map[string]any{
		"version": "agentgate.broker.v2", "launch_id": "lch-cmd", "target_id": "local",
		"deadline":   time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		"listen":     map[string]any{"network": "tcp", "address": "10.251.77.2", "port": 18443, "subnet": "10.251.77.0/29"},
		"stats_path": filepath.Join(dir, "stats.json"),
		"run_as":     map[string]any{"uid": 65534, "gid": 65534},
		"routes": []any{map[string]any{
			"name":       "anthropic",
			"upstream":   map[string]any{"host": "api.example.test"},
			"credential": map[string]any{"secret_file": f.secret, "header": "x-api-key"},
			"rules":      []any{map[string]any{"methods": []any{"POST"}, "path": "/v1/messages", "match": "exact"}},
		}},
	}
	if mutate != nil {
		mutate(m)
	}
	raw, _ := json.Marshal(m)
	if err := os.WriteFile(f.config, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func call(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := realMain(args, &out, &errb)
	for _, s := range []string{out.String(), errb.String()} {
		for _, form := range []string{fakeSecret, base64.StdEncoding.EncodeToString([]byte(fakeSecret)), fakeSecret[:16]} {
			if strings.Contains(s, form) {
				t.Fatalf("secret leaked into command output")
			}
		}
	}
	return code, out.String(), errb.String()
}

func TestValidatePrintsTheAgentBaseURLs(t *testing.T) {
	f := setup(t, nil)
	code, out, _ := call(t, "validate", f.config)
	if code != exitOK {
		t.Fatal(code, out)
	}
	var s summary
	if err := json.Unmarshal([]byte(out), &s); err != nil {
		t.Fatal(err)
	}
	if !s.OK || !s.SecretsChecked || len(s.Routes) != 1 || s.Routes[0].BaseURL != "http://10.251.77.2:18443/anthropic" ||
		s.Routes[0].Upstream != "api.example.test:443" || len(s.ConfigSHA256) != 64 || s.Listen != "tcp:10.251.77.2:18443" {
		t.Fatalf("%+v", s)
	}
}

func TestValidateRefusesBadCustodyAndConfig(t *testing.T) {
	f := setup(t, nil)
	os.Chmod(f.config, 0o664)
	if code, _, _ := call(t, "validate", f.config); code != exitConfig {
		t.Fatal("group-writable config accepted", code)
	}
	os.Chmod(f.config, 0o600)
	link := filepath.Join(f.dir, "link.json")
	os.Symlink(f.config, link)
	if code, _, _ := call(t, "validate", link); code != exitConfig {
		t.Fatal("symlinked config accepted", code)
	}
	os.Chmod(f.secret, 0o644)
	if code, out, _ := call(t, "validate", f.config); code != exitSecret || !strings.Contains(out, "custody") {
		t.Fatal("exposed secret accepted", code, out)
	}
	if code, _, _ := call(t, "validate", "--skip-secrets", f.config); code != exitOK {
		t.Fatal("skip-secrets", code)
	}
	bad := setup(t, func(m map[string]any) { m["listen"].(map[string]any)["address"] = "0.0.0.0" })
	if code, out, _ := call(t, "validate", bad.config); code != exitConfig || !strings.Contains(out, "listen.address") {
		t.Fatal(code, out)
	}
	expired := setup(t, func(m map[string]any) { m["deadline"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339) })
	if code, _, _ := call(t, "validate", expired.config); code != exitConfig {
		t.Fatal("expired deadline accepted", code)
	}
}

func TestRunFailsClosed(t *testing.T) {
	f := setup(t, nil)
	// No interface on this machine carries the configured broker address.
	if code, _, errs := call(t, "run", f.config); code != exitListen || !strings.Contains(errs, "listen address") {
		t.Fatal(code, errs)
	}
	if code, _, _ := call(t, "run", "--config-sha256", strings.Repeat("0", 64), f.config); code != exitConfig {
		t.Fatal("digest mismatch accepted", code)
	}
	os.Chmod(f.secret, 0o640)
	if code, _, _ := call(t, "run", f.config); code != exitSecret {
		t.Fatal("exposed secret accepted", code)
	}
	if code, _, _ := call(t, "run", "--unknown", f.config); code != exitUsage {
		t.Fatal(code)
	}
	if code, _, _ := call(t, "run"); code != exitUsage {
		t.Fatal(code)
	}
	if code, _, _ := call(t, "bogus"); code != exitUsage {
		t.Fatal(code)
	}
	if code, out, _ := call(t, "version"); code != exitOK || !strings.HasPrefix(out, "agentgate-broker ") {
		t.Fatal(code, out)
	}
	if _, err := os.Stat(filepath.Join(f.dir, "stats.json")); err == nil {
		t.Fatal("a refused run wrote stats as if it had served")
	}
}

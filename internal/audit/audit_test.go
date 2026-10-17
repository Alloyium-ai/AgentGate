// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/grant"
	"alloyium.local/kernel-poc/internal/kernel"
)

func fixture(t *testing.T, lost uint64) (string, grant.Keys) {
	t.Helper()
	root := t.TempDir()
	keydir := filepath.Join(root, "keys")
	if err := grant.Init(keydir); err != nil {
		t.Fatal(err)
	}
	keys, err := grant.Load(keydir)
	if err != nil {
		t.Fatal(err)
	}
	c := grant.Claims{Issuer: grant.Issuer, Audience: grant.Audience, Deployment: "disposable-dev-poc", Node: "node", Boot: "boot", Run: "run", Domain: "42", Agent: "worker", AgentKey: keys.Trust.Agent, JobDigest: grant.Digest([]byte("job")), Generation: "1", Workspace: "/var/lib/poc/workspace/", Endpoint: "127.0.0.1:18081", DeadlineNS: "9007199254740993", Issued: time.Now().Unix(), Expires: time.Now().Unix() + 30, Nonce: strings.Repeat("a", 32)}
	token, err := grant.Sign(c, keys.Authority)
	if err != nil {
		t.Fatal(err)
	}
	events := []kernel.Event{{Sequence: 1, Generation: 1, Cgroup: 42, MonoNS: 9007199254740993, PID: 50, UID: 65534, Hook: 1, Allowed: 1}, {Sequence: 2, Generation: 1, Cgroup: 42, PID: 51, UID: 65534, Hook: 2}}
	dir := filepath.Join(root, "run")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = Save(dir, token, c, events, kernel.Counters{Decisions: 2 + lost, Lost: lost}, keys, "object-hash", "completed"); err != nil {
		t.Fatal(err)
	}
	return dir, keys
}

func TestCompleteRetainedEvidence(t *testing.T) {
	dir, keys := fixture(t, 0)
	result, err := Verify(dir, keys.Trust)
	if err != nil || result != Complete {
		t.Fatalf("%s: %v", result, err)
	}
}

func TestEvidenceFailures(t *testing.T) {
	tests := map[string]struct {
		mutate func(string)
		want   string
	}{
		"byte-mutation": {func(dir string) {
			p := filepath.Join(dir, "events.jsonl")
			b, _ := os.ReadFile(p)
			b = []byte(strings.Replace(string(b), `"uid":65534`, `"uid":65533`, 1))
			os.WriteFile(p, b, 0600)
		}, Tampered},
		"suffix-deletion": {func(dir string) {
			p := filepath.Join(dir, "events.jsonl")
			b, _ := os.ReadFile(p)
			lines := strings.Split(string(b), "\n")
			os.WriteFile(p, []byte(lines[0]+"\n"), 0600)
		}, Incomplete},
		"terminal-missing": {func(dir string) { os.Remove(filepath.Join(dir, "terminal.json")) }, Incomplete},
		"truncated-entry": {func(dir string) {
			p := filepath.Join(dir, "events.jsonl")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, b[:len(b)-5], 0600)
		}, Incomplete},
		"cross-generation": {func(dir string) {
			p := filepath.Join(dir, "events.jsonl")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, []byte(strings.Replace(string(b), `"generation":"1"`, `"generation":"2"`, 1)), 0600)
		}, Tampered},
		"seal-mutation": {func(dir string) {
			p := filepath.Join(dir, "terminal.json")
			b, _ := os.ReadFile(p)
			os.WriteFile(p, []byte(strings.Replace(string(b), `"lost":"0"`, `"lost":"1"`, 1)), 0600)
		}, Tampered},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			dir, keys := fixture(t, 0)
			test.mutate(dir)
			result, err := Verify(dir, keys.Trust)
			if err == nil || result != test.want {
				t.Fatalf("%s: %v; want %s", result, err, test.want)
			}
		})
	}
}

func TestRecordedLoss(t *testing.T) {
	dir, keys := fixture(t, 3)
	result, err := Verify(dir, keys.Trust)
	if err == nil || result != Incomplete {
		t.Fatalf("%s: %v", result, err)
	}
}

func TestUntrustedKeys(t *testing.T) {
	dir, keys := fixture(t, 0)
	keys.Trust.Node = "invalid"
	result, err := Verify(dir, keys.Trust)
	if err == nil || result != UnknownKey {
		t.Fatalf("%s: %v", result, err)
	}
}

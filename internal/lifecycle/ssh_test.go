// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"strings"
	"testing"
)

func sshManifest() Manifest {
	return Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "ssh", RuntimeVersion: "shell-v1", Executable: "/usr/bin/dash", ExecutableDigest: strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), Arguments: []string{"-c", "printf '%s' hello"}, Workspace: "/var/lib/agentgate/workspace", Environment: map[string]string{}, InputDigest: SSHEmptyInputDigest}
}

func TestSSHManifestBindsExactShellCommand(t *testing.T) {
	m := sshManifest()
	base, err := m.Digest()
	if err != nil || !SSHRuntimeMatches([]string{"-c"}, m) {
		t.Fatalf("valid SSH command rejected: %v", err)
	}
	m.Arguments[1] += "!"
	changed, err := m.Digest()
	if err != nil || base == changed {
		t.Fatal("changed SSH command retained the job digest")
	}
	if SSHRuntimeMatches([]string{"-c", "extra"}, m) {
		t.Fatal("an unpinned shell prefix passed")
	}
}

func TestSSHManifestRejectsOtherExecutionContracts(t *testing.T) {
	cases := map[string]func(*Manifest){
		"direct-exec":           func(m *Manifest) { m.Arguments = []string{"printf", "hello"} },
		"shell-prefix":          func(m *Manifest) { m.Arguments = []string{"-lc", "echo hello"} },
		"empty":                 func(m *Manifest) { m.Arguments[1] = "" },
		"oversized":             func(m *Manifest) { m.Arguments[1] = strings.Repeat("x", SSHCommandMaxBytes+1) },
		"input":                 func(m *Manifest) { m.InputDigest = strings.Repeat("a", 64) },
		"environment":           func(m *Manifest) { m.Environment["TOKEN"] = "untrusted" },
		"null":                  func(m *Manifest) { m.Arguments[1] = "echo\x00bad" },
		"invalid-utf8-decoding": func(m *Manifest) { m.Arguments[1] = "echo \ufffd" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			m := sshManifest()
			change(&m)
			if m.Validate() == nil || SSHRuntimeMatches([]string{"-c"}, m) {
				t.Fatal("changed SSH contract passed")
			}
		})
	}
}

func TestSSHManifestSignsOnlyConfiguredToolchainEnvironment(t *testing.T) {
	m := sshManifest()
	m.Environment = map[string]string{"PATH": "/usr/bin:/bin", "HOME": m.Workspace, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"}
	base, err := m.Digest()
	if err != nil {
		t.Fatal(err)
	}
	m.Environment["PATH"] = "/usr/bin"
	if m.Validate() == nil {
		t.Fatal("changed toolchain path passed")
	}
	m.Environment["PATH"] = "/usr/bin:/bin"
	delete(m.Environment, "LANG")
	changed, err := m.Digest()
	if err != nil || changed == base {
		t.Fatal("the signed environment did not change the job digest", err)
	}
	for key, value := range map[string]string{"LD_PRELOAD": "/work/lib.so", "TOKEN": "secret", "HOME": "/root"} {
		m := sshManifest()
		m.Environment[key] = value
		if m.Validate() == nil {
			t.Fatal("untrusted environment passed", key)
		}
	}
}

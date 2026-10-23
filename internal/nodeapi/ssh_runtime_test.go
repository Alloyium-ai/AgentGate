// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSSHRuntimeRequiresExactEnrollmentAndShellPrefix(t *testing.T) {
	set, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil {
		t.Fatal(err)
	}
	runtime := RuntimeArtifact{Version: "shell-v1", Executable: "/usr/bin/dash", ExecutableDigest: strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), ArgumentsPrefix: []string{"-c"}, Files: set.Files(), FilesDigest: set.Digest()}
	m := lifecycle.Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "ssh", RuntimeVersion: runtime.Version, Executable: runtime.Executable, ExecutableDigest: runtime.ExecutableDigest, ImageDigest: runtime.ImageDigest, Arguments: []string{"-c", "echo safe"}, Workspace: "/var/lib/agentgate/workspace", Environment: map[string]string{}, InputDigest: lifecycle.SSHEmptyInputDigest}
	binding := lifecycle.Binding{ArtifactDigests: map[string]string{"runtime.ssh.files": set.Digest()}}
	enrollment := Enrollment{Runtimes: map[string]RuntimeArtifact{"ssh": runtime}}
	if !runtimeMatches(enrollment, m, binding) {
		t.Fatal("exact enrolled shell rejected")
	}
	runtime.ArgumentsPrefix = []string{"-lc"}
	enrollment.Runtimes["ssh"] = runtime
	if runtimeMatches(enrollment, m, binding) {
		t.Fatal("different shell prefix passed enrollment")
	}
	runtime.ArgumentsPrefix = []string{"-c"}
	enrollment.Runtimes["ssh"] = runtime
	m.Environment["LD_PRELOAD"] = "/host/lib.so"
	if runtimeMatches(enrollment, m, binding) {
		t.Fatal("loader environment passed enrollment")
	}
	delete(m.Environment, "LD_PRELOAD")
	m.Environment["PATH"] = "/usr/bin:/bin"
	if runtimeMatches(enrollment, m, binding) {
		t.Fatal("an unenrolled toolchain environment passed")
	}
	runtime.Environment = map[string]string{"PATH": "/usr/bin:/bin"}
	enrollment.Runtimes["ssh"] = runtime
	if !runtimeMatches(enrollment, m, binding) {
		t.Fatal("the signed and enrolled toolchain environment was rejected")
	}
	encoded, err := json.Marshal(runtime)
	if err != nil || !bytes.Contains(encoded, []byte(`"environment":{"PATH":"/usr/bin:/bin"}`)) {
		t.Fatal("the enrolled environment was absent from the wire record", err)
	}
	runtime.Environment = nil
	encoded, err = json.Marshal(runtime)
	if err != nil || bytes.Contains(encoded, []byte(`"environment"`)) {
		t.Fatal("a legacy empty enrollment changed its wire record", err)
	}
}

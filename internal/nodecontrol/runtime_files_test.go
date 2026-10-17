// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodecontrol

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"context"
	"strings"
	"testing"
)

func TestRuntimeFilesControlBindsManifestAndExactSet(t *testing.T) {
	b, _ := boundFixture()
	m := lifecycle.Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "codex", RuntimeVersion: "fixture", Executable: "/opt/agent/bin/codex", ExecutableDigest: strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), Arguments: []string{"--version"}, Workspace: "/workspace", Environment: map[string]string{}, InputDigest: strings.Repeat("c", 64)}
	b.JobDigest, _ = m.Digest()
	set, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil {
		t.Fatal(err)
	}
	measurement, err := set.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	b.ArtifactDigests["runtime.codex.files"] = set.Digest()
	p := RuntimeFiles{Manifest: m, Measurement: measurement}
	raw, err := Encode(b, "runtime_files_verified", p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decoder(b)(raw)
	if err != nil || got.ControlPhase != "runtime_files_verified" || got.Decision != nil {
		t.Fatal(got, err)
	}
	for _, mutate := range []func(*RuntimeFiles){
		func(p *RuntimeFiles) { p.Manifest.RuntimeVersion = "other" },
		func(p *RuntimeFiles) { p.Measurement.Files = nil },
		func(p *RuntimeFiles) { p.Measurement.Digest = strings.Repeat("d", 64) },
		func(p *RuntimeFiles) { p.Measurement.TotalBytes = 1 },
		func(p *RuntimeFiles) { p.Measurement.Protocol = "other" },
	} {
		changed := p
		mutate(&changed)
		if _, err := Encode(b, "runtime_files_verified", changed); err == nil {
			t.Fatal("changed runtime file proof passed")
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"testing"
)

func emptyRuntimeFilesDigest() string {
	set, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil {
		panic(err)
	}
	return set.Digest()
}
func TestRuntimeFileBindingRejectsOmissionAndLoaderSubstitution(t *testing.T) {
	r := RuntimeArtifact{Files: []runtimeclosure.File{}, FilesDigest: emptyRuntimeFilesDigest()}
	m := lifecycle.Manifest{AgentKind: "codex", Environment: map[string]string{}}
	b := lifecycle.Binding{ArtifactDigests: map[string]string{"runtime.codex.files": r.FilesDigest}}
	if !RuntimeFilesMatch(r, m, b) {
		t.Fatal("an explicit empty closure failed")
	}
	bad := r
	bad.Files = nil
	if RuntimeFilesMatch(bad, m, b) {
		t.Fatal("an omitted closure passed")
	}
	bad = r
	bad.FilesDigest = "changed"
	if RuntimeFilesMatch(bad, m, b) {
		t.Fatal("a changed closure digest passed")
	}
	for _, key := range []string{"NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"} {
		m.Environment = map[string]string{key: "substitution"}
		if RuntimeFilesMatch(r, m, b) {
			t.Fatal("a loader override passed", key)
		}
	}
	m.Environment = map[string]string{}
	delete(b.ArtifactDigests, "runtime.codex.files")
	if RuntimeFilesMatch(r, m, b) {
		t.Fatal("a missing signed closure binding passed")
	}
}

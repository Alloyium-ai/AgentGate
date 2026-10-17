// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"testing"
)

func TestAuthorityRuntimeFileBindingRejectsSubstitutions(t *testing.T) {
	f := newFixture(t)
	b, m := f.request.Prepared.Binding, f.request.Manifest
	r := RuntimePin{Files: []runtimeclosure.File{}, FilesDigest: emptyRuntimeFilesDigest()}
	if !runtimeFilesMatch(r, b, m) {
		t.Fatal("explicit static closure rejected")
	}
	bad := r
	bad.Files = nil
	if runtimeFilesMatch(bad, b, m) {
		t.Fatal("omitted closure passed")
	}
	bad = r
	bad.FilesDigest = "changed"
	if runtimeFilesMatch(bad, b, m) {
		t.Fatal("changed digest passed")
	}
	for _, key := range []string{"NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"} {
		m.Environment = map[string]string{key: "substitution"}
		if runtimeFilesMatch(r, b, m) {
			t.Fatal("loader substitution passed", key)
		}
	}
	m.Environment = map[string]string{}
	b.ArtifactDigests = copyArtifacts(b.ArtifactDigests)
	delete(b.ArtifactDigests, "runtime.codex.files")
	if runtimeFilesMatch(r, b, m) {
		t.Fatal("missing binding passed")
	}
}

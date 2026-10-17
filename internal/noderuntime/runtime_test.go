// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func runtimeHash(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func TestPiStageMeasuresTheActualScriptAndPackage(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	node := filepath.Join(root, "node")
	pkg := filepath.Join(root, "package")
	entry := filepath.Join(pkg, "cli.js")
	if err := os.Mkdir(pkg, 0755); err != nil {
		t.Fatal(err)
	}
	native := runtimeELFFixture("")
	if err := os.WriteFile(node, native, 0555); err != nil {
		t.Fatal(err)
	}
	script := []byte("owned Pi fixture")
	if err := os.WriteFile(entry, script, 0444); err != nil {
		t.Fatal(err)
	}
	packageDigest, err := jobartifacts.DigestTree(ctx, pkg)
	if err != nil {
		t.Fatal(err)
	}
	emptyFiles, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil {
		t.Fatal(err)
	}
	r := nodeapi.RuntimeArtifact{Files: []runtimeclosure.File{}, FilesDigest: emptyFiles.Digest(), Version: "fixture", Executable: node, ExecutableDigest: runtimeHash(native), ImageDigest: "sha256:" + runtimeHash(nil), ArgumentsPrefix: []string{entry, "--print"}, EntryScript: entry, EntryScriptDigest: runtimeHash(script), PackageRoot: pkg, PackageDigest: packageDigest}
	s := &Sources{enrollments: map[string]nodeapi.Enrollment{"agent": {AgentID: "agent", Enabled: true, Runtimes: map[string]nodeapi.RuntimeArtifact{"pi": r}}}}
	b := lifecycle.Binding{AgentID: "agent", ArtifactDigests: map[string]string{"runtime.pi.entry": r.EntryScriptDigest, "runtime.pi.package": r.PackageDigest, "runtime.pi.files": r.FilesDigest}}
	m := lifecycle.Manifest{AgentKind: "pi", RuntimeVersion: r.Version, Executable: r.Executable, ExecutableDigest: r.ExecutableDigest, ImageDigest: r.ImageDigest, Arguments: append([]string{}, r.ArgumentsPrefix...), Environment: map[string]string{}}
	if err = s.VerifyRuntime(ctx, b, m); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*lifecycle.Manifest){func(m *lifecycle.Manifest) { m.Arguments = []string{"-e", "fake"} }, func(m *lifecycle.Manifest) { m.Arguments = append(m.Arguments, "--extension", "other.js") }, func(m *lifecycle.Manifest) { m.Environment["NODE_OPTIONS"] = "--require other.js" }} {
		bad := clone(m)
		change(&bad)
		if s.VerifyRuntime(ctx, b, bad) == nil {
			t.Fatal("a different Pi entry path was accepted")
		}
	}
	if err = os.WriteFile(entry, []byte("changed bytes"), 0444); err != nil {
		t.Fatal(err)
	}
	if s.VerifyRuntime(ctx, b, m) == nil {
		t.Fatal("changed script bytes were accepted")
	}
}

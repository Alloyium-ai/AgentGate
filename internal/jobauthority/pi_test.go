// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPiAuthorityRequiresExactRuntimeCustody(t *testing.T) {
	f := newFixture(t)
	cases := map[string]func(*RuntimePin, *lifecycle.Manifest, *lifecycle.Binding){
		"missing-argv":           func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) { r.ArgumentsPrefix = nil },
		"missing-entry":          func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) { r.EntryScript = "" },
		"missing-entry-digest":   func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) { r.EntryScriptDigest = "" },
		"missing-package":        func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) { r.PackageRoot = "" },
		"missing-package-digest": func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) { r.PackageDigest = "" },
		"node-e": func(_ *RuntimePin, m *lifecycle.Manifest, _ *lifecycle.Binding) {
			m.Arguments = []string{"-e", "process.exit(0)"}
		},
		"extra-extension-suffix": func(_ *RuntimePin, m *lifecycle.Manifest, _ *lifecycle.Binding) {
			m.Arguments = append(m.Arguments, "--extension", "/other/extension.js")
		},
		"different-first-argument": func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) {
			r.ArgumentsPrefix[0] = "/other/cli.js"
		},
		"entry-outside-package": func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) {
			r.EntryScript = "/other/cli.js"
			r.ArgumentsPrefix[0] = r.EntryScript
		},
		"entry-equals-package": func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) {
			r.EntryScript = r.PackageRoot
			r.ArgumentsPrefix[0] = r.EntryScript
		},
		"sibling-package-prefix": func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) {
			r.EntryScript = "/immutable/pi-other/cli.js"
			r.ArgumentsPrefix[0] = r.EntryScript
		},
		"root-package":      func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) { r.PackageRoot = "/" },
		"temporary-package": func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) { r.PackageRoot = "/tmp/pi" },
		"unclean-package":   func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) { r.PackageRoot = "/immutable/./pi" },
		"null-entry":        func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) { r.EntryScript += "\x00" },
		"null-argument":     func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) { r.ArgumentsPrefix[1] += "\x00" },
		"uppercase-entry-digest": func(r *RuntimePin, _ *lifecycle.Manifest, _ *lifecycle.Binding) {
			r.EntryScriptDigest = strings.Repeat("A", 64)
		},
		"wrong-entry-binding": func(_ *RuntimePin, _ *lifecycle.Manifest, b *lifecycle.Binding) {
			b.ArtifactDigests["runtime.pi.entry"] = strings.Repeat("0", 64)
		},
		"wrong-package-binding": func(_ *RuntimePin, _ *lifecycle.Manifest, b *lifecycle.Binding) {
			b.ArtifactDigests["runtime.pi.package"] = strings.Repeat("0", 64)
		},
	}
	for _, key := range piLoaderEnvironment {
		key := key
		cases["loader-"+key] = func(_ *RuntimePin, m *lifecycle.Manifest, _ *lifecycle.Binding) { m.Environment[key] = "override" }
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r, m, b := piFixture(f)
			change(&r, &m, &b)
			if piTrust(r, b).VerifyManifest(context.Background(), b, m) == nil {
				t.Fatal("uncontrolled Pi runtime accepted")
			}
		})
	}
	r, m, b := piFixture(f)
	if e := piTrust(r, b).VerifyManifest(context.Background(), b, m); e != nil {
		t.Fatal("exact enrolled Pi runtime rejected", e)
	}
	for _, key := range piLoaderEnvironment {
		m.Environment[key] = ""
	}
	if e := piTrust(r, b).VerifyManifest(context.Background(), b, m); e != nil {
		t.Fatal("empty loader variables rejected", e)
	}
}
func piFixture(f *testFixture) (RuntimePin, lifecycle.Manifest, lifecycle.Binding) {
	b := f.request.Prepared.Binding
	b.ArtifactDigests = copyArtifacts(b.ArtifactDigests)
	m := f.request.Manifest
	m.AgentKind = "pi"
	m.Executable = "/immutable/node"
	m.Arguments = []string{"/immutable/pi/dist/cli.js", "--mode", "fixture"}
	m.Environment = map[string]string{}
	r := RuntimePin{Kind: "pi", Version: m.RuntimeVersion, Executable: m.Executable, ExecutableDigest: m.ExecutableDigest, ImageDigest: m.ImageDigest, ArgumentsPrefix: append([]string{}, m.Arguments...), EntryScript: m.Arguments[0], EntryScriptDigest: strings.Repeat("a", 64), PackageRoot: "/immutable/pi", PackageDigest: strings.Repeat("b", 64)}
	r.Files = []runtimeclosure.File{}
	r.FilesDigest = emptyRuntimeFilesDigest()
	b.ArtifactDigests["runtime.pi.files"] = r.FilesDigest
	b.ArtifactDigests["runtime.pi.entry"] = r.EntryScriptDigest
	b.ArtifactDigests["runtime.pi.package"] = r.PackageDigest
	b.JobDigest, _ = m.Digest()
	return r, m, b
}
func piTrust(r RuntimePin, b lifecycle.Binding) *FileTrust {
	return &FileTrust{TrustFile{Enrollments: []EnrollmentPin{{AgentID: b.AgentID, AgentKey: b.AgentKey, NodeID: b.NodeID, BootID: b.BootID, PolicyDigests: []string{b.PolicyDigest}, Runtimes: []RuntimePin{r}}}, Targets: map[string]TargetPin{b.NodeID: {BootID: b.BootID, CompilerDigest: b.CompilerDigest, ArtifactDigests: copyArtifacts(b.ArtifactDigests)}}}}
}

func TestPiTrustConfigurationRejectsMissingPins(t *testing.T) {
	f := newFixture(t)
	r, _, b := piFixture(f)
	r.PackageDigest = ""
	config := piTrust(r, b).config
	config.Protocol = "agentgate.authority-config.v1"
	config.MaxLifetimeSeconds = 60
	config.Subjects = map[string]SubjectPin{b.AgentID: {Role: "agent", PublicKey: b.AgentKey}, b.NodeID: {Role: "node", PublicKey: base64.RawURLEncoding.EncodeToString(f.node.Public().(ed25519.PublicKey))}}
	config.Documents = map[string]string{b.PolicyDigest: "/protected/document.json"}
	raw, e := json.Marshal(config)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(f.dir, "missing-pi.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = LoadTrust(path); e == nil || e.Error() != "authority_pi_runtime_pins_required" {
		t.Fatal("unmeasured Pi enrollment loaded", e)
	}
}

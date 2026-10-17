// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"strings"
	"testing"
)

func TestPiEnrollmentBindsScriptPackageAndArgumentPrefix(t *testing.T) {
	runtime := RuntimeArtifact{Version: "0.81.1", Executable: "/opt/agent/node", ExecutableDigest: strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), ArgumentsPrefix: []string{"/opt/agent/pi/node_modules/@earendil-works/pi-coding-agent/dist/cli.js", "--mode", "json", "-p", "--no-session"}, EntryScript: "/opt/agent/pi/node_modules/@earendil-works/pi-coding-agent/dist/cli.js", EntryScriptDigest: strings.Repeat("c", 64), PackageRoot: "/opt/agent/pi", PackageDigest: strings.Repeat("d", 64)}
	runtime.Files = []runtimeclosure.File{}
	runtime.FilesDigest = emptyRuntimeFilesDigest()
	runtime.ArgumentsPrefix = append(runtime.ArgumentsPrefix, "--model", "reviewed-model")
	manifest := lifecycle.Manifest{AgentKind: "pi", RuntimeVersion: runtime.Version, Executable: runtime.Executable, ExecutableDigest: runtime.ExecutableDigest, ImageDigest: runtime.ImageDigest, Arguments: append([]string{}, runtime.ArgumentsPrefix...)}
	binding := lifecycle.Binding{ArtifactDigests: map[string]string{"runtime.pi.entry": runtime.EntryScriptDigest, "runtime.pi.package": runtime.PackageDigest, "runtime.pi.files": runtime.FilesDigest}}
	enrollment := Enrollment{Runtimes: map[string]RuntimeArtifact{"pi": runtime}}
	if !runtimeMatches(enrollment, manifest, binding) {
		t.Fatal("the exact enrolled Pi script and package must match")
	}
	for _, name := range []string{"eval", "node-option", "other-script", "prefix", "entry-digest", "package-digest", "outside-root", "missing-enrollment", "extension-suffix", "NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"} {
		t.Run(name, func(t *testing.T) {
			m := manifest
			m.Arguments = append([]string{}, manifest.Arguments...)
			r := runtime
			r.ArgumentsPrefix = append([]string{}, runtime.ArgumentsPrefix...)
			b := binding
			b.ArtifactDigests = map[string]string{"runtime.pi.entry": runtime.EntryScriptDigest, "runtime.pi.package": runtime.PackageDigest, "runtime.pi.files": runtime.FilesDigest}
			switch name {
			case "eval":
				m.Arguments = []string{"-e", "console.log('not pi')"}
			case "node-option":
				m.Arguments = append([]string{"--import", "/other/loader.js"}, m.Arguments...)
			case "other-script":
				m.Arguments[0] = "/opt/agent/pi/other.js"
			case "prefix":
				m.Arguments[2] = "rpc"
			case "entry-digest":
				delete(b.ArtifactDigests, "runtime.pi.entry")
			case "package-digest":
				b.ArtifactDigests["runtime.pi.package"] = strings.Repeat("e", 64)
			case "outside-root":
				r.PackageRoot = "/opt/other"
			case "missing-enrollment":
				r.EntryScript = ""
				r.PackageDigest = ""
			case "extension-suffix":
				m.Arguments = append(m.Arguments, "--extension", "/work/other.js")
			default:
				m.Environment = map[string]string{name: "/work/other.js"}
			}
			if runtimeMatches(Enrollment{Runtimes: map[string]RuntimeArtifact{"pi": r}}, m, b) {
				t.Fatal("an unpinned or substituted Pi entrypoint matched")
			}
		})
	}
}

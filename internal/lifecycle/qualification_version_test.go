// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"path/filepath"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"alloyium.local/kernel-poc/internal/testpolicy"
)

func versionSpec(t *testing.T) QualificationVersionSpec {
	t.Helper()
	b := fixtureBinding()
	b.SchemaDigest = policy.SchemaDigest()
	b.ArtifactDigests["runtime.codex"] = QualificationVersionSHA256
	b.ArtifactDigests["held-helper"] = strings.Repeat("3", 64)
	files, _ := runtimeclosure.New([]runtimeclosure.File{})
	b.ArtifactDigests["runtime.codex.files"] = files.Digest()
	m := Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "codex", RuntimeVersion: QualificationVersionRuntime, Executable: QualificationVersionExecutable, ExecutableDigest: QualificationVersionSHA256, ImageDigest: "sha256:" + strings.Repeat("4", 64), Arguments: []string{"--version"}, Environment: map[string]string{}, Workspace: "/var/lib/kernel-poc-qualification-version-unit", InputDigest: versionInputDigest()}
	b.JobDigest, _ = m.Digest()
	s := QualificationVersionSpec{Binding: b, Manifest: m, OwnedRoot: m.Workspace, SourceRevision: strings.Repeat("7", 40), TargetDigest: strings.Repeat("6", 64)}
	d := testpolicy.Deny()
	d.Lifecycle.DurationSeconds = 30
	d.Runtime.Seccomp.AllowSyscalls = []string{"read", "write", "close", "openat", "fstat", "dup2", "execve", "exit_group", "mmap", "mprotect", "munmap", "brk"}
	d.Runtime.Memory = &policy.MemoryPolicy{Default: "deny", Anonymous: []string{"map", "read", "write", "protect"}, Heap: "allow"}
	d.Runtime.Bootstrap = &policy.BootstrapPolicy{Profile: "measured-held-exec.v1", HelperDigest: b.ArtifactDigests["held-helper"], Operations: []string{"barrier_read", "listener_send", "filter_finalize", "working_directory"}, MaxHoldSeconds: 10}
	d.Programs.Rules = []policy.ProgramRule{{ID: "native-exec", Selector: policy.Selector{Kind: "exact", Path: m.Executable}, Effect: "allow"}}
	d.Files.Rules = []policy.FileRule{{ID: "native-image", Selector: policy.Selector{Kind: "exact", Path: m.Executable}, Operations: []string{"read", "mmap", "map_execute", "mprotect"}, Effect: "allow"}}
	for path, ops := range versionStreams(s) {
		d.Files.Rules = append(d.Files.Rules, policy.FileRule{ID: "stream-" + filepath.Base(path), Selector: policy.Selector{Kind: "exact", Path: path}, Operations: ops, Effect: "allow"})
	}
	var err error
	d.RequiredCapabilities, err = policy.Requirements(d)
	if err != nil {
		t.Fatal(err)
	}
	s.Binding.PolicyDigest, err = d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	s.CandidateDigest = s.Binding.PolicyDigest
	s.Document, err = d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNativeVersionScopeRejectsOtherCommandsAndChangedCandidate(t *testing.T) {
	s := versionSpec(t)
	if _, err := QualificationVersionScopeDigest(s); err != nil {
		t.Fatal(err)
	}
	if _, err := QualificationFixtureScopeDigest(QualificationFixtureSpec(s)); err == nil {
		t.Fatal("the native version borrowed the fixed worker permit")
	}
	for name, change := range map[string]func(*QualificationVersionSpec){
		"model argv":          func(s *QualificationVersionSpec) { s.Manifest.Arguments = []string{"exec", "prompt"} },
		"additional argv":     func(s *QualificationVersionSpec) { s.Manifest.Arguments = append(s.Manifest.Arguments, "ignored") },
		"different image":     func(s *QualificationVersionSpec) { s.Manifest.ExecutableDigest = strings.Repeat("9", 64) },
		"environment":         func(s *QualificationVersionSpec) { s.Manifest.Environment["OPENAI_API_KEY"] = "forbidden" },
		"nonempty input":      func(s *QualificationVersionSpec) { s.Manifest.InputDigest = fixtureInputDigest('T') },
		"different candidate": func(s *QualificationVersionSpec) { s.CandidateDigest = strings.Repeat("9", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			s := clone(s)
			change(&s)
			s.Binding.JobDigest, _ = s.Manifest.Digest()
			if validateVersionSpec(s) == nil {
				t.Fatal("an unrelated version scope passed")
			}
		})
	}
}

func TestNativeVersionScopeRejectsCredentialsNetworkAndExtraRights(t *testing.T) {
	for _, name := range []string{"private-key", "network-call", "other-exec", "anonymous-execute", "long-lived"} {
		t.Run(name, func(t *testing.T) {
			s := versionSpec(t)
			d, err := policy.Parse(s.Document, "json")
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "private-key":
				d.Files.Rules = append(d.Files.Rules, policy.FileRule{ID: "secret", Selector: policy.Selector{Kind: "exact", Path: s.OwnedRoot + "/node.key"}, Operations: []string{"read"}, Effect: "allow"})
			case "network-call":
				d.Runtime.Seccomp.AllowSyscalls = append(d.Runtime.Seccomp.AllowSyscalls, "socket")
			case "other-exec":
				d.Programs.Rules[0].Selector.Path = "/bin/sh"
			case "anonymous-execute":
				d.Runtime.Memory.Anonymous = append(d.Runtime.Memory.Anonymous, "execute")
			case "long-lived":
				d.Lifecycle.DurationSeconds = 31
			}
			d.RequiredCapabilities, _ = policy.Requirements(d)
			s.Binding.PolicyDigest, _ = d.Digest()
			s.CandidateDigest = s.Binding.PolicyDigest
			s.Document, _ = d.Canonical()
			if validateVersionSpec(s) == nil {
				t.Fatal("an unrelated permission entered the native version fixture")
			}
		})
	}
}

func TestVersionPurposeCannotBorrowFixedManagerOrCapabilities(t *testing.T) {
	s := versionSpec(t)
	p := &QualificationFixturePermit{spec: QualificationFixtureSpec(s), digest: strings.Repeat("8", 64), purpose: QualificationVersionPurpose}
	if _, err := NewQualificationFixtureManager(nil, nil, nil, nil, Identity{}, 0, nil, nil, p); err == nil {
		t.Fatal("the version purpose entered the fixed worker manager")
	}
	b := s.Binding
	b.CgroupID = 42
	if err := p.Resolve(b); err != nil {
		t.Fatal(err)
	}
	e := Evidence{Binding: b, FixturePurpose: QualificationVersionPurpose, Capabilities: map[string]Capability{"fs.rules.v1": {State: "fixture-only", Mechanisms: []string{QualificationVersionPurpose}, EvidenceDigest: p.Digest()}}}
	if err := p.CheckCapabilities(e, []string{"fs.rules.v1"}); err != nil {
		t.Fatal(err)
	}
	if (&Manager{}).checkCapabilities(e, []string{"fs.rules.v1"}) == nil {
		t.Fatal("the version fixture entered normal admission")
	}
	e.FixturePurpose = QualificationFixturePurpose
	if p.CheckCapabilities(e, []string{"fs.rules.v1"}) == nil {
		t.Fatal("a different fixture purpose borrowed the version permit")
	}
}

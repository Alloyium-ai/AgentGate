// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/testpolicy"
	"encoding/json"
	"strings"
	"testing"
)

func qualificationSpec(t *testing.T) QualificationFixtureSpec {
	t.Helper()
	b := fixtureBinding()
	b.SchemaDigest = policy.SchemaDigest()
	b.ArtifactDigests["qualification-lifecycle-worker"] = strings.Repeat("2", 64)
	b.ArtifactDigests["held-helper"] = strings.Repeat("3", 64)
	m := Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "codex", RuntimeVersion: QualificationFixtureRuntime, Executable: "/var/lib/kernel-poc-qualification-unit/qualification-lifecycle-worker", ExecutableDigest: b.ArtifactDigests["qualification-lifecycle-worker"], ImageDigest: "sha256:" + strings.Repeat("4", 64), Arguments: []string{}, Environment: map[string]string{}, Workspace: "/var/lib/kernel-poc-qualification-unit", InputDigest: fixtureInputDigest('T')}
	b.JobDigest, _ = m.Digest()
	d := testpolicy.Deny()
	d.Runtime.Seccomp.AllowSyscalls = []string{"read", "write", "close", "openat", "fstat", "dup2", "execve", "exit_group", "getpid", "getppid", "clone", "futex"}
	d.Runtime.Bootstrap = &policy.BootstrapPolicy{Profile: "measured-held-exec.v1", HelperDigest: b.ArtifactDigests["held-helper"], Operations: []string{"barrier_read", "listener_send", "filter_finalize", "working_directory"}, MaxHoldSeconds: 10}
	d.Programs.Rules = []policy.ProgramRule{{ID: "worker", Selector: policy.Selector{Kind: "exact", Path: m.Executable}, Effect: "allow"}}
	d.Files.Rules = []policy.FileRule{{ID: "input", Selector: policy.Selector{Kind: "exact", Path: m.Workspace + "/input"}, Operations: []string{"read"}, Effect: "allow"}}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	b.PolicyDigest, _ = d.Digest()
	raw, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return QualificationFixtureSpec{Binding: b, Manifest: m, Document: raw, CandidateDigest: strings.Repeat("5", 64), TargetDigest: strings.Repeat("6", 64), SourceRevision: strings.Repeat("7", 40), OwnedRoot: m.Workspace}
}
func TestFixedQualificationPermitRejectsGeneralExecution(t *testing.T) {
	spec := qualificationSpec(t)
	if err := validateFixtureSpec(spec); err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*QualificationFixtureSpec){
		"agent":        func(s *QualificationFixtureSpec) { s.Manifest.AgentKind = "claude" },
		"argv":         func(s *QualificationFixtureSpec) { s.Manifest.Arguments = []string{"--untrusted"} },
		"environment":  func(s *QualificationFixtureSpec) { s.Manifest.Environment["LD_PRELOAD"] = "/untrusted" },
		"worker":       func(s *QualificationFixtureSpec) { s.Manifest.Executable = "/var/lib/other" },
		"root":         func(s *QualificationFixtureSpec) { s.OwnedRoot = "/var/lib/production" },
		"schema":       func(s *QualificationFixtureSpec) { s.Binding.SchemaDigest = strings.Repeat("0", 64) },
		"input":        func(s *QualificationFixtureSpec) { s.Manifest.InputDigest = fixtureInputDigest('X') },
		"source":       func(s *QualificationFixtureSpec) { s.SourceRevision = strings.Repeat("z", 40) },
		"preallocated": func(s *QualificationFixtureSpec) { s.Binding.CgroupID = 42 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			s := clone(spec)
			change(&s)
			if validateFixtureSpec(s) == nil {
				t.Fatal("general execution obtained a fixed-worker permit")
			}
		})
	}
	for _, name := range []string{"syscall", "program", "file", "memory", "worker-write"} {
		t.Run(name, func(t *testing.T) {
			s := clone(spec)
			d, err := policy.Parse(s.Document, "json")
			if err != nil {
				t.Fatal(err)
			}
			switch name {
			case "syscall":
				d.Runtime.Seccomp.AllowSyscalls = append(d.Runtime.Seccomp.AllowSyscalls, "socket")
			case "program":
				d.Programs.Rules[0].Selector.Path = "/var/lib/another-program"
			case "file":
				d.Files.Rules[0].Selector.Path = "/etc/passwd"
			case "worker-write":
				d.Files.Rules[0].Selector.Path = s.Manifest.Executable
				d.Files.Rules[0].Operations = []string{"write"}
			case "memory":
				d.Runtime.Memory = &policy.MemoryPolicy{Default: "deny", Anonymous: []string{}, Heap: "allow"}
			}
			d.RequiredCapabilities, _ = policy.Requirements(d)
			s.Binding.PolicyDigest, _ = d.Digest()
			s.Document, _ = d.Canonical()
			if validateFixtureSpec(s) == nil {
				t.Fatal("an unrelated allowance obtained a fixture permit")
			}
		})
	}
}
func TestOpaqueQualificationPermitBindsOneDomainAndRejectsNormalCapabilities(t *testing.T) {
	spec := qualificationSpec(t)
	p := &QualificationFixturePermit{spec: clone(spec), digest: strings.Repeat("8", 64)}
	raw, _ := json.Marshal(p)
	var decoded QualificationFixturePermit
	if json.Unmarshal(raw, &decoded) != nil || decoded.Digest() != "" {
		t.Fatal("the opaque permit survived transport")
	}
	actual := clone(spec.Binding)
	actual.CgroupID = 42
	if p.CheckBinding(actual, false) == nil {
		t.Fatal("an unresolved domain passed")
	}
	if err := p.Resolve(actual); err != nil {
		t.Fatal(err)
	}
	if p.CheckBinding(actual, false) != nil {
		t.Fatal("the exact resolved domain failed")
	}
	changed := clone(actual)
	changed.CgroupID++
	if p.Resolve(changed) == nil || p.CheckBinding(changed, false) == nil {
		t.Fatal("a second domain borrowed the permit")
	}
	e := Evidence{Binding: actual, FixturePurpose: QualificationFixturePurpose, Capabilities: map[string]Capability{"fs.rules.v1": {State: "fixture-only", Mechanisms: []string{QualificationFixturePurpose}, EvidenceDigest: p.Digest()}}}
	if p.CheckCapabilities(e, []string{"fs.rules.v1"}) != nil {
		t.Fatal("the explicit fixture evidence failed")
	}
	if checkCapabilities(e, []string{"fs.rules.v1"}) == nil || (&Manager{}).checkCapabilities(e, []string{"fs.rules.v1"}) == nil {
		t.Fatal("fixture evidence qualified normal admission")
	}
	cap := e.Capabilities["fs.rules.v1"]
	cap.State = "qualified"
	e.Capabilities["fs.rules.v1"] = cap
	if p.CheckCapabilities(e, []string{"fs.rules.v1"}) == nil {
		t.Fatal("a fixture invented qualified capability states")
	}
}

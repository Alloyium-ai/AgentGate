// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeaudit"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func documentFixture() policy.Document {
	templates := []string{}
	extensions := map[string]json.RawMessage{}
	d := policy.Document{SchemaVersion: policy.Version, Profile: policy.KernelProfile, Defaults: &policy.Defaults{"deny", "deny", "deny"}, RuntimeTemplates: &templates, Extensions: &extensions,
		Files: &policy.Files{Defaults: policy.FileDefaults{"deny", "deny"}, Rules: []policy.FileRule{}, ResourceUse: "recheck-and-terminate"}, Programs: &policy.Programs{Default: "deny", Rules: []policy.ProgramRule{}}, Network: &policy.Network{Default: "deny", Rules: []policy.NetworkRule{}, DNS: policy.DNS{"trusted-forwarder.v1", "validate-chain", "remove-expired-authorization"}}, Sockets: &policy.SocketPolicy{Default: "deny", Rules: []policy.SocketRule{}}, Identity: &policy.Identity{"local-enrollment", true, true, true, true, "job-cgroup", "inherit"}, Runtime: &policy.Runtime{Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{}, Capabilities: []string{}, NoNewPrivileges: true, Seccomp: policy.Seccomp{"explicit-allowlist-notify.v2", "x86_64", "deny", []string{}}}, Lifecycle: &policy.Lifecycle{"baseline", 20, "restore-baseline", "terminate-job", "pinned-generation-reconcile"}, Evidence: &policy.Evidence{"node-chain-authority-batch.v1", 0, 500, 5}}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	return d
}

func put32(raw []byte, offset int, value uint32) { binary.LittleEndian.PutUint32(raw[offset:], value) }
func put64(raw []byte, offset int, value uint64) { binary.LittleEndian.PutUint64(raw[offset:], value) }
func fixture(key string) []byte {
	sizes := map[string]int{"files/files216.v1": 216, "peers/peers96.v2": 96, "sockets/sockets112.v1": 112, "custody/custody64.v1": 64, "process/process80.v1": 80, "syscalls/syscalls128.v2": 128}
	raw := make([]byte, sizes[key])
	put64(raw, 0, 1)
	switch key {
	case "files/files216.v1":
		put64(raw, 8, 3)
		put64(raw, 16, 42)
		put64(raw, 24, 1000)
	case "peers/peers96.v2":
		put64(raw, 8, 3)
		put64(raw, 16, 42)
		put64(raw, 24, 43)
		put64(raw, 32, 1000)
		put32(raw, 48, 1)
		put32(raw, 88, 2)
		put32(raw, 92, 17)
	case "sockets/sockets112.v1":
		put64(raw, 8, 3)
		put64(raw, 16, 42)
		put64(raw, 24, 43)
		put64(raw, 32, 1000)
		put32(raw, 56, 16)
		put32(raw, 88, 1)
		put32(raw, 92, 17)
	case "custody/custody64.v1":
		put64(raw, 8, 42)
		put64(raw, 24, 43)
		put64(raw, 32, 3)
		put64(raw, 40, 1000)
		put32(raw, 56, 1)
	case "process/process80.v1":
		put64(raw, 8, 42)
		put64(raw, 24, 43)
		put64(raw, 32, 3)
		put64(raw, 40, 1000)
		put32(raw, 56, 1)
		put32(raw, 72, 4)
	case "syscalls/syscalls128.v2":
		put64(raw, 8, 42)
		put64(raw, 16, 43)
		put64(raw, 24, 3)
		put64(raw, 32, 1000)
		put64(raw, 40, 500)
		put64(raw, 48, 39)
		put64(raw, 56, 99)
		put32(raw, 64, 99)
		put32(raw, 68, 99)
		put32(raw, 72, 65534)
		put32(raw, 76, 1)
		put64(raw, 104, 39)
		put32(raw, 120, 2)
		put32(raw, 124, 1)
	}
	return raw
}

type deps struct {
	document policy.Document
	snapshot jobgrant.Snapshot
	prepared lifecycle.PrepareResponse
	wall     time.Time
	reject   bool
}

func (d *deps) VerifyEnrollment(context.Context, lifecycle.Binding) error {
	if d.reject {
		return errors.New("fixture unavailable")
	}
	return nil
}
func (d *deps) VerifyManifest(context.Context, lifecycle.Binding, lifecycle.Manifest) error {
	return nil
}
func (d *deps) Resolve(context.Context, string) (policy.Document, error) { return d.document, nil }
func (d *deps) Current(context.Context, lifecycle.Binding) (jobgrant.Snapshot, error) {
	if d.reject {
		return jobgrant.Snapshot{}, errors.New("fixture unavailable")
	}
	return d.snapshot, nil
}

type testFixture struct {
	s           *Server
	store       *Store
	config      Config
	request     IssueRequest
	agent, node ed25519.PrivateKey
	dir         string
	deps        *deps
}

func newFixture(t *testing.T) *testFixture {
	t.Helper()
	base := os.Getenv("AGENTGATE_TEST_SCRATCH")
	if base == "" {
		t.Skip("set an owned protected fixture directory")
	}
	dir, e := os.MkdirTemp(base, "authority-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	doc := documentFixture()
	digest, e := doc.Digest()
	if e != nil {
		t.Fatal(e)
	}
	agent := ed25519.NewKeyFromSeed([]byte(strings.Repeat("a", 32)))
	node := ed25519.NewKeyFromSeed([]byte(strings.Repeat("n", 32)))
	key := ed25519.NewKeyFromSeed([]byte(strings.Repeat("s", 32)))
	m := lifecycle.Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "codex", RuntimeVersion: "fixture", Executable: "/fixture/agent", ExecutableDigest: strings.Repeat("a", 64), ImageDigest: "sha256:" + strings.Repeat("b", 64), Arguments: []string{}, Workspace: "/fixture/workspace", Environment: map[string]string{}, InputDigest: strings.Repeat("c", 64)}
	md, e := m.Digest()
	if e != nil {
		t.Fatal(e)
	}
	b := lifecycle.Binding{AgentID: "agent-one", AgentKey: base64.RawURLEncoding.EncodeToString(agent.Public().(ed25519.PublicKey)), JobDigest: md, GrantID: "grant-one", RunID: "run-one", NodeID: "node-one", BootID: "boot-one", PolicyDigest: digest, SchemaDigest: policy.SchemaDigest(), CompilerDigest: strings.Repeat("d", 64), ArtifactDigests: map[string]string{"runtime.codex.files": emptyRuntimeFilesDigest(), "files": strings.Repeat("e", 64), "peers": strings.Repeat("e", 64), "sockets": strings.Repeat("e", 64), "custody": strings.Repeat("e", 64), "process": strings.Repeat("e", 64), "syscalls": strings.Repeat("e", 64), "node": strings.Repeat("e", 64)}, CgroupID: 42, Generation: 3, DeadlineNS: uint64(20*time.Second) + 500}
	now := time.Now().UTC()
	caps := map[string]policy.Capability{}
	ecaps := map[string]lifecycle.Capability{}
	for _, id := range doc.RequiredCapabilities {
		caps[id] = policy.Capability{State: "enforced", Mechanisms: []string{"fixture-only"}, ReceiptSHA256: strings.Repeat("f", 64)}
		ecaps[id] = lifecycle.Capability{State: "qualified", Mechanisms: []string{"fixture-only"}, EvidenceDigest: strings.Repeat("f", 64)}
	}
	report := policy.CapabilityReport{SchemaVersion: policy.CapabilityVersion, Node: b.NodeID, Boot: b.BootID, Challenge: "fixture", Kernel: "fixture-6.8", Architecture: "x86_64", SourceRevision: strings.Repeat("a", 40), ArtifactSHA256: strings.Repeat("e", 64), PolicySchemaDigest: policy.SchemaDigest(), InventorySHA256: strings.Repeat("c", 64), BTFSHA256: strings.Repeat("d", 64), KernelConfigSHA256: strings.Repeat("e", 64), IssuedAt: now.Unix() - 1, ValidUntil: now.Unix() + 60, Capabilities: caps, Probes: []policy.HookProbe{}}
	reportRaw, e := policy.SignReport(report, node)
	if e != nil {
		t.Fatal(e)
	}
	target, e := policy.VerifyTarget(reportRaw, node.Public().(ed25519.PublicKey), policy.TargetBinding{b.NodeID, b.BootID, "fixture"}, now.Unix())
	if e != nil {
		t.Fatal(e)
	}
	snapshot := jobgrant.Snapshot{Target: target, CompilerDigest: b.CompilerDigest, ArtifactDigests: b.ArtifactDigests}
	qd, e := jobgrant.QualificationDigest(snapshot)
	if e != nil {
		t.Fatal(e)
	}
	streams := []jobaudit.Stream{}
	for _, name := range []string{"files", "peers", "sockets", "custody", "process"} {
		f := jobaudit.ResourceFormats()[name]
		streams = append(streams, jobaudit.Stream{Name: name, Kind: "resource", Version: f.Version, ArtifactDigest: b.ArtifactDigests["files"]})
	}
	streams = append(streams, jobaudit.Stream{Name: "syscalls", Kind: "observation", Version: "syscalls128.v2", ArtifactDigest: b.ArtifactDigests["files"]})
	streams = append(streams, jobaudit.Stream{Name: "node", Kind: "control", Version: "nodecontrol.v1", ArtifactDigest: b.ArtifactDigests["node"]})
	h := jobaudit.Header{Protocol: jobaudit.HeaderProtocol, Binding: b, DocumentDigest: digest, QualificationDigest: qd, RequiredCapabilities: doc.RequiredCapabilities, RequiredStreams: streams, CreatedMonoNS: 1}
	hr, e := jobaudit.HeaderBytes(h)
	if e != nil {
		t.Fatal(e)
	}
	hd, _ := jobaudit.HeaderDigest(h)
	evidence := lifecycle.Evidence{Binding: b, Phase: "quarantined", Quarantined: true, ReadbackDigest: strings.Repeat("9", 64), MandatoryHooks: true, Capabilities: ecaps, Empty: true}
	evidence.Digest = lifecycle.EvidenceDigest(evidence)
	p := lifecycle.PrepareResponse{AuditHeader: hr, AuditHeaderDigest: hd, Protocol: lifecycle.PreparedProtocol, Binding: b, ManifestDigest: md, PreparationDeadlineNS: uint64(time.Second), Evidence: evidence}
	p.PreparationKeyID = "node-key"
	p.PreparedAtUnix = now.Unix()
	p.PreparedMonoNS = 500
	signing, e := lifecycle.PrepareSigningBytes(p)
	if e != nil {
		t.Fatal(e)
	}
	p.PreparationSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(node, signing))
	dependencies := &deps{document: doc, snapshot: snapshot, prepared: p, wall: now}
	store, e := OpenStore(filepath.Join(dir, "authority.db"), "fixture-epoch")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	config := Config{AuthorityID: "authority", KeyID: "signer", SigningKey: key, Subjects: map[string]ProofSubject{"agent-one": {"agent", agent.Public().(ed25519.PublicKey)}, "node-one": {"node", node.Public().(ed25519.PublicKey)}}, NodeKeys: map[string]ed25519.PublicKey{"node-one/node-key": node.Public().(ed25519.PublicKey)}, Enrollment: dependencies, Documents: dependencies, Qualification: dependencies, Preparations: nil, Clock: fixedClock{now, 1 << 60}, Store: store, Registry: testRegistry, MaxLifetime: time.Minute, RequestTimeout: 15 * time.Second}
	config.Preparations, e = NewPreparations(config.NodeKeys, config.Clock, 15*time.Second)
	if e != nil {
		t.Fatal(e)
	}
	server, e := New(config)
	if e != nil {
		t.Fatal(e)
	}
	return &testFixture{server, store, config, IssueRequest{IssueProtocol, m, p, doc}, agent, node, dir, dependencies}
}

func testRegistry(b lifecycle.Binding) jobaudit.Registry {
	return nodecontrol.Registry(nodeaudit.Registry(), b)
}

func emptyRuntimeFilesDigest() string {
	set, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil {
		panic(err)
	}
	return set.Digest()
}

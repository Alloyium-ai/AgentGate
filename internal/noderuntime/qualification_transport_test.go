// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/testpolicy"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func qualificationResponseFixture(t *testing.T) (QualificationPrepared, lifecycle.QualificationFixtureSpec, map[string]ed25519.PublicKey, ed25519.PublicKey) {
	t.Helper()
	artifacts := map[string]string{}
	for i, name := range []string{"node", "watchdog", "held-helper", "exec-broker", "qualification-lifecycle-worker", "files", "peers", "sockets", "custody", "process", "syscalls", "runtime.codex.files"} {
		artifacts[name] = fmt.Sprintf("%064x", i+1)
	}
	b := lifecycle.Binding{AgentID: "qualification-agent", AgentKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), JobDigest: strings.Repeat("1", 64), GrantID: "qualification-grant", RunID: "qualification-run", NodeID: "qualification-node", BootID: "qualification-boot", PolicyDigest: strings.Repeat("2", 64), SchemaDigest: policy.SchemaDigest(), CompilerDigest: strings.Repeat("3", 64), ArtifactDigests: artifacts, Generation: 1, DeadlineNS: uint64(30 * time.Second)}
	root := "/var/lib/kernel-poc-qualification-transport"
	sum := sha256.Sum256([]byte{'T'})
	input := hex.EncodeToString(sum[:])
	m := lifecycle.Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "codex", RuntimeVersion: lifecycle.QualificationFixtureRuntime, Executable: root + "/qualification-lifecycle-worker", ExecutableDigest: artifacts["qualification-lifecycle-worker"], ImageDigest: "sha256:" + strings.Repeat("4", 64), Arguments: []string{}, Environment: map[string]string{}, Workspace: root, InputDigest: input}
	b.JobDigest, _ = m.Digest()
	d := testpolicy.Deny()
	d.Runtime.Seccomp.AllowSyscalls = []string{"read", "write", "close", "openat", "fstat", "dup2", "execve", "exit_group", "getpid", "getppid", "clone", "futex"}
	d.Runtime.Bootstrap = &policy.BootstrapPolicy{Profile: "measured-held-exec.v1", HelperDigest: artifacts["held-helper"], Operations: []string{"barrier_read", "listener_send", "filter_finalize", "working_directory"}, MaxHoldSeconds: 10}
	d.Programs.Rules = []policy.ProgramRule{{ID: "worker", Selector: policy.Selector{Kind: "exact", Path: m.Executable}, Effect: "allow"}}
	d.Files.Rules = []policy.FileRule{{ID: "input", Selector: policy.Selector{Kind: "exact", Path: root + "/input"}, Operations: []string{"read"}, Effect: "allow"}}
	d.RequiredCapabilities, _ = policy.Requirements(d)
	b.PolicyDigest, _ = d.Digest()
	doc, err := d.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	spec := lifecycle.QualificationFixtureSpec{Binding: b, Manifest: m, Document: doc, CandidateDigest: strings.Repeat("5", 64), TargetDigest: strings.Repeat("6", 64), SourceRevision: strings.Repeat("7", 40), OwnedRoot: root}
	scope, err := lifecycle.QualificationFixtureScopeDigest(spec)
	if err != nil {
		t.Fatal(err)
	}
	b.CgroupID = 42
	q := enforcement.QuarantineReadback{Domain: 42, MapIDs: map[string]uint32{}, Markers: map[string]uint32{}}
	for i, name := range []string{"files/policies", "files/owned", "peers/net_policies", "sockets/sock_policies", "sockets/sock_managed", "custody/cust_bindings", "custody/cust_managed", "process/proc_policies", "process/proc_managed"} {
		q.MapIDs[name] = uint32(i + 1)
	}
	for _, name := range []string{"files/owned", "sockets/sock_managed", "custody/cust_managed", "process/proc_managed"} {
		q.Markers[name] = 1
	}
	e := lifecycle.Evidence{Binding: b, FixturePurpose: lifecycle.QualificationFixturePurpose, Phase: "quarantined", Quarantined: true, Empty: true, MandatoryHooks: true, ReadbackDigest: strings.Repeat("8", 64), Capabilities: map[string]lifecycle.Capability{}}
	for _, id := range d.RequiredCapabilities {
		e.Capabilities[id] = lifecycle.Capability{State: "fixture-only", Mechanisms: []string{lifecycle.QualificationFixturePurpose}, EvidenceDigest: scope}
	}
	e.Digest = lifecycle.EvidenceDigest(e)
	h := jobaudit.Header{Protocol: jobaudit.HeaderProtocol, FixturePurpose: lifecycle.QualificationFixturePurpose, Binding: b, DocumentDigest: b.PolicyDigest, QualificationDigest: scope, RequiredCapabilities: d.RequiredCapabilities, CreatedMonoNS: 1}
	for name, format := range jobaudit.ResourceFormats() {
		h.RequiredStreams = append(h.RequiredStreams, jobaudit.Stream{Name: name, Kind: "resource", Version: format.Version, ArtifactDigest: artifacts[name]})
	}
	h.RequiredStreams = append(h.RequiredStreams, jobaudit.Stream{Name: "syscalls", Kind: "observation", Version: "syscalls104.v1", ArtifactDigest: artifacts["syscalls"]}, jobaudit.Stream{Name: "node", Kind: "control", Version: "nodecontrol.v1", ArtifactDigest: artifacts["node"]})
	header, err := jobaudit.HeaderBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	hd, _ := jobaudit.HeaderDigest(h)
	watchKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	ack := lifecycle.WatchdogAck{Protocol: lifecycle.WatchdogAckProtocol, Binding: b, Daemon: lifecycle.DaemonIdentity{PID: 1234, StartTimeTicks: 1, InstanceID: "fixture"}, WatchdogID: "fixture-watchdog", ArtifactDigest: artifacts["watchdog"], IssuedNS: 2}
	encoded, _ := json.Marshal(ack)
	ack.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(watchKey, append([]byte("agentgate-watchdog-custody-v1\n"), encoded...)))
	wire, err := q.Wire()
	if err != nil {
		t.Fatal(err)
	}
	r := QualificationPrepared{Protocol: QualificationPreparedProtocol, Purpose: lifecycle.QualificationFixturePurpose, PermitDigest: scope, TargetDigest: spec.TargetDigest, Record: lifecycle.Record{Binding: b, State: "quarantined", Revision: 2, PreparationDeadlineNS: uint64(20 * time.Second), Evidence: []lifecycle.Evidence{e}, Watchdog: &ack}, Quarantine: wire, AuditHeader: header, AuditHeaderDigest: hd, PreparedAtUnix: 100, PreparedMonoNS: 10, NodeKeyID: "fixture-node-key"}
	nodeKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	signing, err := QualificationPreparedSigningBytes(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(nodeKey, signing))
	return r, spec, map[string]ed25519.PublicKey{b.NodeID + "/" + r.NodeKeyID: nodeKey.Public().(ed25519.PublicKey)}, watchKey.Public().(ed25519.PublicKey)
}
func TestQualificationPreparationPinsNodeWatchdogScopeAndRawDeny(t *testing.T) {
	r, spec, keys, watch := qualificationResponseFixture(t)
	if _, err := VerifyQualificationPrepared(r, spec, keys, watch, 100, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"node-signature", "watchdog-key", "scope", "state", "map", "freshness"} {
		t.Run(name, func(t *testing.T) {
			value, candidate, pinned, watchdog := qualificationResponseFixture(t)
			wall := int64(100)
			switch name {
			case "node-signature":
				value.Signature = "invalid"
			case "watchdog-key":
				watchdog = ed25519.NewKeyFromSeed(make([]byte, 32)).Public().(ed25519.PublicKey)
			case "scope":
				candidate.CandidateDigest = strings.Repeat("9", 64)
			case "state":
				value.Record.Evidence[0].Capabilities["fs.rules.v1"] = lifecycle.Capability{State: "qualified"}
			case "map":
				value.Quarantine.Files[520] = 32
			case "freshness":
				wall = 107
			}
			if _, err := VerifyQualificationPrepared(value, candidate, pinned, watchdog, wall, 5*time.Second); err == nil {
				t.Fatal("an altered fixture preparation passed")
			}
		})
	}
}
func TestQualificationTransportRejectsCaseAliases(t *testing.T) {
	var start QualificationStart
	if lifecycle.DecodeTransport(strings.NewReader(`{"Protocol":"x"}`), &start) == nil {
		t.Fatal("a case alias entered the fixture transport")
	}
}

func TestQualificationStatePathsStayInsideOwnedFixture(t *testing.T) {
	_, spec, _, _ := qualificationResponseFixture(t)
	root := spec.OwnedRoot
	c := Config{Journal: root + "/journal", DomainState: root + "/domains", AuditRoot: root + "/audit", ArtifactRoot: root + "/streams", SocketPath: root + "/node.sock", WatchdogSocket: root + "/watchdog.sock", WatchdogStore: root + "/watchdog", NodeKeyFile: root + "/node.key", Documents: map[string]string{spec.Binding.PolicyDigest: root + "/policy.json"}, NodeKeys: map[string]string{"node": "public"}, AuthorityKeys: map[string]string{"authority": "public"}, Qualification: QualificationConfig{ReportFile: root + "/target.json"}, Authority: AuthorityConfig{SocketPath: root + "/authority.sock"}}
	if err := validateQualificationNodePaths(c, spec); err != nil {
		t.Fatal(err)
	}
	c.NodeKeyFile = "/var/lib/live-node/node.key"
	if validateQualificationNodePaths(c, spec) == nil {
		t.Fatal("a fixture could read a different node key")
	}
}

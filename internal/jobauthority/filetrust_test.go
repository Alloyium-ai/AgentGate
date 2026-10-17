// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/policy"
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

func TestProtectedTrustPinsDocumentRuntimeTargetAndCopies(t *testing.T) {
	f := newFixture(t)
	b := f.request.Prepared.Binding
	m := f.request.Manifest
	document, e := f.request.Document.Canonical()
	if e != nil {
		t.Fatal(e)
	}
	documentPath := filepath.Join(f.dir, "document.json")
	if e = os.WriteFile(documentPath, document, 0600); e != nil {
		t.Fatal(e)
	}
	report := f.deps.snapshot.Target.Report()
	b.ArtifactDigests = copyArtifacts(b.ArtifactDigests)
	b.ArtifactDigests["qualification"] = strings.Repeat("8", 64)
	artifactDigest, e := policy.ArtifactSetDigest(b.ArtifactDigests)
	if e != nil {
		t.Fatal(e)
	}
	report.Qualification = &policy.QualificationScope{Protocol: policy.QualificationScopeVersion, ProducerSHA256: b.ArtifactDigests["qualification"], CompilerSHA256: b.CompilerDigest, ArtifactsSHA256: artifactDigest, PolicyDigests: []string{b.PolicyDigest}, RequiredCapabilities: f.request.Document.RequiredCapabilities, ContractsSHA256: strings.Repeat("9", 64), EvidenceSHA256: strings.Repeat("a", 64)}
	reportRaw, e := policy.SignReport(report, f.node)
	if e != nil {
		t.Fatal(e)
	}
	reportPath := filepath.Join(f.dir, "report.json")
	if e = os.WriteFile(reportPath, reportRaw, 0600); e != nil {
		t.Fatal(e)
	}
	nodeKey := base64.RawURLEncoding.EncodeToString(f.node.Public().(ed25519.PublicKey))
	config := TrustFile{Protocol: "agentgate.authority-config.v1", AuthorityID: "authority", KeyID: "signer", MaxLifetimeSeconds: 60, Subjects: map[string]SubjectPin{"agent-one": {"agent", b.AgentKey}, "node-one": {"node", nodeKey}}, NodeKeys: map[string]string{"node-one/node-key": nodeKey}, Documents: map[string]string{b.PolicyDigest: documentPath}, Enrollments: []EnrollmentPin{{AgentID: b.AgentID, AgentKey: b.AgentKey, NodeID: b.NodeID, BootID: b.BootID, PolicyDigests: []string{b.PolicyDigest}, Runtimes: []RuntimePin{{Kind: m.AgentKind, Version: m.RuntimeVersion, Executable: m.Executable, ExecutableDigest: m.ExecutableDigest, ImageDigest: m.ImageDigest, Files: []runtimeclosure.File{}, FilesDigest: emptyRuntimeFilesDigest()}}}}, Targets: map[string]TargetPin{b.NodeID: {BootID: b.BootID, Challenge: report.Challenge, PublicKey: nodeKey, ReportFile: reportPath, CompilerDigest: b.CompilerDigest, ArtifactDigests: b.ArtifactDigests}}}
	path := filepath.Join(f.dir, "trust.json")
	raw, _ := json.Marshal(config)
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	loaded, trust, e := LoadTrust(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = trust.VerifyEnrollment(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	if e = trust.VerifyManifest(context.Background(), b, m); e != nil {
		t.Fatal(e)
	}
	if _, e = trust.Resolve(context.Background(), b.PolicyDigest); e != nil {
		t.Fatal(e)
	}
	if _, e = trust.Current(context.Background(), b); e != nil {
		t.Fatal(e)
	}
	report.Qualification = nil
	legacy, e := policy.SignReport(report, f.node)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(reportPath, legacy, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = trust.Current(context.Background(), b); e == nil {
		t.Fatal("legacy fixture report authorized production trust")
	}
	loaded.Subjects[b.AgentID] = SubjectPin{"node", nodeKey}
	pin := loaded.Targets[b.NodeID]
	pin.ArtifactDigests["kernel"] = strings.Repeat("0", 64)
	if e = trust.VerifyEnrollment(context.Background(), b); e != nil {
		t.Fatal("returned config changed frozen trust", e)
	}
	other := m
	other.RuntimeVersion = "other"
	if e = trust.VerifyManifest(context.Background(), b, other); e == nil {
		t.Fatal("unapproved runtime accepted")
	}
	changed := b
	changed.BootID = "different"
	if e = trust.VerifyEnrollment(context.Background(), changed); e == nil {
		t.Fatal("changed boot accepted")
	}
	if e = os.WriteFile(documentPath, []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = trust.Resolve(context.Background(), b.PolicyDigest); e == nil {
		t.Fatal("changed document accepted")
	}
}
func TestRuntimeCannotBorrowAnotherEnrollmentPolicy(t *testing.T) {
	f := newFixture(t)
	b := f.request.Prepared.Binding
	m := f.request.Manifest
	other := m
	other.RuntimeVersion = "other"
	pin := EnrollmentPin{AgentID: b.AgentID, AgentKey: b.AgentKey, NodeID: b.NodeID, BootID: b.BootID, PolicyDigests: []string{b.PolicyDigest}, Runtimes: []RuntimePin{{Kind: m.AgentKind, Version: m.RuntimeVersion, Executable: m.Executable, ExecutableDigest: m.ExecutableDigest, ImageDigest: m.ImageDigest, Files: []runtimeclosure.File{}, FilesDigest: emptyRuntimeFilesDigest()}}}
	borrowed := pin
	borrowed.PolicyDigests = []string{strings.Repeat("0", 64)}
	borrowed.Runtimes = []RuntimePin{{Kind: other.AgentKind, Version: other.RuntimeVersion, Executable: other.Executable, ExecutableDigest: other.ExecutableDigest, ImageDigest: other.ImageDigest, Files: []runtimeclosure.File{}, FilesDigest: emptyRuntimeFilesDigest()}}
	trust := &FileTrust{TrustFile{Enrollments: []EnrollmentPin{pin, borrowed}, Targets: map[string]TargetPin{b.NodeID: {BootID: b.BootID, CompilerDigest: b.CompilerDigest, ArtifactDigests: b.ArtifactDigests}}}}
	if e := trust.VerifyManifest(context.Background(), b, other); e == nil {
		t.Fatal("runtime borrowed another policy approval")
	}
}

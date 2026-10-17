// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"alloyium.local/kernel-poc/internal/policy"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func fullDocumentFixture() policy.Document {
	extensions := map[string]json.RawMessage{}
	templates := []string{}
	doc := policy.Document{SchemaVersion: policy.Version, Profile: policy.KernelProfile, RequiredCapabilities: []string{}, Defaults: &policy.Defaults{"deny", "deny", "deny"}, RuntimeTemplates: &templates,
		Files:     &policy.Files{Defaults: policy.FileDefaults{"deny", "deny"}, ResourceUse: "recheck-and-terminate", Rules: []policy.FileRule{{ID: "one-read", Selector: policy.Selector{"exact", "/work/one"}, Operations: []string{"read"}, Effect: "allow"}}},
		Programs:  &policy.Programs{Default: "deny", Rules: []policy.ProgramRule{}},
		Network:   &policy.Network{Default: "deny", Rules: []policy.NetworkRule{}, DNS: policy.DNS{"trusted-forwarder.v1", "validate-chain", "remove-expired-authorization"}},
		Sockets:   &policy.SocketPolicy{Default: "deny", Rules: []policy.SocketRule{}},
		Identity:  &policy.Identity{"local-enrollment", true, true, true, true, "job-cgroup", "inherit"},
		Runtime:   &policy.Runtime{Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{}, Capabilities: []string{}, NoNewPrivileges: true, Seccomp: policy.Seccomp{"explicit-allowlist-notify.v2", "x86_64", "deny", []string{}}},
		Lifecycle: &policy.Lifecycle{"owned-baseline", 20, "restore-baseline", "terminate-job", "pinned-generation-reconcile"},
		Evidence:  &policy.Evidence{"node-chain-authority-batch.v1", 0, 500, 5}, Extensions: &extensions,
	}
	doc.RequiredCapabilities, _ = policy.Requirements(doc)
	return doc
}
func documentInput(doc policy.Document) CreatePolicyDocument {
	raw, _ := json.Marshal(doc)
	return CreatePolicyDocument{Name: "Full deny policy", Format: "json", Source: string(raw), SchemaDigest: policy.SchemaDigest(), Reason: "Store the explicit full policy contract"}
}

func TestImmutableDocumentVersionsPreserveFieldsAndBindAllContent(t *testing.T) {
	s := storeFixture(t)
	s.CustomerPolicy = true
	doc := fullDocumentFixture()
	input := documentInput(doc)
	value, err := s.CreatePolicyDocument(humanOp(), input)
	if err != nil {
		t.Fatal(err)
	}
	first := value.(DocumentVersion)
	stored, err := s.PolicyDocument(first.Version.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored.Document, doc) || stored.Version.Digest != first.Version.Digest {
		t.Fatal("full document fields or binding changed")
	}
	doc.Files.Rules[0].Selector.Path = "/work/two"
	input = documentInput(doc)
	input.ParentID = first.Version.ID
	value, err = s.CreatePolicyDocument(humanOp(), input)
	if err != nil {
		t.Fatal(err)
	}
	next := value.(DocumentVersion)
	if next.Version.Number != 2 || next.Version.ParentID != first.Version.ID || next.DocumentDigest == first.DocumentDigest || next.Version.Digest == first.Version.Digest {
		t.Fatal("the next version reused its parent's binding")
	}
	stored, err = s.PolicyDocument(first.Version.ID)
	if err != nil || stored.Document.Files.Rules[0].Selector.Path != "/work/one" {
		t.Fatal("the parent document changed")
	}
	input.Name = "A different policy name"
	if _, err = s.CreatePolicyDocument(humanOp(), input); err == nil {
		t.Fatal("a document version silently ignored changed policy metadata")
	}
	for _, query := range []string{"UPDATE policy_documents SET document='{}'", "DELETE FROM policy_documents", "UPDATE versions SET digest='changed'"} {
		if _, err = s.DB.Exec(query); err == nil {
			t.Fatal("immutable document binding changed")
		}
	}
	if _, err = s.EditVersion(humanOp(), first.Version.PolicyID, EditVersion{ParentID: first.Version.ID, Rights: Rights{true, "127.0.0.1", 18081}, Reason: "Attempt to omit the full policy"}); err == nil {
		t.Fatal("a selected edit discarded full document fields")
	}
}

func TestDocumentContractCannotPublishOrAdmitBeforeCompilerQualification(t *testing.T) {
	s := storeFixture(t)
	s.CustomerPolicy = true
	value, err := s.CreatePolicyDocument(humanOp(), documentInput(fullDocumentFixture()))
	if err != nil {
		t.Fatal(err)
	}
	version := value.(DocumentVersion).Version
	value, err = s.Transition(humanOp(), version.ID, etag(version.Revision), Decision{State: "proposed", Reason: "Submit the full contract for inspection"})
	if err != nil {
		t.Fatal(err)
	}
	version = value.(Version)
	if _, err = s.Transition(humanOp(), version.ID, etag(version.Revision), Decision{State: "approved", Reason: "Attempt approval before engine qualification"}); err == nil {
		t.Fatal("an unqualified compiler authorized publication")
	}
	if _, err = s.RequestPolicy(humanOp(), RequestPolicy{VersionID: version.ID, Reason: "Attempt use of an unqualified draft"}); err == nil {
		t.Fatal("an unpublished full contract authorized a request")
	}
	var admissions int
	_ = s.DB.QueryRow("SELECT count(*) FROM admissions").Scan(&admissions)
	if admissions != 0 {
		t.Fatal("a contract draft issued a grant")
	}
}

func TestStoredDocumentPreviewRejectsProbeOnlyAndWrongBoot(t *testing.T) {
	s := storeFixture(t)
	node, key, _, reportInput := reportFixture(t, s)
	var envelope policy.CapabilityEnvelope
	_ = json.Unmarshal([]byte(reportInput.Envelope), &envelope)
	doc := fullDocumentFixture()
	for _, id := range doc.RequiredCapabilities {
		envelope.Report.Capabilities[id] = policy.Capability{State: "probe-only", Mechanisms: []string{"unqualified-hook"}}
	}
	raw, err := policy.SignReport(envelope.Report, key)
	if err != nil {
		t.Fatal(err)
	}
	reportInput.Envelope = string(raw)
	value, err := s.PutTargetReport(Operation{Actor: node, RequestID: newID()}, reportInput)
	if err != nil {
		t.Fatal(err)
	}
	target := value.(TargetReportRecord)
	value, err = s.CreatePolicyDocument(humanOp(), documentInput(doc))
	if err != nil {
		t.Fatal(err)
	}
	version := value.(DocumentVersion)
	for _, boot := range []string{"synthetic-boot", "another-boot"} {
		in := PolicyPreviewInput{version.Version.ID, target.Digest, "synthetic-node", boot, "Reject an unqualified or changed target"}
		if _, err = s.PreviewPolicyDocument(humanOp(), in); err == nil {
			t.Fatal("an unqualified or changed target produced an effective policy")
		}
	}
}

func TestStoredDocumentDetectsCorruptionAndRejectsImplicitPermissions(t *testing.T) {
	s := storeFixture(t)
	s.CustomerPolicy = true
	doc := fullDocumentFixture()
	input := documentInput(doc)
	input.Source = strings.Replace(input.Source, `"read":"deny"`, `"read":"allow"`, 1)
	if _, err := s.CreatePolicyDocument(humanOp(), input); err == nil {
		t.Fatal("the document stored an implicit read allowance")
	}
	input = documentInput(doc)
	input.SchemaDigest = strings.Repeat("0", 64)
	if _, err := s.CreatePolicyDocument(humanOp(), input); err == nil {
		t.Fatal("the document stored with a different schema")
	}
	value, err := s.CreatePolicyDocument(humanOp(), documentInput(doc))
	if err != nil {
		t.Fatal(err)
	}
	id := value.(DocumentVersion).Version.ID
	if _, err = s.DB.Exec("DROP TRIGGER policy_document_no_update"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("UPDATE policy_documents SET document_digest=? WHERE version_id=?", strings.Repeat("f", 64), id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.PolicyDocument(id); err == nil {
		t.Fatal("a damaged document binding remained valid")
	}
}

func TestNewDocumentAndTargetRequestsRejectDuplicateAndMissingFields(t *testing.T) {
	for _, item := range []struct {
		raw string
		dto any
	}{
		{`{"node":"one","node":"two","boot":"boot","reason":"Reject duplicate node"}`, &TargetChallengeInput{}},
		{`{"challenge_id":"id","reason":"Reject missing envelope"}`, &TargetReportInput{}},
		{`{"version_id":"id","target_digest":"digest","node":"node","reason":"Reject missing boot"}`, &PolicyPreviewInput{}},
		{`{"name":"Draft","format":"json","source":"{}","reason":"Reject missing schema"}`, &CreatePolicyDocument{}},
	} {
		if err := decodeTargetBody([]byte(item.raw), item.dto); err == nil {
			t.Fatal("an ambiguous or incomplete document request decoded")
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package control

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/audit"
	"alloyium.local/kernel-poc/internal/grant"
	"alloyium.local/kernel-poc/internal/kernel"
)

func evidenceAdmission(t *testing.T, s *Store) (Actor, ed25519.PrivateKey, Admission) {
	t.Helper()
	v := publish(t, s, createVersion(t, s))
	agent, _ := enroll(t, s, "synthetic-evidence-agent", "agent", []string{"request:create", "policy:read"})
	node, key := enroll(t, s, "synthetic-evidence-node", "service", []string{"admission:write", "admission:release", "evidence:write"})
	value, err := s.RequestPolicy(Operation{Actor: agent}, RequestPolicy{VersionID: v.ID, Reason: "Request the evidence fixture"})
	if err != nil {
		t.Fatal(err)
	}
	q := value.(PolicyRequest)
	if _, err = s.DecideRequest(humanOp(), q.ID, etag(1), Decision{State: "approved", Reason: "Approve the evidence fixture"}); err != nil {
		t.Fatal(err)
	}
	value, err = s.Admit(Operation{Actor: node}, AdmitInput{q.ID, "evidence-fixture-run", "synthetic-node", "boot-1", "42", "/var/lib/evidence/workspace/", "9007199254740993", "Admit the evidence fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return node, key, value.(Admission)
}

func nodeEvidence(t *testing.T, s *Store, key ed25519.PrivateKey, a Admission, lost uint64) Evidence {
	t.Helper()
	var expected grant.Claims
	parts := strings.Split(a.Token, ".")
	body, err := b64.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(body, &expected); err != nil {
		t.Fatal(err)
	}
	claims, err := grant.Verify(a.Token, s.Authority.Public().(ed25519.PublicKey), expected, time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	events := []kernel.Event{{Sequence: 1, Generation: 1, Cgroup: 42, MonoNS: 9007199254740993, PID: 55, UID: 65534, Hook: 1, Allowed: 1}}
	if err = audit.Save(dir, a.Token, claims, events, kernel.Counters{Decisions: 1 + lost, Lost: lost}, grant.Keys{Node: key}, grant.Digest([]byte("controlled-bpf-object")), "completed"); err != nil {
		t.Fatal(err)
	}
	stream, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := os.ReadFile(filepath.Join(dir, "terminal.json"))
	if err != nil {
		t.Fatal(err)
	}
	return Evidence{a.Token, string(stream), terminal}
}

func TestEvidenceAdmissionAndRetentionStatuses(t *testing.T) {
	for _, mode := range []string{"complete", "lost", "tampered", "missing-seal"} {
		t.Run(mode, func(t *testing.T) {
			s := storeFixture(t)
			node, key, a := evidenceAdmission(t, s)
			op := Operation{Actor: node}
			e := nodeEvidence(t, s, key, a, 0)
			spool := filepath.Join(t.TempDir(), "spool")
			in := IngestInput{a.ID, e, "Retain a labeled evidence fixture"}
			if _, err := s.Ingest(op, in, spool); err == nil {
				t.Fatal("ingest preceded installation confirmation")
			}
			bad := ActivateInput{a.VersionID, "wrong-digest", grant.Digest([]byte("controlled-bpf-object")), "Try a changed policy binding"}
			if _, err := s.Activate(op, a.ID, bad); err == nil {
				t.Fatal("changed policy activated")
			}
			good := ActivateInput{a.VersionID, a.PolicyDigest, grant.Digest([]byte("controlled-bpf-object")), "Confirm the installed fixture"}
			if _, err := s.Activate(op, a.ID, good); err != nil {
				t.Fatal(err)
			}
			if mode == "lost" {
				e = nodeEvidence(t, s, key, a, 3)
			}
			in.Evidence = e
			value, err := s.Receipt(op, in, spool)
			if err != nil {
				t.Fatal(err)
			}
			terminal, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			in.Evidence.Terminal = terminal
			want := audit.Complete
			if mode == "lost" {
				want = audit.Incomplete
			}
			if mode == "tampered" {
				in.Evidence.Events = "altered\n"
				want = audit.Tampered
			}
			if mode == "missing-seal" {
				in.Evidence.Terminal = nil
				want = audit.Incomplete
			}
			value, err = s.Ingest(op, in, spool)
			if err != nil {
				t.Fatal(err)
			}
			run := value.(Run)
			detail, detailErr := s.RunDetail(run.ID, humanOp().Actor)
			if detailErr != nil {
				t.Fatal(detailErr)
			}
			summary := detail["seal"].(map[string]any)
			if mode == "lost" && summary["reported_loss"] != "3" {
				t.Fatal("loss count disappeared from run details")
			}
			if mode == "missing-seal" && summary["present"] != false {
				t.Fatal("the run fabricated a missing seal")
			}
			if run.Verifier != want {
				t.Fatalf("retained %s, wanted %s", run.Verifier, want)
			}
			if _, err = s.Ingest(op, in, spool); err == nil {
				t.Fatal("duplicate evidence changed immutable history")
			}
		})
	}
}

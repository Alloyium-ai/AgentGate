// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"alloyium.local/kernel-poc/internal/policy"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func reportFixture(t *testing.T, s *Store) (Actor, ed25519.PrivateKey, TargetChallenge, TargetReportInput) {
	t.Helper()
	s.CustomerPolicy = true
	node, key := enroll(t, s, "synthetic-report-node", "service", []string{"target:write", "target:read", "policy:read"})
	value, err := s.CreateTargetChallenge(Operation{Actor: node, RequestID: newID()}, TargetChallengeInput{"synthetic-node", "synthetic-boot", "Measure the owned target kernel"})
	if err != nil {
		t.Fatal(err)
	}
	challenge := value.(TargetChallenge)
	report := policy.CapabilityReport{SchemaVersion: policy.CapabilityVersion, Node: challenge.Node, Boot: challenge.Boot, Challenge: challenge.Challenge, Kernel: "6.8.0-142-generic", Architecture: "x86_64", SourceRevision: strings.Repeat("a", 40), ArtifactSHA256: strings.Repeat("b", 64), PolicySchemaDigest: policy.SchemaDigest(), IssuedAt: time.Now().Unix(), ValidUntil: time.Now().Unix() + 120, Capabilities: map[string]policy.Capability{}, Probes: []policy.HookProbe{}}
	raw, err := policy.SignReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	return node, key, challenge, TargetReportInput{challenge.ID, string(raw), "Submit the signed target report"}
}

func TestTargetReportConsumesChallengeOnceAndRevalidatesTrust(t *testing.T) {
	s := storeFixture(t)
	node, _, challenge, in := reportFixture(t, s)
	const workers = 4
	results := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.PutTargetReport(Operation{Actor: node, RequestID: newID()}, in)
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	passed := 0
	for err := range results {
		if err == nil {
			passed++
		}
	}
	if passed != 1 {
		t.Fatalf("challenge admitted %d reports", passed)
	}
	var id string
	if err := s.DB.QueryRow("SELECT digest FROM target_reports WHERE challenge_id=?", challenge.ID).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TargetReport(id, node); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TargetReport(id, Actor{Kind: "service", Subject: "another-node"}); err == nil {
		t.Fatal("another node read the target report")
	}
	if _, err := s.DB.Exec("UPDATE services SET enabled=0 WHERE subject=?", node.Subject); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TargetReport(id, Actor{Kind: "human"}); err == nil {
		t.Fatal("a disabled node retained a current target")
	}
}

func TestTargetReportRejectsForgeryIdentityReplayExpiryAndRestore(t *testing.T) {
	for _, mode := range []string{"forgery", "boot", "node", "expired-challenge", "key-rotation", "restore", "expired-report", "duplicate"} {
		t.Run(mode, func(t *testing.T) {
			s := storeFixture(t)
			node, key, _, in := reportFixture(t, s)
			var envelope policy.CapabilityEnvelope
			if err := json.Unmarshal([]byte(in.Envelope), &envelope); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "forgery":
				_, key, _ = ed25519.GenerateKey(rand.Reader)
			case "boot":
				envelope.Report.Boot = "another-boot"
			case "node":
				envelope.Report.Node = "another-node"
			case "expired-report":
				envelope.Report.IssuedAt = time.Now().Unix() - 120
				envelope.Report.ValidUntil = time.Now().Unix() - 1
			case "expired-challenge":
				_, _ = s.DB.Exec("UPDATE target_challenges SET expires=0")
			case "key-rotation":
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				_, _ = s.DB.Exec("UPDATE services SET public_key=? WHERE subject=?", EncodePublic(pub), node.Subject)
			case "restore":
				// The real restore writes a committed audit event, after the challenge.
				tx, _ := s.DB.Begin()
				_, err := appendAudit(tx, Operation{Actor: Actor{Subject: "deployment", Kind: "system"}, Action: "backup.restored"}, "committed")
				if err != nil {
					t.Fatal(err)
				}
				if err = tx.Commit(); err != nil {
					t.Fatal(err)
				}
			}
			raw, err := policy.SignReport(envelope.Report, key)
			if err != nil {
				t.Fatal(err)
			}
			in.Envelope = string(raw)
			if mode == "duplicate" {
				in.Envelope = strings.Replace(in.Envelope, `"boot":"synthetic-boot"`, `"boot":"synthetic-boot","boot":"synthetic-boot"`, 1)
			}
			if _, err = s.PutTargetReport(Operation{Actor: node, RequestID: newID()}, in); err == nil {
				t.Fatal("the target report crossed its trust boundary")
			}
			var reports int
			_ = s.DB.QueryRow("SELECT count(*) FROM target_reports").Scan(&reports)
			if reports != 0 {
				t.Fatal("a rejected target report persisted")
			}
		})
	}
}

func TestTargetReportAuditFailureRollsBackChallengeAndReport(t *testing.T) {
	s := storeFixture(t)
	node, _, challenge, in := reportFixture(t, s)
	if _, err := s.DB.Exec(`CREATE TRIGGER reject_target_audit BEFORE INSERT ON audit WHEN NEW.action='target.report.accepted' BEGIN SELECT RAISE(ABORT,'target audit unavailable'); END;`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PutTargetReport(Operation{Actor: node, RequestID: newID()}, in); err == nil {
		t.Fatal("a target report survived audit failure")
	}
	var reports, used int
	_ = s.DB.QueryRow("SELECT count(*) FROM target_reports").Scan(&reports)
	_ = s.DB.QueryRow("SELECT used FROM target_challenges WHERE id=?", challenge.ID).Scan(&used)
	if reports != 0 || used != 0 {
		t.Fatal("audit failure consumed a challenge or persisted a report")
	}
}

func TestTargetReportSurvivesRestartButRestoreRequiresFreshReport(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "original")
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	node, _, _, in := reportFixture(t, s)
	value, err := s.PutTargetReport(Operation{Actor: node, RequestID: newID()}, in)
	if err != nil {
		t.Fatal(err)
	}
	id := value.(TargetReportRecord).Digest
	if err = s.Backup(filepath.Join(root, "snapshot")); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	s, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.TargetReport(id, node); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	dest := filepath.Join(root, "restored")
	if err = RestoreNew(filepath.Join(root, "snapshot"), dest); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if _, err = s.TargetReport(id, node); err == nil {
		t.Fatal("a restored target report retained execution authority")
	}
}

func TestTargetChallengeRequiresServiceScopeAndBoundsPendingRequests(t *testing.T) {
	s := storeFixture(t)
	node, _, _, _ := reportFixture(t, s)
	in := TargetChallengeInput{"synthetic-node", "synthetic-boot", "Issue a bounded target challenge"}
	if _, err := s.CreateTargetChallenge(humanOp(), in); err == nil {
		t.Fatal("an admin bypassed the node service channel")
	}
	for i := 0; i < 3; i++ {
		if _, err := s.CreateTargetChallenge(Operation{Actor: node, RequestID: newID()}, in); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.CreateTargetChallenge(Operation{Actor: node, RequestID: newID()}, in); err == nil {
		t.Fatal("unbounded current target challenges")
	}
	if _, err := s.RegisterService(Operation{Actor: Actor{Subject: "deployment", Kind: "system", Scopes: []string{"agents:write"}}}, Service{Subject: "agent-with-node-scope", Kind: "agent", PublicKey: EncodePublic(ed25519.PublicKey(make([]byte, 32))), Scopes: []string{"target:write"}}); err == nil {
		t.Fatal("an agent received a node target scope")
	}
}

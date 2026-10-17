// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func storeFixture(t *testing.T) *Store {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	seedHumanSession(s)
	t.Cleanup(func() { s.DB.Close() })
	return s
}
func seedHumanSession(s *Store) {
	actor := Actor{Subject: "synthetic-admin", Kind: "human", Roles: []string{"admin"}, Groups: []string{"admins"}}
	if _, err := s.DB.Exec("INSERT OR REPLACE INTO sessions VALUES(?,?,?,?)", digest([]byte("unit-fixture-human-session")), jsonText(sessionActor{actor, s.LoginAuthority}), "unit-fixture-csrf", time.Now().Add(time.Hour).Unix()); err != nil {
		panic(err)
	}
}
func humanOp(stores ...*Store) Operation {
	if len(stores) > 0 {
		seedHumanSession(stores[0])
	}
	return Operation{SessionHash: digest([]byte("unit-fixture-human-session")), Actor: Actor{Subject: "synthetic-admin", Kind: "human", Roles: []string{"admin"}}, RequestID: newID(), BodyDigest: "fixture"}
}
func createVersion(t *testing.T, s *Store) Version {
	t.Helper()
	seedHumanSession(s)
	value, err := s.CreatePolicy(humanOp(), CreatePolicy{"Synthetic workspace policy", "Disposable developer acceptance", Rights{true, "127.0.0.1", 18081}, "Create a controlled fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return value.(map[string]any)["version"].(Version)
}
func publish(t *testing.T, s *Store, v Version) Version {
	t.Helper()
	for _, state := range []string{"proposed", "approved", "published"} {
		op := humanOp()
		op.Idempotency = newID()
		value, err := s.Transition(op, v.ID, etag(v.Revision), Decision{State: state, Reason: "Review the controlled fixture"})
		if err != nil {
			t.Fatal(err)
		}
		v = value.(Version)
	}
	return v
}
func enroll(t *testing.T, s *Store, subject, kind string, scopes []string) (Actor, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node := ""
	if kind == "service" {
		node = "synthetic-node"
	}
	_, err = s.RegisterService(Operation{Actor: Actor{Subject: "deployment", Kind: "system", Scopes: []string{"agents:write"}}, RequestID: newID()}, Service{subject, kind, EncodePublic(pub), scopes, node, true})
	if err != nil {
		t.Fatal(err)
	}
	return Actor{Subject: subject, Kind: kind, Scopes: scopes}, key
}
func TestAuditFailureRollsBackBusinessChange(t *testing.T) {
	s := storeFixture(t)
	if _, err := s.DB.Exec(`CREATE TRIGGER reject_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'synthetic disk failure'); END;`); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreatePolicy(humanOp(), CreatePolicy{"Synthetic policy", "", Rights{true, "127.0.0.1", 18081}, "Verify transactional rollback"})
	if err == nil || !strings.Contains(err.Error(), "synthetic disk failure") {
		t.Fatalf("audit failure did not reach the transaction boundary: %v", err)
	}
	var n int
	s.DB.QueryRow("SELECT COUNT(*) FROM policies").Scan(&n)
	if n != 0 {
		t.Fatal("policy survived audit failure")
	}
}
func TestImmutableVersionsAndAudit(t *testing.T) {
	s := storeFixture(t)
	v := publish(t, s, createVersion(t, s))
	value, err := s.EditVersion(humanOp(), v.PolicyID, EditVersion{v.ID, Rights{false, "127.0.0.1", 18082}, "Propose narrower workspace rights"})
	if err != nil {
		t.Fatal(err)
	}
	next := value.(Version)
	old, err := versionFrom(s.DB, v.ID)
	if err != nil || old.Rights != v.Rights || old.Digest != v.Digest || next.ID == v.ID {
		t.Fatal("edit changed historical policy")
	}
	for _, sql := range []string{"UPDATE audit SET reason='altered'", "DELETE FROM audit", "UPDATE versions SET rights='{}'", "DELETE FROM versions"} {
		if _, err = s.DB.Exec(sql); err == nil {
			t.Fatalf("history mutation succeeded: %s", sql)
		}
	}
}
func TestConcurrentDecisionRequiresExactRevision(t *testing.T) {
	s := storeFixture(t)
	v := createVersion(t, s)
	value, err := s.Transition(humanOp(), v.ID, etag(1), Decision{State: "proposed", Reason: "Submit the fixture"})
	if err != nil {
		t.Fatal(err)
	}
	v = value.(Version)
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op := humanOp()
			op.Idempotency = newID()
			_, err := s.Transition(op, v.ID, etag(v.Revision), Decision{State: "approved", Reason: "Concurrent review fixture"})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else {
			status, _, _ := errorResult(err)
			if status != 412 {
				t.Fatalf("unexpected error: %v", err)
			}
		}
	}
	if success != 1 {
		t.Fatalf("accepted %d decisions", success)
	}
	var denied int
	s.DB.QueryRow("SELECT COUNT(*) FROM audit WHERE result='denied'").Scan(&denied)
	if denied != 7 {
		t.Fatalf("recorded %d denied decisions", denied)
	}
}
func TestMachineCannotApproveOrPublish(t *testing.T) {
	s := storeFixture(t)
	v := createVersion(t, s)
	actor, _ := enroll(t, s, "synthetic-agent", "agent", []string{"proposal:create", "request:create", "policy:read"})
	actor.Roles = []string{"admin"}
	op := Operation{Actor: actor, RequestID: newID()}
	for _, state := range []string{"approved", "published"} {
		_, err := s.Transition(op, v.ID, etag(1), Decision{State: state, Reason: "Try a forged role"})
		status, _, _ := errorResult(err)
		if status != 403 {
			t.Fatalf("machine acquired human authority: %v", err)
		}
	}
	var n int
	s.DB.QueryRow("SELECT COUNT(*) FROM audit WHERE actor_kind='agent' AND result='denied'").Scan(&n)
	if n != 2 {
		t.Fatalf("missing denied attempts: %d", n)
	}
}
func TestAdmissionBindingIdempotencyAndHistory(t *testing.T) {
	s := storeFixture(t)
	v := publish(t, s, createVersion(t, s))
	agent, _ := enroll(t, s, "synthetic-agent", "agent", []string{"request:create", "policy:read"})
	node, _ := enroll(t, s, "synthetic-node-service", "service", []string{"admission:write", "admission:release", "evidence:write"})
	value, err := s.RequestPolicy(Operation{Actor: agent, RequestID: newID()}, RequestPolicy{VersionID: v.ID, Reason: "Run the synthetic kernel fixture"})
	if err != nil {
		t.Fatal(err)
	}
	q := value.(PolicyRequest)
	value, err = s.DecideRequest(humanOp(), q.ID, etag(1), Decision{State: "approved", VersionID: v.ID, Reason: "Approve the exact published fixture"})
	if err != nil {
		t.Fatal(err)
	}
	q = value.(PolicyRequest)
	op := Operation{Actor: node, RequestID: newID(), Idempotency: "one-admission", BodyDigest: "bound-enrollment", ProofNonce: "first-proof"}
	in := AdmitInput{q.ID, "synthetic-run-1", "synthetic-node", "boot-1", "42", "/var/lib/synthetic/workspace/", "9007199254740993", "Admit the approved fixture"}
	value, err = s.Admit(op, in)
	if err != nil {
		t.Fatal(err)
	}
	a := value.(Admission)
	if a.VersionID != v.ID || a.PolicyDigest != v.Digest {
		t.Fatal("admission lost policy binding")
	}
	op.ProofNonce = "second-proof"
	replayed, err := s.Admit(op, in)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(replayed)
	var same Admission
	json.Unmarshal(data, &same)
	if same.ID != a.ID {
		t.Fatal("idempotent retry created a new admission")
	}
	op.ProofNonce = "third-proof"
	op.Idempotency = "another-admission"
	if _, err = s.Admit(op, in); err == nil {
		t.Fatal("request replay admitted")
	}
	_, err = s.EditVersion(humanOp(), v.PolicyID, EditVersion{v.ID, Rights{false, "127.0.0.1", 18082}, "Create a later draft"})
	if err != nil {
		t.Fatal(err)
	}
	kept, err := scanAdmission(s.DB.QueryRow("SELECT * FROM admissions WHERE id=?", a.ID))
	if err != nil || kept.PolicyDigest != v.Digest {
		t.Fatal("later edit rewrote admission")
	}
	var exposed int
	s.DB.QueryRow("SELECT COUNT(*) FROM audit WHERE after_json LIKE '%eyJhbGci%'").Scan(&exposed)
	if exposed != 0 {
		t.Fatal("audit exposed a grant credential")
	}
}
func TestPaginationAndSafeFilters(t *testing.T) {
	s := storeFixture(t)
	for i := 0; i < 4; i++ {
		createVersion(t, s)
	}
	f := Filter{Limit: 2, Values: map[string][]string{}}
	p, err := s.Audit(f)
	if err != nil || len(p.Items) != 2 || p.Next == "" {
		t.Fatal("missing bounded page")
	}
	f, err = ParseFilter(map[string][]string{"cursor": {p.Next}, "limit": {"2"}})
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.Audit(f)
	if err != nil || next.Items[0].ID <= p.Items[1].ID {
		t.Fatal("cursor repeated records")
	}
	f.Values.Set("actor", "x' OR 1=1 --")
	filtered, err := s.Audit(f)
	if err != nil || len(filtered.Items) != 0 {
		t.Fatal("filter escaped its bound")
	}
	if _, err = ParseFilter(map[string][]string{"limit": {"100000"}}); err == nil {
		t.Fatal("unbounded page accepted")
	}
	f.Values.Set("after", time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	f.Values.Del("actor")
	filtered, err = s.Audit(f)
	if err != nil || len(filtered.Items) != 0 {
		t.Fatal("time filter differs")
	}
}

func TestDisabledMachineCannotCommitPreparedRequest(t *testing.T) {
	s := storeFixture(t)
	v := publish(t, s, createVersion(t, s))
	actor, _ := enroll(t, s, "synthetic-disabled-agent", "agent", []string{"request:create", "policy:read"})
	if _, err := s.SetServiceStatus(humanOp(), actor.Subject, ServiceStatus{false, "Disable the prepared machine identity"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.RequestPolicy(Operation{Actor: actor}, RequestPolicy{VersionID: v.ID, Reason: "Attempt a request after identity disable"})
	status, _, _ := errorResult(err)
	if status != 403 {
		t.Fatalf("disabled prepared identity committed: %v", err)
	}
	var n int
	s.DB.QueryRow("SELECT COUNT(*) FROM requests").Scan(&n)
	if n != 0 {
		t.Fatal("disabled request escaped the authorization transaction")
	}
}

func TestHumanCannotUseAnOverlappingEnforcerSubject(t *testing.T) {
	s := storeFixture(t)
	human := humanOp()
	_, err := s.RegisterService(human, Service{Subject: human.Actor.Subject, Kind: "service", PublicKey: EncodePublic(s.Authority.Public().(ed25519.PublicKey)), Scopes: []string{"admission:write", "admission:release", "evidence:write"}, Node: "synthetic-node"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.Admit(human, AdmitInput{RequestID: "synthetic-request", RunID: "synthetic-run", Node: "synthetic-node", Reason: "Attempt a human session on the enforcer channel"})
	status, _, _ := errorResult(err)
	if status != 403 {
		t.Fatalf("human session used a machine subject: %v", err)
	}
	for _, scope := range []string{"admission:release", "evidence:write"} {
		if err = require(human.Actor, scope, false); err == nil {
			t.Fatal("human role entered the machine channel")
		}
	}
}

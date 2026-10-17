// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package control

import (
	"alloyium.local/kernel-poc/internal/grant"
	"database/sql"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func secondCachedActivation(t *testing.T) (*Store, Actor, Admission, Operation, ActivateInput) {
	t.Helper()
	s := storeFixture(t)
	node, _, a := evidenceAdmission(t, s)
	op := Operation{Actor: node, Idempotency: "independent-cached-activation", BodyDigest: "exact-activation", ProofNonce: "independent-initial-proof"}
	in := ActivateInput{a.VersionID, a.PolicyDigest, grant.Digest([]byte("controlled-bpf-object")), "Activate the independent review fixture"}
	if _, err := s.Activate(op, a.ID, in); err != nil {
		t.Fatal(err)
	}
	return s, node, a, op, in
}

func TestSecondCachedActivationRejectsTerminalAndRetiredStates(t *testing.T) {
	for _, mode := range []string{"revoked", "released", "retired", "expired", "disabled-service"} {
		t.Run(mode, func(t *testing.T) {
			s, node, a, op, in := secondCachedActivation(t)
			want := map[string]string{"revoked": "stale_admission", "released": "stale_admission", "retired": "policy_unpublished", "expired": "grant_expired", "disabled-service": "service_inactive"}[mode]
			switch mode {
			case "revoked":
				if _, err := s.Release(humanOp(), a.ID, Decision{State: "revoked", Reason: "Withdraw before a cached authorization reply"}); err != nil {
					t.Fatal(err)
				}
			case "released":
				if _, err := s.Release(Operation{Actor: node}, a.ID, Decision{State: "released", Reason: "Release before a cached authorization reply"}); err != nil {
					t.Fatal(err)
				}
			case "retired":
				v, err := versionFrom(s.DB, a.VersionID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = s.Transition(humanOp(), v.ID, etag(v.Revision), Decision{State: "retired", Reason: "Retire before a cached authorization reply"}); err != nil {
					t.Fatal(err)
				}
			case "expired":
				if _, err := s.DB.Exec("DROP TRIGGER admission_binding_immutable; UPDATE admissions SET expires='2000-01-01T00:00:00Z'"); err != nil {
					t.Fatal(err)
				}
			case "disabled-service":
				if _, err := s.SetServiceStatus(humanOp(), node.Subject, ServiceStatus{false, "Disable the service before a cached authorization reply"}); err != nil {
					t.Fatal(err)
				}
			}
			op.ProofNonce = "independent-fresh-proof"
			value, err := s.Activate(op, a.ID, in)
			_, code, _ := errorResult(err)
			if err == nil || code != want {
				t.Fatalf("cached %s reply: value=%v code=%s err=%v", mode, value, code, err)
			}
			var nonces, denials int
			if err = s.DB.QueryRow("SELECT COUNT(*) FROM nonces WHERE actor=? AND nonce=?", node.Subject, op.ProofNonce).Scan(&nonces); err != nil {
				t.Fatal(err)
			}
			if err = s.DB.QueryRow("SELECT COUNT(*) FROM audit WHERE actor=? AND resource=? AND result='denied'", node.Subject, a.ID).Scan(&denials); err != nil {
				t.Fatal(err)
			}
			if nonces != 1 || denials != 1 {
				t.Fatalf("denial lacks atomic provenance: nonce=%d audit=%d", nonces, denials)
			}
		})
	}
}

func TestSecondCachedReplyRaceOrdersDisable(t *testing.T) {
	for attempt := 0; attempt < 12; attempt++ {
		s, _, a, op, in := secondCachedActivation(t)
		op.ProofNonce = fmt.Sprintf("race-proof-%d", attempt)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var cachedErr, disabledErr error
		go func() { defer wg.Done(); <-start; _, cachedErr = s.Activate(op, a.ID, in) }()
		go func() {
			defer wg.Done()
			<-start
			_, disabledErr = s.SetServiceStatus(humanOp(), a.AgentID, ServiceStatus{false, "Disable during the cached authorization race"})
		}()
		close(start)
		wg.Wait()
		if disabledErr != nil {
			t.Fatal(disabledErr)
		}
		if cachedErr == nil {
			var replay, disabled int64
			if err := s.DB.QueryRow("SELECT MAX(id) FROM audit WHERE action='grant.admitted.replayed' AND result='replayed'").Scan(&replay); err != nil {
				t.Fatal(err)
			}
			if err := s.DB.QueryRow("SELECT MAX(id) FROM audit WHERE action='agent.status.changed' AND result='committed'").Scan(&disabled); err != nil {
				t.Fatal(err)
			}
			if replay >= disabled {
				t.Fatal("cached authorization committed after disable")
			}
		} else {
			_, code, _ := errorResult(cachedErr)
			if code != "agent_disabled" {
				t.Fatalf("wrong race denial: %v", cachedErr)
			}
		}
	}
}

func TestSecondConcurrentCachedProofHasOneReply(t *testing.T) {
	s, _, a, op, in := secondCachedActivation(t)
	op.ProofNonce = "one-concurrent-cached-proof"
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Activate(op, a.ID, in); results <- err }()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for err := range results {
		if err == nil {
			accepted++
		} else {
			_, code, _ := errorResult(err)
			if code != "proof_replay" {
				t.Fatalf("wrong concurrent denial: %v", err)
			}
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d cached replies for one proof", accepted)
	}
	var replay, denied int
	s.DB.QueryRow("SELECT COUNT(*) FROM audit WHERE resource=? AND result='replayed'", a.ID).Scan(&replay)
	s.DB.QueryRow("SELECT COUNT(*) FROM audit WHERE resource=? AND result='denied'", a.ID).Scan(&denied)
	if replay != 1 || denied != 7 {
		t.Fatalf("wrong atomic audit: replay=%d denied=%d", replay, denied)
	}
}

func TestSecondHumanRolesReloadAtCommit(t *testing.T) {
	s := storeFixture(t)
	op := humanOp()
	s.mu.Lock()
	s.ResolveRoles = func([]string) []string { return []string{"viewer"} }
	s.mu.Unlock()
	_, err := s.Mutation(op, "policy:write", true, func(tx *sql.Tx, _ *Operation) (any, error) { return "unexpected", nil })
	_, code, _ := errorResult(err)
	if err == nil || code != "forbidden" {
		t.Fatalf("stale admin role survived role reload: %v", err)
	}
}

func TestSecondOptionalSchemaNullAndArrayBounds(t *testing.T) {
	if err := decodeBody([]byte(`{"name":"Optional null","description":null,"rights":{"workspace_write":false,"tcp_address":"127.0.0.1","tcp_port":18081},"reason":"Review optional schema types"}`), &CreatePolicy{}); err == nil {
		t.Error("optional nonnullable description accepted null")
	}
	scopes := make([]string, 17)
	for i := range scopes {
		scopes[i] = "policy:read"
	}
	body, _ := json.Marshal(Service{Subject: "array-bounds-agent", Kind: "agent", PublicKey: "public", Scopes: scopes})
	if err := decodeBody(body, &Service{}); err == nil {
		t.Error("scopes maxItems=16 accepts 17 items")
	}
}

func TestSecondExpiryAfterWaitingForStoreLock(t *testing.T) {
	s := storeFixture(t)
	op := humanOp()
	s.mu.Lock()
	start := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(start)
		_, err := s.CreatePolicy(op, CreatePolicy{Name: "Expired queued operation", Rights: Rights{false, "127.0.0.1", 18081}, Reason: "Check queued expiry before commit"})
		done <- err
	}()
	<-start
	if _, err := s.DB.Exec("UPDATE sessions SET expires=? WHERE id_hash=?", time.Now().Unix()-1, op.SessionHash); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	err := <-done
	_, code, _ := errorResult(err)
	if err == nil || code != "session_expired" {
		t.Fatalf("queued expired mutation committed: %v", err)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package control

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/grant"
)

func preparedBrowser(t *testing.T, f *authFixture, path string, body []byte) (*Server, *http.Request, call) {
	t.Helper()
	session := readSession(t, f)
	app := NewServer(f.Store, f.Auth, filepath.Join(t.TempDir(), "spool"), t.TempDir())
	r := httptest.NewRequest("POST", f.App.URL+"/api/v1/"+path, bytes.NewReader(body))
	for _, cookie := range f.Client.Jar.Cookies(r.URL) {
		r.AddCookie(cookie)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.App.URL)
	r.Header.Set("X-CSRF-Token", session.CSRF)
	r.Header.Set("Idempotency-Key", newID())
	r.Header.Set("If-Match", etag(1))
	c, err := app.prepare(r)
	if err != nil {
		t.Fatal(err)
	}
	return app, r, c
}

func TestPreparedDecisionsAndPublicationRecheckSession(t *testing.T) {
	for _, action := range []string{"publication", "decision"} {
		for _, cause := range []string{"logout", "expiry", "restore-deletion"} {
			t.Run(action+"/"+cause, func(t *testing.T) {
				f := authTestFixture(t)
				response, _ := loginFlow(t, f, "admin")
				response.Body.Close()
				v := createVersion(t, f.Store)
				path := "versions/" + v.ID + "/transition"
				body := []byte(jsonText(Decision{State: "published", Reason: "Publish the exact reviewed fixture"}))
				revision := 3
				if action == "publication" {
					for _, state := range []string{"proposed", "approved"} {
						value, err := f.Store.Transition(humanOp(), v.ID, etag(v.Revision), Decision{State: state, Reason: "Prepare a publication fixture"})
						if err != nil {
							t.Fatal(err)
						}
						v = value.(Version)
					}
				} else {
					v = publish(t, f.Store, v)
					actor, _ := enroll(t, f.Store, "lifecycle-agent", "agent", []string{"request:create"})
					value, err := f.Store.RequestPolicy(Operation{Actor: actor}, RequestPolicy{VersionID: v.ID, Reason: "Request the lifecycle fixture"})
					if err != nil {
						t.Fatal(err)
					}
					q := value.(PolicyRequest)
					path = "requests/" + q.ID + "/decision"
					body = []byte(jsonText(Decision{State: "approved", VersionID: v.ID, Reason: "Approve the exact lifecycle fixture"}))
					revision = 1
				}
				app, r, c := preparedBrowser(t, f, path, body)
				r.Header.Set("If-Match", etag(revision))
				switch cause {
				case "logout":
					if err := f.Auth.Logout(httptest.NewRecorder(), r); err != nil {
						t.Fatal(err)
					}
				case "expiry":
					f.Store.DB.Exec("UPDATE sessions SET expires=? WHERE id_hash=?", time.Now().Unix()-1, c.Operation.SessionHash)
				case "restore-deletion":
					f.Store.DB.Exec("DELETE FROM sessions")
				}
				if _, err := app.write(r, c); err == nil {
					t.Fatal("a stale browser decision committed")
				}
				var n int
				f.Store.DB.QueryRow("SELECT COUNT(*) FROM audit WHERE actor_kind='human' AND result='denied' AND resource=?", r.URL.Path).Scan(&n)
			})
		}
	}
}

func TestCachedHumanReplyRequiresCurrentSession(t *testing.T) {
	f := authTestFixture(t)
	response, _ := loginFlow(t, f, "admin")
	response.Body.Close()
	v := createVersion(t, f.Store)
	app, r, c := preparedBrowser(t, f, "versions/"+v.ID+"/transition", []byte(jsonText(Decision{State: "proposed", Reason: "Submit one exact version"})))
	if _, err := app.write(r, c); err != nil {
		t.Fatal(err)
	}
	if err := f.Auth.Logout(httptest.NewRecorder(), r); err != nil {
		t.Fatal(err)
	}
	if _, err := app.write(r, c); err == nil {
		t.Fatal("a cached authorization reply survived logout")
	}
}

func TestConcurrentLogoutOrdersPublication(t *testing.T) {
	for attempt := 0; attempt < 8; attempt++ {
		f := authTestFixture(t)
		response, _ := loginFlow(t, f, "admin")
		response.Body.Close()
		v := createVersion(t, f.Store)
		for _, state := range []string{"proposed", "approved"} {
			value, err := f.Store.Transition(humanOp(), v.ID, etag(v.Revision), Decision{State: state, Reason: "Prepare concurrent publication"})
			if err != nil {
				t.Fatal(err)
			}
			v = value.(Version)
		}
		app, r, c := preparedBrowser(t, f, "versions/"+v.ID+"/transition", []byte(jsonText(Decision{State: "published", Reason: "Publish during the logout race"})))
		r.Header.Set("If-Match", etag(v.Revision))
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var mutationErr, logoutErr error
		go func() { defer wg.Done(); <-start; _, mutationErr = app.write(r, c) }()
		go func() { defer wg.Done(); <-start; logoutErr = f.Auth.Logout(httptest.NewRecorder(), r) }()
		close(start)
		wg.Wait()
		if logoutErr != nil {
			t.Fatal(logoutErr)
		}
		if mutationErr == nil {
			var published, loggedOut int64
			f.Store.DB.QueryRow("SELECT MAX(id) FROM audit WHERE action='policy.published' AND result='committed'").Scan(&published)
			f.Store.DB.QueryRow("SELECT MAX(id) FROM audit WHERE action='auth.logout' AND result='committed'").Scan(&loggedOut)
			if published >= loggedOut {
				t.Fatal("publication committed after logout")
			}
		}
	}
}

func TestExpiryDuringTransactionRollsBack(t *testing.T) {
	s := storeFixture(t)
	op := humanOp()
	_, err := s.Mutation(op, "policy:write", true, func(tx *sql.Tx, _ *Operation) (any, error) {
		_, e := tx.Exec("UPDATE sessions SET expires=? WHERE id_hash=?", time.Now().Unix()-1, op.SessionHash)
		return map[string]string{"attempt": "expire during a mutation"}, e
	})
	if err == nil {
		t.Fatal("a transaction returned after its session expired")
	}
}

func TestCachedActivationRechecksAgentAndRestore(t *testing.T) {
	for _, cause := range []string{"disabled-agent", "restore"} {
		t.Run(cause, func(t *testing.T) {
			s := storeFixture(t)
			node, _, a := evidenceAdmission(t, s)
			op := Operation{Actor: node, Idempotency: "cached-activation", BodyDigest: "exact-activation", ProofNonce: "initial-proof"}
			in := ActivateInput{a.VersionID, a.PolicyDigest, grant.Digest([]byte("controlled-bpf-object")), "Activate the exact cached fixture"}
			if _, err := s.Activate(op, a.ID, in); err != nil {
				t.Fatal(err)
			}
			if cause == "disabled-agent" {
				if _, err := s.SetServiceStatus(humanOp(), a.AgentID, ServiceStatus{false, "Disable before a cached reply"}); err != nil {
					t.Fatal(err)
				}
			} else {
				root := t.TempDir()
				snapshot := filepath.Join(root, "snapshot")
				if err := s.Backup(snapshot); err != nil {
					t.Fatal(err)
				}
				dest := filepath.Join(root, "restored")
				if err := RestoreNew(snapshot, dest); err != nil {
					t.Fatal(err)
				}
				restored, err := OpenStore(dest)
				if err != nil {
					t.Fatal(err)
				}
				defer restored.DB.Close()
				s = restored
			}
			op.ProofNonce = "fresh-proof"
			if _, err := s.Activate(op, a.ID, in); err == nil {
				t.Fatal("a cached activation bypassed current authorization")
			}
		})
	}
}

func TestNonceAndDenialCommitTogether(t *testing.T) {
	s := storeFixture(t)
	actor, _ := enroll(t, s, "nonce-denial-agent", "agent", []string{"request:create"})
	op := Operation{Actor: actor, ProofNonce: "denied-proof"}
	_, err := s.RequestPolicy(op, RequestPolicy{VersionID: "unknown", Reason: "Try an unknown policy"})
	if err == nil {
		t.Fatal("invalid request succeeded")
	}
	var n int
	s.DB.QueryRow("SELECT COUNT(*) FROM nonces WHERE actor=? AND nonce=?", actor.Subject, op.ProofNonce).Scan(&n)
	if n != 1 {
		t.Fatal("denial lost its replay tombstone")
	}
	s.DB.Exec(`CREATE TRIGGER reject_denial BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'denial audit failure'); END;`)
	op.ProofNonce = "audit-failure-proof"
	_, err = s.RequestPolicy(op, RequestPolicy{VersionID: "unknown", Reason: "Fail audit persistence"})
	if err == nil {
		t.Fatal("denial audit failure disappeared")
	}
	s.DB.QueryRow("SELECT COUNT(*) FROM nonces WHERE nonce=?", op.ProofNonce).Scan(&n)
	if n != 0 {
		t.Fatal("a nonce committed without its denial audit")
	}
}

func TestCachedGrantCannotSurviveRestore(t *testing.T) {
	s := storeFixture(t)
	v := publish(t, s, createVersion(t, s))
	agent, _ := enroll(t, s, "cached-restore-agent", "agent", []string{"request:create"})
	node, _ := enroll(t, s, "cached-restore-node", "service", []string{"admission:write"})
	value, err := s.RequestPolicy(Operation{Actor: agent}, RequestPolicy{VersionID: v.ID, Reason: "Request one exact cached grant"})
	if err != nil {
		t.Fatal(err)
	}
	q := value.(PolicyRequest)
	if _, err = s.DecideRequest(humanOp(), q.ID, etag(1), Decision{State: "approved", Reason: "Approve one cached grant"}); err != nil {
		t.Fatal(err)
	}
	op := Operation{Actor: node, Idempotency: "cached-grant", BodyDigest: "exact-grant", ProofNonce: "initial-cached-grant-proof"}
	in := AdmitInput{q.ID, "cached-grant-run", "synthetic-node", "boot", "42", "/var/lib/cached/workspace/", "9007199254740993", "Admit one exact cached grant"}
	if _, err = s.Admit(op, in); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	snapshot := filepath.Join(root, "snapshot")
	if err = s.Backup(snapshot); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "restored")
	if err = RestoreNew(snapshot, dest); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenStore(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.DB.Close()
	op.ProofNonce = "fresh-cached-grant-proof"
	if _, err = restored.Admit(op, in); err == nil {
		t.Fatal("cached grant returned an approval from before restore")
	}
}

func TestConcurrentReadProofAdmitsOneAttempt(t *testing.T) {
	f := authTestFixture(t)
	actor, key := enroll(t, f.Store, "concurrent-read-agent", "agent", []string{"policy:read"})
	path := "/api/v1/policies"
	proof := SignProof(actor.Subject, "GET", path, nil, key, f.App.URL, f.Auth.Epoch)
	var wg sync.WaitGroup
	results := make(chan int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, _ := http.NewRequest("GET", f.App.URL+path, nil)
			r.Header.Set("Authorization", "Alloyium-Proof "+proof)
			response, err := f.Client.Do(r)
			if err != nil {
				results <- 0
				return
			}
			defer response.Body.Close()
			results <- response.StatusCode
		}()
	}
	wg.Wait()
	close(results)
	accepted := 0
	for status := range results {
		if status == 200 {
			accepted++
		} else if status != 409 {
			t.Fatalf("unexpected read status %d", status)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d reads with one proof", accepted)
	}
}

func TestDisabledProofRemainsConsumedAfterEnable(t *testing.T) {
	f := authTestFixture(t)
	actor, key := enroll(t, f.Store, "disabled-proof-agent", "agent", []string{"policy:read"})
	if _, err := f.Store.SetServiceStatus(humanOp(), actor.Subject, ServiceStatus{false, "Disable before a signed read"}); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/policies"
	proof := SignProof(actor.Subject, "GET", path, nil, key, f.App.URL, f.Auth.Epoch)
	read := func() int {
		r, _ := http.NewRequest("GET", f.App.URL+path, nil)
		r.Header.Set("Authorization", "Alloyium-Proof "+proof)
		response, err := f.Client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	if read() != 401 {
		t.Fatal("disabled identity read succeeded")
	}
	if _, err := f.Store.SetServiceStatus(humanOp(), actor.Subject, ServiceStatus{true, "Enable after the denied proof"}); err != nil {
		t.Fatal(err)
	}
	if read() != 409 {
		t.Fatal("a denied read proof survived identity enable")
	}
}

func TestCachedPublicationAndDecisionRequireLiveBinding(t *testing.T) {
	for _, action := range []string{"publication", "decision"} {
		t.Run(action, func(t *testing.T) {
			f := authTestFixture(t)
			response, _ := loginFlow(t, f, "admin")
			response.Body.Close()
			v := createVersion(t, f.Store)
			path := "versions/" + v.ID + "/transition"
			body := []byte(jsonText(Decision{State: "published", Reason: "Publish one immutable cached version"}))
			revision := 3
			if action == "publication" {
				for _, state := range []string{"proposed", "approved"} {
					value, err := f.Store.Transition(humanOp(), v.ID, etag(v.Revision), Decision{State: state, Reason: "Prepare one cached publication"})
					if err != nil {
						t.Fatal(err)
					}
					v = value.(Version)
				}
			} else {
				v = publish(t, f.Store, v)
				agent, _ := enroll(t, f.Store, "cached-decision-agent", "agent", []string{"request:create"})
				value, err := f.Store.RequestPolicy(Operation{Actor: agent}, RequestPolicy{VersionID: v.ID, Reason: "Request one cached decision"})
				if err != nil {
					t.Fatal(err)
				}
				q := value.(PolicyRequest)
				path = "requests/" + q.ID + "/decision"
				body = []byte(jsonText(Decision{State: "approved", VersionID: v.ID, Reason: "Approve one exact cached request"}))
				revision = 1
			}
			app, r, c := preparedBrowser(t, f, path, body)
			r.Header.Set("If-Match", etag(revision))
			if _, err := app.write(r, c); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Store.DB.Exec("DELETE FROM sessions WHERE id_hash=?", c.Operation.SessionHash); err != nil {
				t.Fatal(err)
			}
			if _, err := app.write(r, c); err == nil {
				t.Fatal("cached privileged reply survived session deletion")
			}
		})
	}
}

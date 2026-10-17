// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package control

import (
	"alloyium.local/kernel-poc/internal/grant"
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestReviewerPreparedHumanMustReauthorize(t *testing.T) {
	for _, mode := range []string{"logout", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			f := authTestFixture(t)
			res, _ := loginFlow(t, f, "admin")
			res.Body.Close()
			session := readSession(t, f)
			app := NewServer(f.Store, f.Auth, filepath.Join(t.TempDir(), "spool"), t.TempDir())
			body := []byte(`{"name":"Prepared stale policy","rights":{"workspace_write":true,"tcp_address":"127.0.0.1","tcp_port":18081},"reason":"Review the session authorization race"}`)
			r := httptest.NewRequest("POST", f.App.URL+"/api/v1/policies", bytes.NewReader(body))
			for _, c := range f.Client.Jar.Cookies(r.URL) {
				r.AddCookie(c)
			}
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", f.App.URL)
			r.Header.Set("X-CSRF-Token", session.CSRF)
			c, err := app.prepare(r)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "logout" {
				if err = f.Auth.Logout(httptest.NewRecorder(), r); err != nil {
					t.Fatal(err)
				}
			} else {
				if _, err = f.Store.DB.Exec("UPDATE sessions SET expires=?", time.Now().Unix()-1); err != nil {
					t.Fatal(err)
				}
			}
			if _, err = f.Auth.Session(r); err == nil {
				t.Fatal("fixture did not revoke the session")
			}
			value, err := app.write(r, c)
			if err == nil {
				t.Fatalf("STALE_HUMAN_COMMITTED after %s: %s", mode, jsonText(value))
			}
		})
	}
}

func TestReviewerRestoredIssuedGrantMustFenceActivation(t *testing.T) {
	root := t.TempDir()
	s, err := OpenStore(filepath.Join(root, "original"))
	if err != nil {
		t.Fatal(err)
	}
	node, _, a := evidenceAdmission(t, s)
	if err = s.Backup(filepath.Join(root, "snapshot")); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	if err = RestoreNew(filepath.Join(root, "snapshot"), filepath.Join(root, "restored")); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(filepath.Join(root, "restored"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	op := Operation{Actor: node, ProofNonce: "fresh-restore-proof", Idempotency: "fresh-restore-activation", BodyDigest: "exact-activation"}
	in := ActivateInput{a.VersionID, a.PolicyDigest, grant.Digest([]byte("controlled-bpf-object")), "Activate a restored issued grant without a fresh human decision"}
	value, err := s.Activate(op, a.ID, in)
	if err == nil {
		t.Fatalf("RESTORED_GRANT_ADMITTED without a new human decision: %s", jsonText(value))
	}
}

func TestReviewerDisabledAgentMustFenceActivation(t *testing.T) {
	s := storeFixture(t)
	node, _, a := evidenceAdmission(t, s)
	if _, err := s.SetServiceStatus(humanOp(), a.AgentID, ServiceStatus{false, "Disable the requested agent before activation"}); err != nil {
		t.Fatal(err)
	}
	value, err := s.Activate(Operation{Actor: node}, a.ID, ActivateInput{a.VersionID, a.PolicyDigest, grant.Digest([]byte("controlled-bpf-object")), "Activate after the agent was disabled"})
	if err == nil {
		t.Fatalf("DISABLED_AGENT_ADMITTED: %s", jsonText(value))
	}
}

func TestReviewerProofReplayOnRead(t *testing.T) {
	f := authTestFixture(t)
	actor, key := enroll(t, f.Store, "review-read-agent", "agent", []string{"policy:read"})
	path := "/api/v1/policies"
	proof := SignProof(actor.Subject, "GET", path, nil, key, f.App.URL, f.Auth.Epoch)
	for i := 0; i < 2; i++ {
		r, _ := http.NewRequest("GET", f.App.URL+path, nil)
		r.Header.Set("Authorization", "Alloyium-Proof "+proof)
		res, err := f.Client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		if i == 1 && res.StatusCode == 200 {
			t.Fatal("REPEATED_READ_PROOF_ACCEPTED")
		}
	}
}

func TestReviewerDeniedProofMustStayConsumed(t *testing.T) {
	f := authTestFixture(t)
	actor, key := enroll(t, f.Store, "review-denied-proof-agent", "agent", []string{"request:create", "policy:read"})
	v := createVersion(t, f.Store)
	body := []byte(jsonText(RequestPolicy{VersionID: v.ID, Reason: "Request the draft policy with one signed proof"}))
	path := "/api/v1/requests"
	proof := SignProof(actor.Subject, "POST", path, body, key, f.App.URL, f.Auth.Epoch)
	post := func() int {
		r, _ := http.NewRequest("POST", f.App.URL+path, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Alloyium-Proof "+proof)
		res, err := f.Client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if status := post(); status != 409 {
		t.Fatalf("expected unpublished denial, got %d", status)
	}
	publish(t, f.Store, v)
	if status := post(); status == 200 {
		t.Fatal("DENIED_MUTATION_PROOF_REPLAY_CREATED_REQUEST")
	}
}

func TestReviewerRequiredStatusField(t *testing.T) {
	f := authTestFixture(t)
	res, _ := loginFlow(t, f, "admin")
	res.Body.Close()
	session := readSession(t, f)
	actor, _ := enroll(t, f.Store, "review-status-agent", "agent", []string{"policy:read"})
	body := []byte(`{"reason":"The caller omitted the required enabled field"}`)
	r, _ := http.NewRequest("POST", f.App.URL+"/api/v1/agents/"+actor.Subject+"/status", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.App.URL)
	r.Header.Set("X-CSRF-Token", session.CSRF)
	res, err := f.Client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	svc, err := serviceFrom(f.Store.DB, actor.Subject)
	if err != nil {
		t.Fatal(err)
	}
	if res.StatusCode == 200 && !svc.Enabled {
		t.Fatal("OMITTED_ENABLED_FIELD_DISABLED_AGENT")
	}
}

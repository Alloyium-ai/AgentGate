// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/control/oidctest"
)

type authFixture struct {
	Store  *Store
	Auth   *Auth
	App    *httptest.Server
	Issuer *oidctest.Issuer
	Client *http.Client
}

func authTestFixture(t *testing.T) *authFixture {
	t.Helper()
	store := storeFixture(t)
	issuer := oidctest.New()
	t.Cleanup(issuer.Close)
	app := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(app.Close)
	cfg := AuthConfig{Issuer: issuer.URL(), ClientID: issuer.ClientID, ClientSecret: issuer.Secret, PublicURL: app.URL, GroupRoles: map[string][]string{"admins": {"admin"}, "editors": {"editor"}, "viewers": {"viewer"}, "approvers": {"approver"}, "auditors": {"auditor"}}, SessionLifetime: time.Minute}
	auth, err := NewAuth(context.Background(), store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	seedHumanSession(store)
	issuer.Redirect = app.URL + "/auth/callback"
	server := NewServer(store, auth, filepath.Join(t.TempDir(), "spool"), t.TempDir())
	app.Config.Handler = server.Handler()
	client := app.Client()
	client.Jar, _ = cookiejar.New(nil)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &authFixture{store, auth, app, issuer, client}
}
func loginFlow(t *testing.T, f *authFixture, user string) (*http.Response, string) {
	t.Helper()
	response, err := f.Client.Get(f.App.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	authorization := response.Header.Get("Location")
	response.Body.Close()
	if !strings.Contains(authorization, "code_challenge_method=S256") {
		t.Fatal("PKCE S256 absent")
	}
	response, err = f.Client.Get(f.Issuer.CompleteURL(authorization, user))
	if err != nil {
		t.Fatal(err)
	}
	callback := response.Header.Get("Location")
	response.Body.Close()
	response, err = f.Client.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	return response, callback
}
func readSession(t *testing.T, f *authFixture) Session {
	t.Helper()
	response, err := f.Client.Get(f.App.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		b, _ := io.ReadAll(response.Body)
		t.Fatalf("session %d: %s", response.StatusCode, b)
	}
	var s Session
	if err = json.NewDecoder(response.Body).Decode(&s); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestOIDCCodeFlowAndStateReplay(t *testing.T) {
	f := authTestFixture(t)
	response, callback := loginFlow(t, f, "admin")
	response.Body.Close()
	if response.StatusCode != 302 {
		t.Fatalf("login failed %d", response.StatusCode)
	}
	session := readSession(t, f)
	if session.Actor.Kind != "human" || !session.Actor.Can("decision:write") {
		t.Fatal("OIDC roles lost")
	}
	response, err := f.Client.Get(callback)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode == 302 && response.Header.Get("Location") == "/" {
		t.Fatal("state replay created a session")
	}
	var n int
	f.Store.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE id_hash<>?", digest([]byte("unit-fixture-human-session"))).Scan(&n)
	if n != 1 {
		t.Fatal("state replay changed sessions")
	}
}
func TestOIDCRejectsUntrustedTokensAndGroups(t *testing.T) {
	for _, mode := range []string{"wrong-issuer", "wrong-audience", "expired", "wrong-nonce", "unknown-groups", "machine-account"} {
		t.Run(mode, func(t *testing.T) {
			f := authTestFixture(t)
			f.Issuer.Mode(mode)
			user := "admin"
			if mode == "unknown-groups" {
				user = "untrusted"
			}
			response, _ := loginFlow(t, f, user)
			response.Body.Close()
			if response.StatusCode == 302 && response.Header.Get("Location") == "/" {
				t.Fatalf("accepted %s", mode)
			}
			var n int
			f.Store.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE id_hash<>?", digest([]byte("unit-fixture-human-session"))).Scan(&n)
			if n != 0 {
				t.Fatal("invalid login persisted a session")
			}
		})
	}
}
func TestCSRFRoleBypassAndSessionExpiry(t *testing.T) {
	f := authTestFixture(t)
	response, _ := loginFlow(t, f, "viewer")
	response.Body.Close()
	session := readSession(t, f)
	body := []byte(`{"name":"Synthetic unauthorized policy","description":"","rights":{"workspace_write":true,"tcp_address":"127.0.0.1","tcp_port":18081},"reason":"Try a role bypass"}`)
	request, _ := http.NewRequest("POST", f.App.URL+"/api/v1/policies", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := f.Client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("missing CSRF accepted")
	}
	request, _ = http.NewRequest("POST", f.App.URL+"/api/v1/policies", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", f.App.URL)
	request.Header.Set("X-CSRF-Token", session.CSRF)
	response, err = f.Client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 403 {
		t.Fatal("viewer bypassed server authorization")
	}
	f.Store.DB.Exec("UPDATE sessions SET expires=?", time.Now().Unix()-1)
	response, err = f.Client.Get(f.App.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("expired session accepted")
	}
}
func TestMachineProofBindsBodyAndRejectsReplay(t *testing.T) {
	f := authTestFixture(t)
	agent, key := enroll(t, f.Store, "synthetic-machine-agent", "agent", []string{"request:create", "proposal:create", "policy:read"})
	v := publish(t, f.Store, createVersion(t, f.Store))
	body := []byte(jsonText(RequestPolicy{VersionID: v.ID, Reason: "Run a controlled fixture"}))
	path := "/api/v1/requests"
	proof := SignProof(agent.Subject, "POST", path, body, key, f.App.URL, f.Auth.Epoch)
	post := func(payload []byte) int {
		r, _ := http.NewRequest("POST", f.App.URL+path, bytes.NewReader(payload))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Alloyium-Proof "+proof)
		res, e := f.Client.Do(r)
		if e != nil {
			t.Fatal(e)
		}
		defer res.Body.Close()
		return res.StatusCode
	}
	if post(body) != 200 {
		t.Fatal("valid proof failed")
	}
	if post(body) != 409 {
		t.Fatal("proof replay accepted")
	}
	if post([]byte(`{"version_id":"other","reason":"changed"}`)) != 401 {
		t.Fatal("proof did not bind request body")
	}
}

func TestIdempotencyBindsTheMutationResource(t *testing.T) {
	f := authTestFixture(t)
	res, _ := loginFlow(t, f, "admin")
	res.Body.Close()
	session := readSession(t, f)
	first := createVersion(t, f.Store)
	second := createVersion(t, f.Store)
	for _, v := range []Version{first, second} {
		if _, err := f.Store.Transition(humanOp(), v.ID, etag(1), Decision{State: "proposed", Reason: "Submit a separate immutable version"}); err != nil {
			t.Fatal(err)
		}
	}
	body := []byte(`{"state":"approved","reason":"Approve this exact resource"}`)
	post := func(id string) int {
		r, _ := http.NewRequest("POST", f.App.URL+"/api/v1/versions/"+id+"/transition", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", f.App.URL)
		r.Header.Set("X-CSRF-Token", session.CSRF)
		r.Header.Set("If-Match", etag(2))
		r.Header.Set("Idempotency-Key", "one-resource-decision")
		response, err := f.Client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}
	if post(first.ID) != 200 || post(second.ID) != 409 {
		t.Fatal("an idempotency key crossed the resource boundary")
	}
	v, err := versionFrom(f.Store.DB, second.ID)
	if err != nil || v.State != "proposed" {
		t.Fatal("the conflicting request changed its version")
	}
}

func TestAPIBoundsAndHistoryMethod(t *testing.T) {
	f := authTestFixture(t)
	res, _ := loginFlow(t, f, "admin")
	res.Body.Close()
	session := readSession(t, f)
	r, _ := http.NewRequest("POST", f.App.URL+"/api/v1/policies", bytes.NewReader(make([]byte, (4<<20)+1)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.App.URL)
	r.Header.Set("X-CSRF-Token", session.CSRF)
	res, err := f.Client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 413 {
		t.Fatal("oversized body entered the API")
	}
	r, _ = http.NewRequest("DELETE", f.App.URL+"/api/v1/policies", strings.NewReader("{}"))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.App.URL)
	r.Header.Set("X-CSRF-Token", session.CSRF)
	res, err = f.Client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 405 {
		t.Fatal("history removal endpoint exists")
	}
	res, err = f.Client.Get(f.App.URL + "/api/v1/events/invalid")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 404 {
		t.Fatal("an invalid stream path entered the event loop")
	}
}

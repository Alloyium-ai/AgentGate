// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const localTestPassword = "synthetic-only-passphrase-2026"

func localFixture(t *testing.T) (*Store, *Auth) {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "store"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	if err = s.BootstrapAdmin("operator", "Synthetic operator", localTestPassword); err != nil {
		t.Fatal(err)
	}
	a, err := NewAuth(context.Background(), s, AuthConfig{AuthMode: "local", Instance: "synthetic-instance", PublicURL: "https://community.example.test", SessionLifetime: time.Hour, GroupRoles: map[string][]string{"local:operator": {"admin"}}})
	if err != nil {
		t.Fatal(err)
	}
	return s, a
}
func localLoginFixture(t *testing.T, a *Auth) (*http.Cookie, Session) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://community.example.test/auth/local/challenge", nil)
	if err := a.LocalChallenge(w, r); err != nil {
		t.Fatal(err)
	}
	var challenge map[string]string
	json.Unmarshal(w.Body.Bytes(), &challenge)
	login := httptest.NewRequest("POST", "https://community.example.test/auth/local/login", strings.NewReader(`{"username":"operator","password":"`+localTestPassword+`"}`))
	login.AddCookie(w.Result().Cookies()[0])
	login.Header.Set("Origin", a.Config.PublicURL)
	login.Header.Set("Content-Type", "application/json")
	login.Header.Set("X-CSRF-Token", challenge["csrf_token"])
	w = httptest.NewRecorder()
	if err := a.LocalLogin(w, login); err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "__Host-enforcer-session" {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatal("local session cookie lost its protection")
	}
	r = httptest.NewRequest("GET", "https://community.example.test/api/v1/session", nil)
	r.AddCookie(cookie)
	session, err := a.Session(r)
	if err != nil {
		t.Fatal(err)
	}
	return cookie, session
}
func TestLocalBootstrapSessionAndCSRF(t *testing.T) {
	s, a := localFixture(t)
	if err := s.BootstrapAdmin("otheradmin", "Other", localTestPassword); err == nil {
		t.Fatal("second first administrator accepted")
	}
	cookie, session := localLoginFixture(t, a)
	if session.Actor.Subject != "local:operator" || len(session.Actor.Groups) != 0 || !session.Actor.Can("users:write") {
		t.Fatal("local login did not use local roles")
	}
	r := httptest.NewRequest("POST", "https://community.example.test/api/v1/policies", nil)
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://untrusted.example.test")
	r.Header.Set("X-CSRF-Token", session.CSRF)
	if a.CSRF(r, session) == nil {
		t.Fatal("cross-origin local mutation accepted")
	}
	r.Header.Set("Origin", a.Config.PublicURL)
	if err := a.CSRF(r, session); err != nil {
		t.Fatal(err)
	}
}
func TestLocalRolesRecheckInsideMutation(t *testing.T) {
	s, a := localFixture(t)
	_, session := localLoginFixture(t, a)
	op := Operation{Actor: session.Actor, SessionHash: session.Binding, RequestID: newID()}
	_, err := s.Mutation(op, "policy:write", true, func(tx *sql.Tx, _ *Operation) (any, error) {
		_, err := tx.Exec(`UPDATE local_users SET roles='["viewer"]' WHERE username='operator'`)
		return map[string]string{"changed": "yes"}, err
	})
	if err == nil {
		t.Fatal("local role loss after entry authorized the commit")
	}
	current, err := localUserFrom(s.DB, "operator")
	if err != nil || !hasAdmin(current.Roles) {
		t.Fatal("denied transaction did not roll back roles")
	}
	if _, err = s.DB.Exec(`UPDATE local_users SET roles='["viewer"]' WHERE username='operator'`); err != nil {
		t.Fatal(err)
	}
	_, err = s.CreatePolicy(op, CreatePolicy{"Denied policy", "", Rights{true, "127.0.0.1", 18081}, "Reject stale administrator roles"})
	if err == nil {
		t.Fatal("stale session roles authorized a mutation")
	}
}
func TestLocalStatusAndPasswordRevokeSessions(t *testing.T) {
	s, a := localFixture(t)
	cookie, session := localLoginFixture(t, a)
	admin := Operation{Actor: session.Actor, SessionHash: session.Binding, RequestID: newID()}
	_, err := s.PutUser(admin, UserInput{Username: "secondadmin", Name: "Synthetic second", Roles: []string{"admin"}, Enabled: true, Password: localTestPassword, Reason: "Enroll a second administrator"})
	if err != nil {
		t.Fatal(err)
	}
	// Bind a synthetic second administrator session, then disable the first one.
	other := Actor{Subject: "local:secondadmin", Kind: "human", Roles: []string{"admin"}}
	binding := digest([]byte("synthetic-second-session"))
	s.DB.Exec("INSERT INTO sessions VALUES(?,?,?,?)", binding, jsonText(sessionActor{other, a.LoginAuthority}), "synthetic-csrf", time.Now().Add(time.Hour).Unix())
	_, err = s.PutUser(Operation{Actor: other, SessionHash: binding, RequestID: newID()}, UserInput{Username: "operator", Name: "Synthetic operator", Roles: []string{"admin"}, Enabled: false, Parent: 1, Reason: "Disable the first identity"})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "https://community.example.test/api/v1/session", nil)
	r.AddCookie(cookie)
	if _, err = a.Session(r); err == nil {
		t.Fatal("disabled local user retained a session")
	}
	if _, err = s.CreatePolicy(admin, CreatePolicy{"Denied policy", "", Rights{true, "127.0.0.1", 18081}, "Reject a disabled user"}); err == nil {
		t.Fatal("disabled local user authorized a transaction")
	}
	_, err = s.PutUser(Operation{Actor: other, SessionHash: binding, RequestID: newID()}, UserInput{Username: "secondadmin", Name: "Synthetic second", Roles: []string{"viewer"}, Enabled: true, Parent: 1, Reason: "Try to remove the last admin"})
	if err == nil {
		t.Fatal("last administrator removed")
	}
}
func TestLocalChallengeCannotReplayOrCrossOrigin(t *testing.T) {
	_, a := localFixture(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://community.example.test/auth/local/challenge", nil)
	if err := a.LocalChallenge(w, r); err != nil {
		t.Fatal(err)
	}
	var challenge map[string]string
	json.Unmarshal(w.Body.Bytes(), &challenge)
	r = httptest.NewRequest("POST", "https://community.example.test/auth/local/login", nil)
	r.AddCookie(w.Result().Cookies()[0])
	r.Header.Set("X-CSRF-Token", challenge["csrf_token"])
	r.Header.Set("Origin", "https://untrusted.example.test")
	if a.consumeLocalChallenge(r) == nil {
		t.Fatal("cross-origin login accepted")
	}
	r.Header.Set("Origin", a.Config.PublicURL)
	if err := a.consumeLocalChallenge(r); err != nil {
		t.Fatal(err)
	}
	if a.consumeLocalChallenge(r) == nil {
		t.Fatal("challenge replay accepted")
	}
}
func TestLocalAndOIDCNamespacesStaySeparate(t *testing.T) {
	s, a := localFixture(t)
	// The OIDC group name equals the local subject. It must use only the OIDC role map.
	a.Config.GroupRoles = map[string][]string{"local:operator": {"viewer"}}
	actor := Actor{Subject: "oidc:local:operator", Kind: "human", Groups: []string{"local:operator"}, Roles: []string{"admin"}}
	binding := digest([]byte("synthetic-oidc-session"))
	s.DB.Exec("INSERT INTO sessions VALUES(?,?,?,?)", binding, jsonText(sessionActor{actor, a.LoginAuthority}), "csrf", time.Now().Add(time.Hour).Unix())
	_, err := s.CreatePolicy(Operation{Actor: actor, SessionHash: binding}, CreatePolicy{"Denied policy", "", Rights{true, "127.0.0.1", 18081}, "Reject namespace collision"})
	if err == nil {
		t.Fatal("OIDC group name acquired local administrator rights")
	}
}

func TestOIDCAdministratorCannotSelectLocalAccountAuthority(t *testing.T) {
	s, a := localFixture(t)
	a.Config.GroupRoles = map[string][]string{"local:operator": {"admin"}}
	actor := Actor{Subject: "oidc:external-administrator", Kind: "human", Groups: []string{"local:operator"}, Roles: []string{"admin"}}
	binding := digest([]byte("synthetic-external-admin-session"))
	s.DB.Exec("INSERT INTO sessions VALUES(?,?,?,?)", binding, jsonText(sessionActor{actor, a.LoginAuthority}), "csrf", time.Now().Add(time.Hour).Unix())
	_, err := s.PutUser(Operation{Actor: actor, SessionHash: binding, RequestID: newID()}, UserInput{Username: "externaladmin", Name: "Synthetic external", Roles: []string{"admin"}, Enabled: true, Password: localTestPassword, Reason: "Try to select local administrator authority"})
	if err == nil {
		t.Fatal("OIDC groups granted local account administration")
	}
}

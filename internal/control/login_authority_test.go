// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

func sessionRequest(t *testing.T, f *authFixture) *http.Request {
	t.Helper()
	request := httptest.NewRequest("GET", f.App.URL+"/api/v1/session", nil)
	u, _ := url.Parse(f.App.URL)
	for _, cookie := range f.Client.Jar.Cookies(u) {
		request.AddCookie(cookie)
	}
	return request
}
func TestSessionAuthorityPersistsAcrossUnchangedRestart(t *testing.T) {
	f := authTestFixture(t)
	response, _ := loginFlow(t, f, "admin")
	response.Body.Close()
	request := sessionRequest(t, f)
	original := f.Auth.LoginAuthority
	cfg := f.Auth.Config
	cfg.GroupRoles = map[string][]string{"admins": {"viewer"}}
	restarted, err := NewAuth(context.Background(), f.Store, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.LoginAuthority != original {
		t.Fatal("role change altered login authority")
	}
	session, err := restarted.Session(request)
	if err != nil {
		t.Fatal(err)
	}
	if session.Actor.Can("policy:write") || !session.Actor.Can("policy:read") {
		t.Fatal("session did not use current roles")
	}
	if restarted.Epoch == f.Auth.Epoch {
		t.Fatal("machine epoch did not change")
	}
}
func TestSessionAuthorityRejectsEachConfiguredIdentityChange(t *testing.T) {
	for _, kind := range []string{"client", "origin", "lifetime"} {
		t.Run(kind, func(t *testing.T) {
			f := authTestFixture(t)
			response, _ := loginFlow(t, f, "admin")
			response.Body.Close()
			request := sessionRequest(t, f)
			cfg := f.Auth.Config
			switch kind {
			case "client":
				cfg.ClientID = "changed-client"
			case "origin":
				cfg.PublicURL = "https://changed.example"
			case "lifetime":
				cfg.SessionLifetime = 2 * time.Minute
			}
			restarted, err := NewAuth(context.Background(), f.Store, cfg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = restarted.Session(request); err == nil {
				t.Fatal("old session survived identity change")
			}
			var count int
			f.Store.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&count)
			if count != 0 {
				t.Fatal("identity change retained a prior session")
			}
		})
	}
}
func TestPendingLoginAuthorityBindingAndUnchangedRestart(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unchanged", true: "changed"}[changed], func(t *testing.T) {
			f := authTestFixture(t)
			start := httptest.NewRecorder()
			request := httptest.NewRequest("GET", f.App.URL+"/auth/login", nil)
			if err := f.Auth.Login(start, request); err != nil {
				t.Fatal(err)
			}
			authURL, err := url.Parse(start.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			callback := httptest.NewRequest("GET", f.App.URL+"/auth/callback?state="+url.QueryEscape(authURL.Query().Get("state")), nil)
			for _, cookie := range start.Result().Cookies() {
				callback.AddCookie(cookie)
			}
			cfg := f.Auth.Config
			if changed {
				cfg.SessionLifetime = 2 * time.Minute
			}
			restarted, err := NewAuth(context.Background(), f.Store, cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = restarted.consumeState(callback)
			if changed && err == nil {
				t.Fatal("old pending state survived identity change")
			}
			if !changed && err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestPreparedAndCachedSessionRejectChangedAuthority(t *testing.T) {
	f := authTestFixture(t)
	response, _ := loginFlow(t, f, "admin")
	response.Body.Close()
	session, err := f.Auth.Session(sessionRequest(t, f))
	if err != nil {
		t.Fatal(err)
	}
	op := Operation{Actor: session.Actor, SessionHash: session.Binding, Action: "identity.fixture", Resource: "policy", Reason: "Check login authority", RequestID: newID(), Idempotency: "authority-once", BodyDigest: "fixture"}
	if _, err := f.Store.Mutation(op, "policy:write", true, func(*sql.Tx, *Operation) (any, error) { return map[string]string{"id": "fixture"}, nil }); err != nil {
		t.Fatal(err)
	}
	cfg := f.Auth.Config
	cfg.ClientID = "new-client"
	if _, err := NewAuth(context.Background(), f.Store, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Store.Mutation(op, "policy:write", true, func(*sql.Tx, *Operation) (any, error) { t.Fatal("old prepared callback executed"); return nil, nil }); err == nil {
		t.Fatal("cached reply survived identity change")
	}
	op.Idempotency = "new-operation"
	if _, err := f.Store.Mutation(op, "policy:write", true, func(*sql.Tx, *Operation) (any, error) { t.Fatal("old prepared mutation executed"); return nil, nil }); err == nil {
		t.Fatal("prepared session survived identity change")
	}
}
func TestRestoreClearsSessionsAndLoginStatesAtomically(t *testing.T) {
	root := t.TempDir()
	s, err := OpenStore(filepath.Join(root, "original"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	seedHumanSession(s)
	if _, err = s.DB.Exec("INSERT INTO login_states VALUES('pending','nonce','verifier','binding',?)", time.Now().Add(time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("CREATE TRIGGER fixture_refuse_login_delete BEFORE DELETE ON login_states BEGIN SELECT RAISE(ABORT,'fixture deny'); END;"); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(root, "snapshot")
	if err = s.Backup(snapshot); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "restored")
	if err = RestoreNew(snapshot, dest); err == nil {
		t.Fatal("partial restore clearing returned success")
	}
	restored, err := OpenStore(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.DB.Close()
	for _, table := range []string{"sessions", "login_states"} {
		var count int
		if err = restored.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count == 0 {
			t.Fatal("restore clearing escaped rollback", table)
		}
	}
}

func TestLegacyUnboundSessionNeedsFreshLogin(t *testing.T) {
	f := authTestFixture(t)
	response, _ := loginFlow(t, f, "admin")
	response.Body.Close()
	request := sessionRequest(t, f)
	session, err := f.Auth.Session(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.Store.DB.Exec("UPDATE sessions SET actor=? WHERE id_hash=?", jsonText(session.Actor), session.Binding); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Auth.Session(request); err == nil {
		t.Fatal("legacy unbound session authorized")
	}
}

func TestLoginAuthorityRollbackNeverRevivesPriorCredentials(t *testing.T) {
	f := authTestFixture(t)
	response, _ := loginFlow(t, f, "admin")
	response.Body.Close()
	request := sessionRequest(t, f)
	start := httptest.NewRecorder()
	if err := f.Auth.Login(start, httptest.NewRequest("GET", f.App.URL+"/auth/login", nil)); err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(start.Header().Get("Location"))
	callback := httptest.NewRequest("GET", f.App.URL+"/auth/callback?state="+url.QueryEscape(u.Query().Get("state")), nil)
	for _, cookie := range start.Result().Cookies() {
		callback.AddCookie(cookie)
	}
	original := f.Auth.Config
	changed := original
	changed.SessionLifetime = 2 * time.Minute
	if _, err := NewAuth(context.Background(), f.Store, changed); err != nil {
		t.Fatal(err)
	}
	restored, err := NewAuth(context.Background(), f.Store, original)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restored.Session(request); err == nil {
		t.Fatal("A-B-A revived the old session")
	}
	if _, _, err = restored.consumeState(callback); err == nil {
		t.Fatal("A-B-A revived a pending login")
	}
	var changes int
	f.Store.DB.QueryRow("SELECT count(*) FROM audit WHERE action='auth.authority.bound' AND result='committed'").Scan(&changes)
	if changes != 3 {
		t.Fatal("authority changes lack durable audit", changes)
	}
}
func TestLoginAuthorityChangeFailsClosedWhenAuditFails(t *testing.T) {
	f := authTestFixture(t)
	response, _ := loginFlow(t, f, "admin")
	response.Body.Close()
	request := sessionRequest(t, f)
	original := f.Auth.LoginAuthority
	if _, err := f.Store.DB.Exec("CREATE TRIGGER fixture_refuse_authority_audit BEFORE INSERT ON audit WHEN NEW.action='auth.authority.bound' BEGIN SELECT RAISE(ABORT,'fixture refusal'); END;"); err != nil {
		t.Fatal(err)
	}
	changed := f.Auth.Config
	changed.SessionLifetime = 2 * time.Minute
	if _, err := NewAuth(context.Background(), f.Store, changed); err == nil {
		t.Fatal("unaudited authority started")
	}
	if f.Store.LoginAuthority != original {
		t.Fatal("failed change altered the active authority")
	}
	if _, err := f.Auth.Session(request); err != nil {
		t.Fatal("failed change did not roll back session removal", err)
	}
}

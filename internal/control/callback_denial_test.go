// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"net/http"
	"strings"
	"testing"
)

func assertLoginDenial(t *testing.T, f *authFixture, response *http.Response, code, subject, kind string) {
	t.Helper()
	defer response.Body.Close()
	if response.StatusCode != 303 || response.Header.Get("Location") != "/?signin_error="+code {
		t.Fatalf("denial contract: %d %s", response.StatusCode, response.Header.Get("Location"))
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == "__Host-enforcer-session" {
			t.Fatal("denial set a session cookie")
		}
	}
	var actor, actorKind, result, after string
	if err := f.Store.DB.QueryRow("SELECT actor,actor_kind,result,after_json FROM audit WHERE action='auth.denied' ORDER BY id DESC LIMIT 1").Scan(&actor, &actorKind, &result, &after); err != nil {
		t.Fatal(err)
	}
	if actor != subject || actorKind != kind || result != "denied" || after != jsonText(map[string]string{"error_code": code}) {
		t.Fatalf("denial audit: %q %q %q %q", actor, actorKind, result, after)
	}
	var count int
	if err := f.Store.DB.QueryRow("SELECT COUNT(*) FROM sessions WHERE id_hash<>?", digest([]byte("unit-fixture-human-session"))).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("denial persisted a session")
	}
	res, err := f.Client.Get(f.App.URL + "/api/v1/session")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("denied caller acquired a session")
	}
}

func TestVerifiedCallbackDenialRetainsIdentity(t *testing.T) {
	for _, tc := range []struct{ mode, user, code, kind string }{
		{"unknown-groups", "untrusted", "untrusted_groups", "human"},
		{"machine-account", "admin", "machine_session_forbidden", "service"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := authTestFixture(t)
			f.Issuer.Mode(tc.mode)
			response, _ := loginFlow(t, f, tc.user)
			assertLoginDenial(t, f, response, tc.code, "synthetic-"+tc.user, tc.kind)
		})
	}
}

func TestUnverifiedCallbackDenialStaysAnonymous(t *testing.T) {
	for _, mode := range []string{"wrong-issuer", "wrong-audience", "expired", "invalid-signature", "wrong-nonce", "invalid-claims"} {
		t.Run(mode, func(t *testing.T) {
			f := authTestFixture(t)
			f.Issuer.Mode(mode)
			response, _ := loginFlow(t, f, "admin")
			code := "invalid_token"
			if mode == "wrong-nonce" {
				code = "invalid_nonce"
			}
			if mode == "invalid-claims" {
				code = "invalid_claims"
			}
			assertLoginDenial(t, f, response, code, "anonymous", "unknown")
		})
	}
	t.Run("invalid-state", func(t *testing.T) {
		f := authTestFixture(t)
		response, err := f.Client.Get(f.App.URL + "/auth/callback?code=synthetic-claimed-admin&state=" + strings.Repeat("x", 32))
		if err != nil {
			t.Fatal(err)
		}
		assertLoginDenial(t, f, response, "invalid_state", "anonymous", "unknown")
	})
}

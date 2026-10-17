// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/subtle"
	"database/sql"
	"io"
	"net/http"
	"strings"
	"time"
)

func (a *Auth) LocalEnabled() bool {
	return a.Config.AuthMode == "local" || a.Config.AuthMode == "both"
}
func (a *Auth) LocalChallenge(w http.ResponseWriter, r *http.Request) error {
	if !a.LocalEnabled() {
		return fail(404, "local_login_disabled", "Local sign-in is disabled.")
	}
	state, binding := randomToken(), randomToken()
	op := a.operation(r, "auth.local.started", Actor{Subject: "anonymous", Kind: "unknown", Scopes: []string{"auth:write"}})
	_, err := a.Store.Mutation(op, "auth:write", false, func(tx *sql.Tx, _ *Operation) (any, error) {
		if _, err := tx.Exec("DELETE FROM login_states WHERE expires<=?", time.Now().Unix()); err != nil {
			return nil, err
		}
		_, err := tx.Exec("INSERT INTO login_states VALUES(?,?,?,?,?)", digest([]byte(state)), "local", "", a.stateBinding(binding), time.Now().Add(5*time.Minute).Unix())
		return map[string]string{"result": "challenge issued"}, err
	})
	if err == nil {
		secureCookie(w, "__Host-enforcer-login", binding, 300)
		jsonResponse(w, 200, map[string]string{"csrf_token": state})
	}
	return err
}
func (a *Auth) consumeLocalChallenge(r *http.Request) error {
	cookie, err := r.Cookie("__Host-enforcer-login")
	state := r.Header.Get("X-CSRF-Token")
	if err != nil || len(state) != 43 || r.Header.Get("Origin") != strings.TrimRight(a.Config.PublicURL, "/") {
		return fail(403, "csrf_failed", "Start a local login from this application.")
	}
	op := a.operation(r, "auth.local.challenge.consumed", Actor{Subject: "anonymous", Kind: "unknown", Scopes: []string{"auth:write"}})
	_, err = a.Store.Mutation(op, "auth:write", false, func(tx *sql.Tx, _ *Operation) (any, error) {
		var mode, binding string
		var expires int64
		err := tx.QueryRow("SELECT nonce,binding_hash,expires FROM login_states WHERE state_hash=?", digest([]byte(state))).Scan(&mode, &binding, &expires)
		if err != nil || mode != "local" || expires <= time.Now().Unix() || subtle.ConstantTimeCompare([]byte(binding), []byte(a.stateBinding(cookie.Value))) != 1 {
			return nil, fail(403, "csrf_failed", "The local login challenge expired or changed.")
		}
		_, err = tx.Exec("DELETE FROM login_states WHERE state_hash=?", digest([]byte(state)))
		return map[string]string{"result": "consumed"}, err
	})
	return err
}
func (a *Auth) LocalLogin(w http.ResponseWriter, r *http.Request) error {
	if !a.LocalEnabled() {
		return fail(404, "local_login_disabled", "Local sign-in is disabled.")
	}
	if err := a.consumeLocalChallenge(r); err != nil {
		return err
	}
	secureCookie(w, "__Host-enforcer-login", "", -1)
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return fail(415, "json_required", "Use an application/json request.")
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, 4097))
	if err != nil || len(data) > 4096 {
		return fail(413, "body_too_large", "The local login request is too large.")
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err = decodeBody(data, &in); err != nil {
		return err
	}
	if !localUsername.MatchString(in.Username) || len(in.Password) > 256 {
		return fail(401, "invalid_credentials", "The username or password is invalid.")
	}
	// The server bounds concurrent login requests before password derivation.
	actor, err := authenticateLocal(a.Store.DB, in.Username, in.Password)
	if err != nil {
		return err
	}
	sid, csrf := randomToken(), randomToken()
	expires := time.Now().Add(a.Config.SessionLifetime).Unix()
	op := a.operation(r, "auth.local.completed", Actor{Subject: actor.Subject, Kind: "system", Scopes: []string{"auth:write"}})
	op.SessionHash = digest([]byte(sid))
	_, err = a.Store.Mutation(op, "auth:write", false, func(tx *sql.Tx, operation *Operation) (any, error) {
		// Recheck the credential inside the transaction to reject concurrent password changes.
		current, err := authenticateLocal(tx, in.Username, in.Password)
		if err != nil {
			return nil, err
		}
		operation.Actor = current
		_, err = tx.Exec("INSERT INTO sessions VALUES(?,?,?,?)", op.SessionHash, jsonText(sessionActor{current, a.LoginAuthority}), csrf, expires)
		return map[string]any{"subject": current.Subject, "expires": expires}, err
	})
	if err == nil {
		secureCookie(w, "__Host-enforcer-session", sid, int(expires-time.Now().Unix()))
		jsonResponse(w, 200, map[string]string{"result": "signed in"})
	}
	return err
}

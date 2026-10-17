// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// The stored binding is internal. API actors retain the existing public shape.
type sessionActor struct {
	Actor
	LoginAuthority string `json:"login_authority"`
}

func loginAuthority(c AuthConfig) string {
	if c.Instance != "" {
		return digest([]byte(jsonText(struct {
			Schema, Instance, AuthMode, Issuer, ClientID, Origin string
			Lifetime                                             int64
		}{"agentgate.community.login-authority.v1", c.Instance, c.AuthMode, c.Issuer, c.ClientID, strings.TrimRight(c.PublicURL, "/"), int64(c.SessionLifetime)})))
	}
	context := struct {
		Schema   string `json:"schema"`
		Issuer   string `json:"issuer"`
		ClientID string `json:"client_id"`
		Origin   string `json:"origin"`
		Lifetime int64  `json:"lifetime_ns"`
	}{"agentgate.login-authority.v1", c.Issuer, c.ClientID, strings.TrimRight(c.PublicURL, "/"), int64(c.SessionLifetime)}
	return digest([]byte(jsonText(context)))
}
func (a *Auth) stateBinding(cookie string) string {
	return digest([]byte(a.LoginAuthority + "\x00" + cookie))
}
func (a *Auth) operation(r *http.Request, action string, actor Actor) Operation {
	op := authOperation(r, action, actor)
	op.LoginAuthority = a.LoginAuthority
	return op
}
func (s *Store) sessionAuthority(stored sessionActor) error {
	if s.LoginAuthority != "" && stored.LoginAuthority != s.LoginAuthority {
		return fail(401, "login_authority_changed", "The login authority changed. Sign in again.")
	}
	return nil
}
func (a *Auth) sessionRow(binding string) (string, string, int64, error) {
	a.Store.mu.Lock()
	defer a.Store.mu.Unlock()
	if a.Store.LoginAuthority != a.LoginAuthority {
		return "", "", 0, fail(401, "login_authority_changed", "The login authority changed. Sign in again.")
	}
	var actor, csrf string
	var expires int64
	err := a.Store.DB.QueryRow("SELECT actor,csrf,expires FROM sessions WHERE id_hash=?", binding).Scan(&actor, &csrf, &expires)
	if err != nil || expires <= time.Now().Unix() {
		return "", "", 0, fail(401, "session_expired", "Your session expired. Sign in again.")
	}
	return actor, csrf, expires, nil
}

// The append-only audit stores the current binding in the same transaction as revocation.
func (s *Store) bindLoginAuthority(binding string, roles func([]string) []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw string
	err = tx.QueryRow("SELECT after_json FROM audit WHERE action='auth.authority.bound' AND result='committed' ORDER BY id DESC LIMIT 1").Scan(&raw)
	var previous struct {
		LoginAuthority string `json:"login_authority"`
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if err = json.Unmarshal([]byte(raw), &previous); err != nil {
			return err
		}
		if len(previous.LoginAuthority) != 64 {
			return errors.New("stored login authority binding is invalid")
		}
	}
	var auditID int64
	if previous.LoginAuthority != binding {
		if _, err = tx.Exec("DELETE FROM sessions"); err != nil {
			return err
		}
		if _, err = tx.Exec("DELETE FROM login_states"); err != nil {
			return err
		}
		op := Operation{Actor: Actor{Subject: "deployment", Kind: "system"}, Action: "auth.authority.bound", Resource: "session", Reason: "Bind the login authority and revoke prior browser credentials", RequestID: newID(), Before: map[string]string{"login_authority": previous.LoginAuthority}, After: map[string]string{"login_authority": binding, "sessions": "revoked", "login_states": "revoked"}}
		if auditID, err = appendAudit(tx, op, "committed"); err != nil {
			return err
		}
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.LoginAuthority = binding
	s.ResolveRoles = roles
	if auditID != 0 {
		s.notify(auditID)
	}
	return nil
}

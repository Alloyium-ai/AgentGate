// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// API tokens let the CLI act for one human. A token is shown once, stored as
// its SHA-256, limited to a subset of the creator's roles, bounded by an
// expiry, and revocable. Each use takes the intersection of the token's roles
// and the human's current roles, so removing a role from the user removes it
// from every token. A token cannot mint tokens or manage users.
const (
	apiTokenPrefix     = "agt_"
	minTokenLifetime   = time.Hour
	maxTokenLifetime   = 90 * 24 * time.Hour
	maxTokensPerHolder = 32
)

var apiTokenPattern = regexp.MustCompile(`^agt_[A-Za-z0-9_-]{43}$`)
var tokenNamePattern = regexp.MustCompile(`^[A-Za-z0-9 ._-]{1,64}$`)

// APIToken is token metadata; the secret is only in the create response.
type APIToken struct {
	ID       string   `json:"id"`
	Subject  string   `json:"subject"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Created  string   `json:"created_at"`
	Expires  string   `json:"expires_at"`
	Revoked  string   `json:"revoked_at,omitempty"`
	LastUsed string   `json:"last_used_at,omitempty"`
}

// APITokenInput creates a token.
type APITokenInput struct {
	Name             string   `json:"name"`
	Roles            []string `json:"roles"`
	ExpiresInSeconds int      `json:"expires_in_seconds"`
	Reason           string   `json:"reason"`
}

type tokenActor struct {
	Subject string   `json:"subject"`
	Name    string   `json:"name,omitempty"`
	Groups  []string `json:"groups,omitempty"`
}

func bearerToken(r *http.Request) (string, bool) {
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return "", false
	}
	return strings.TrimPrefix(value, "Bearer "), true
}

func intersectRoles(granted, current []string) []string {
	out := []string{}
	for _, g := range granted {
		if validRoles[g] && (contains(current, g) || hasAdmin(current)) {
			out = append(out, g)
		}
	}
	return out
}

// resolveToken returns the actor a token acts for now.
func (s *Store) resolveToken(q queryer, hash string) (Actor, error) {
	var stored, rawRoles, authority, revoked, tokenHash string
	var expires int64
	err := q.QueryRow("SELECT token_hash,actor,roles,login_authority,expires,revoked FROM api_tokens WHERE token_hash=?", hash).Scan(&tokenHash, &stored, &rawRoles, &authority, &expires, &revoked)
	if err != nil || subtle.ConstantTimeCompare([]byte(tokenHash), []byte(hash)) != 1 {
		return Actor{}, fail(401, "invalid_token", "The API token is unknown, expired or revoked.")
	}
	if revoked != "" || expires <= s.now().Unix() || authority != s.LoginAuthority {
		return Actor{}, fail(401, "invalid_token", "The API token is unknown, expired or revoked.")
	}
	var holder tokenActor
	var granted []string
	if json.Unmarshal([]byte(stored), &holder) != nil || json.Unmarshal([]byte(rawRoles), &granted) != nil {
		return Actor{}, fail(401, "invalid_token", "The API token is unknown, expired or revoked.")
	}
	var current []string
	if s.LocalIdentity && strings.HasPrefix(holder.Subject, "local:") {
		actor, err := localActor(q, holder.Subject)
		if err != nil {
			return Actor{}, err
		}
		current = actor.Roles
	} else if s.ResolveRoles != nil {
		current = s.ResolveRoles(holder.Groups)
	}
	roles := intersectRoles(granted, current)
	if len(roles) == 0 {
		return Actor{}, fail(403, "token_roles_revoked", "The API token's roles are no longer granted to its holder.")
	}
	return Actor{Subject: holder.Subject, Kind: "human", Name: holder.Name, Groups: holder.Groups, Roles: roles}, nil
}

// Token authenticates a bearer API token for a read or a prepared mutation.
func (a *Auth) Token(r *http.Request) (Actor, string, error) {
	value, _ := bearerToken(r)
	if !apiTokenPattern.MatchString(value) {
		return Actor{}, "", fail(401, "invalid_token", "The API token is unknown, expired or revoked.")
	}
	hash := digest([]byte(value))
	a.Store.mu.Lock()
	defer a.Store.mu.Unlock()
	actor, err := a.Store.resolveToken(a.Store.DB, hash)
	return actor, hash, err
}

// tokenAllowed lists the API areas a token may call. Everything else, in
// particular users and api-tokens, needs a browser session.
var tokenAllowed = map[string]bool{"targets": true, "profiles": true, "launches": true, "launch-plans": true, "secrets": true, "launch-spec-schema": true, "access-presets": true, "audit": true, "audit-catalog": true, "openapi.json": true, "overview": true, "identity-links": true}

func newAPIToken() string { return apiTokenPrefix + randomToken() }

// CreateAPIToken mints a token for the calling human. The response is the
// only place the secret appears; it is never stored for idempotent replay.
func (s *Store) CreateAPIToken(op Operation, in APITokenInput) (any, error) {
	op.Action, op.Resource, op.Reason = "apitoken.created", "apitoken", safeReason(in.Reason)
	op.Idempotency = ""
	token := newAPIToken()
	return s.Mutation(op, "auth:write", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if operation.SessionHash == "" || operation.TokenHash != "" {
			return nil, fail(403, "session_required", "Create API tokens from a signed-in browser session.")
		}
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if !tokenNamePattern.MatchString(in.Name) || len(in.Roles) < 1 || len(in.Roles) > len(validRoles) {
			return nil, fail(422, "invalid_token_request", "Supply a short name and at least one role.")
		}
		seen := map[string]bool{}
		for _, role := range in.Roles {
			if seen[role] || !validRoles[role] || !(contains(operation.Actor.Roles, role) || hasAdmin(operation.Actor.Roles)) {
				return nil, fail(403, "role_not_held", "A token can carry only distinct roles you hold (an administrator holds every role).")
			}
			seen[role] = true
		}
		lifetime := time.Duration(in.ExpiresInSeconds) * time.Second
		if lifetime < minTokenLifetime || lifetime > maxTokenLifetime {
			return nil, fail(422, "invalid_token_lifetime", "A token lives between one hour and ninety days.")
		}
		var count int
		if err := tx.QueryRow("SELECT count(*) FROM api_tokens WHERE subject=? AND revoked='' AND expires>?", operation.Actor.Subject, s.now().Unix()).Scan(&count); err != nil {
			return nil, err
		}
		if count >= maxTokensPerHolder {
			return nil, fail(409, "token_limit", "Revoke an existing token first.")
		}
		id := newID()
		expires := s.now().Add(lifetime)
		holder := tokenActor{Subject: operation.Actor.Subject, Name: operation.Actor.Name, Groups: operation.Actor.Groups}
		if _, err := tx.Exec("INSERT INTO api_tokens VALUES(?,?,?,?,?,?,?,?,?,'',0)", id, digest([]byte(token)), holder.Subject, jsonText(holder), s.LoginAuthority, in.Name, jsonText(in.Roles), stamp(), expires.Unix()); err != nil {
			return nil, err
		}
		operation.Resource = "apitoken:" + id
		return map[string]any{"id": id, "name": in.Name, "roles": in.Roles, "expires_at": expires.UTC().Format(time.RFC3339), "token": token}, nil
	})
}

func scanToken(rows *sql.Rows) (APIToken, error) {
	var t APIToken
	var roles string
	var expires, used int64
	err := rows.Scan(&t.ID, &t.Subject, &t.Name, &roles, &t.Created, &expires, &t.Revoked, &used)
	if err == nil {
		err = json.Unmarshal([]byte(roles), &t.Roles)
	}
	t.Expires = time.Unix(expires, 0).UTC().Format(time.RFC3339)
	if used != 0 {
		t.LastUsed = time.Unix(used, 0).UTC().Format(time.RFC3339)
	}
	return t, err
}

// APITokens lists the caller's tokens; an administrator sees every token.
func (s *Store) APITokens(a Actor) ([]APIToken, error) {
	query := "SELECT id,subject,name,roles,created,expires,revoked,last_used FROM api_tokens WHERE subject=? ORDER BY created DESC LIMIT 200"
	args := []any{a.Subject}
	if hasAdmin(a.Roles) {
		query = "SELECT id,subject,name,roles,created,expires,revoked,last_used FROM api_tokens ORDER BY created DESC LIMIT 200"
		args = nil
	}
	rows, err := s.DB.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIToken{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeAPIToken revokes one token. A holder revokes their own; an
// administrator revokes any. Revoking a revoked token is a no-op.
func (s *Store) RevokeAPIToken(op Operation, id string, in ReasonInput) (any, error) {
	op.Action, op.Resource, op.Reason = "apitoken.revoked", "apitoken:"+id, safeReason(in.Reason)
	return s.Mutation(op, "auth:write", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		var subject, revoked string
		err := tx.QueryRow("SELECT subject,revoked FROM api_tokens WHERE id=?", id).Scan(&subject, &revoked)
		if errors.Is(err, sql.ErrNoRows) || err == nil && subject != operation.Actor.Subject && !hasAdmin(operation.Actor.Roles) {
			return nil, fail(404, "not_found", "The API token does not exist.")
		}
		if err != nil {
			return nil, err
		}
		if revoked == "" {
			revoked = stamp()
			if _, err = tx.Exec("UPDATE api_tokens SET revoked=? WHERE id=?", revoked, id); err != nil {
				return nil, err
			}
		}
		return map[string]string{"id": id, "revoked_at": revoked}, nil
	})
}

// ReasonInput is a body that carries only a reason.
type ReasonInput struct {
	Reason string `json:"reason"`
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

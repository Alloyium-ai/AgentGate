// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
)

const localUserSchema = `CREATE TABLE IF NOT EXISTS local_users(username TEXT PRIMARY KEY,name TEXT NOT NULL,roles TEXT NOT NULL,enabled INTEGER NOT NULL,password_hash BLOB NOT NULL,salt BLOB NOT NULL,revision INTEGER NOT NULL);`
const passwordIterations = 600000

// validRoles is every role the service grants. A role maps to scopes in Actor.Can.
var validRoles = map[string]bool{"viewer": true, "auditor": true, "editor": true, "launcher": true, "approver": true, "admin": true}

var localUsername = regexp.MustCompile(`^[a-z][a-z0-9_.-]{2,63}$`)

type LocalUser struct {
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Enabled  bool     `json:"enabled"`
	Revision int      `json:"revision"`
}
type UserInput struct {
	Username string   `json:"username"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Enabled  bool     `json:"enabled"`
	Password string   `json:"password,omitempty"`
	Parent   int      `json:"parent_revision"`
	Reason   string   `json:"reason"`
}

func validLocalUser(in UserInput) error {
	if !localUsername.MatchString(in.Username) || len(strings.TrimSpace(in.Name)) < 1 || len(in.Name) > 128 || len(in.Roles) < 1 || len(in.Roles) > len(validRoles) {
		return fail(422, "invalid_local_user", "Supply a username, display name and basic roles.")
	}
	seen := map[string]bool{}
	for _, r := range in.Roles {
		if seen[r] || !validRoles[r] {
			return fail(422, "invalid_local_role", "Use distinct basic roles.")
		}
		seen[r] = true
	}
	return reasonValid(in.Reason)
}
func passwordKey(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, passwordIterations, 32)
}
func newPassword(password string) ([]byte, []byte, error) {
	if len(password) < 16 || len(password) > 256 {
		return nil, nil, fail(422, "password_length", "Use a password between 16 and 256 bytes.")
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}
	key, err := passwordKey(password, salt)
	return key, salt, err
}
func localUserFrom(q queryer, username string) (LocalUser, error) {
	var u LocalUser
	var roles string
	err := q.QueryRow("SELECT username,name,roles,enabled,revision FROM local_users WHERE username=?", username).Scan(&u.Username, &u.Name, &roles, &u.Enabled, &u.Revision)
	if err == nil {
		err = json.Unmarshal([]byte(roles), &u.Roles)
	}
	return u, err
}
func localActor(q queryer, subject string) (Actor, error) {
	u, err := localUserFrom(q, strings.TrimPrefix(subject, "local:"))
	if err != nil || !u.Enabled {
		return Actor{}, fail(401, "local_user_inactive", "The local user is inactive. Sign in again.")
	}
	return Actor{Subject: "local:" + u.Username, Kind: "human", Name: u.Name, Roles: u.Roles}, nil
}
func hasAdmin(roles []string) bool {
	for _, r := range roles {
		if r == "admin" {
			return true
		}
	}
	return false
}
func (s *Store) Users() ([]LocalUser, error) {
	rows, err := s.DB.Query("SELECT username,name,roles,enabled,revision FROM local_users ORDER BY username LIMIT 1001")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []LocalUser{}
	for rows.Next() {
		var u LocalUser
		var raw string
		if err = rows.Scan(&u.Username, &u.Name, &raw, &u.Enabled, &u.Revision); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(raw), &u.Roles); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// Bootstrap requires host custody and only runs while the local user table is empty.
func (s *Store) BootstrapAdmin(username, name, password string) error {
	in := UserInput{Username: username, Name: name, Roles: []string{"admin"}, Enabled: true, Password: password, Reason: "Enroll the first local administrator"}
	op := Operation{Actor: Actor{Subject: "deployment-administrator", Kind: "system", Scopes: []string{"users:write"}}, RequestID: newID()}
	_, err := s.putUser(op, in, true)
	return err
}
func (s *Store) PutUser(op Operation, in UserInput) (any, error) {
	if !s.LocalIdentity {
		return nil, fail(404, "local_identity_disabled", "Local identity administration is disabled.")
	}
	if op.Actor.Kind != "human" || !strings.HasPrefix(op.Actor.Subject, "local:") {
		err := fail(403, "local_administrator_required", "A current local administrator must manage local accounts.")
		if e := s.Denied(op, err); e != nil {
			return nil, e
		}
		return nil, err
	}
	return s.putUser(op, in, false)
}
func (s *Store) putUser(op Operation, in UserInput, first bool) (any, error) {
	op.Action, op.Resource, op.Reason = "user.updated", "local:"+in.Username, safeReason(in.Reason)
	if err := require(op.Actor, "users:write", !first); err != nil {
		if e := s.Denied(op, err); e != nil {
			return nil, e
		}
		return nil, err
	}
	// Hash outside the storage lock. The transaction checks the current actor and user revision.
	var hash, salt []byte
	var err error
	if in.Password != "" {
		hash, salt, err = newPassword(in.Password)
		if err != nil {
			if e := s.Denied(op, err); e != nil {
				return nil, e
			}
			return nil, err
		}
	}
	return s.Mutation(op, "users:write", !first, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := validLocalUser(in); err != nil {
			return nil, err
		}
		var count int
		if err := tx.QueryRow("SELECT count(*) FROM local_users").Scan(&count); err != nil {
			return nil, err
		}
		if first && count != 0 {
			return nil, fail(409, "administrator_exists", "The first administrator already exists.")
		}
		old, err := localUserFrom(tx, in.Username)
		exists := err == nil
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		if in.Parent != old.Revision {
			return nil, fail(412, "user_revision_changed", "Read the current user revision before updating.")
		}
		if !exists && (count >= 1000 || hash == nil) {
			return nil, fail(422, "local_user_limit", "A new user needs a password and available capacity.")
		}
		if exists && old.Enabled && hasAdmin(old.Roles) && (!in.Enabled || !hasAdmin(in.Roles)) {
			var admins int
			if err = tx.QueryRow("SELECT count(*) FROM local_users WHERE enabled=1 AND EXISTS (SELECT 1 FROM json_each(local_users.roles) WHERE value='admin')").Scan(&admins); err != nil {
				return nil, err
			}
			if admins <= 1 {
				return nil, fail(409, "last_administrator", "Keep at least one enabled local administrator.")
			}
		}
		if hash == nil {
			if err = tx.QueryRow("SELECT password_hash,salt FROM local_users WHERE username=?", in.Username).Scan(&hash, &salt); err != nil {
				return nil, err
			}
		}
		u := LocalUser{in.Username, in.Name, in.Roles, in.Enabled, old.Revision + 1}
		operation.Before = old
		if _, err = tx.Exec("INSERT INTO local_users VALUES(?,?,?,?,?,?,?) ON CONFLICT(username) DO UPDATE SET name=excluded.name,roles=excluded.roles,enabled=excluded.enabled,password_hash=excluded.password_hash,salt=excluded.salt,revision=excluded.revision", u.Username, u.Name, jsonText(u.Roles), u.Enabled, hash, salt, u.Revision); err != nil {
			return nil, err
		}
		// A password or status change invalidates every browser credential for this user.
		// Self changes retain this transaction's session until authorization completes; it expires immediately on commit.
		if in.Password != "" || !in.Enabled {
			_, err = tx.Exec("UPDATE sessions SET expires=0 WHERE json_extract(actor,'$.subject')=? AND id_hash<>?", "local:"+u.Username, op.SessionHash)
			if err != nil {
				return nil, err
			}
			if op.Actor.Subject == "local:"+u.Username {
				return nil, fail(409, "self_credential_change", "A second administrator must change your password or status.")
			}
		}
		return u, nil
	})
}
func authenticateLocal(q queryer, username, password string) (Actor, error) {
	// Unknown usernames use the same derivation cost as known usernames.
	salt, expected := make([]byte, 32), make([]byte, 32)
	err := q.QueryRow("SELECT salt,password_hash FROM local_users WHERE username=?", username).Scan(&salt, &expected)
	if len(salt) != 32 || len(expected) != 32 {
		return Actor{}, fail(401, "invalid_credentials", "The username or password is invalid.")
	}
	actual, e := passwordKey(password, salt)
	if e != nil {
		return Actor{}, e
	}
	if err != nil || subtle.ConstantTimeCompare(actual, expected) != 1 {
		return Actor{}, fail(401, "invalid_credentials", "The username or password is invalid.")
	}
	return localActor(q, "local:"+username)
}

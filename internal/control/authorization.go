// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"encoding/json"
	"time"
)

func (s *Store) currentActor(tx *sql.Tx, op *Operation) error {
	if s.CheckConfiguration != nil {
		if err := s.CheckConfiguration(); err != nil {
			return err
		}
	}
	if op.LoginAuthority != "" && op.LoginAuthority != s.LoginAuthority {
		return fail(401, "login_authority_changed", "The login authority changed. Sign in again.")
	}
	switch op.Actor.Kind {
	case "human":
		if op.SessionHash == "" {
			return fail(401, "session_required", "A current verified browser session is required.")
		}
		var raw string
		var expires int64
		if err := tx.QueryRow("SELECT actor,expires FROM sessions WHERE id_hash=?", op.SessionHash).Scan(&raw, &expires); err != nil || expires <= time.Now().Unix() {
			return fail(401, "session_expired", "The browser session expired or was revoked.")
		}
		var stored sessionActor
		if err := json.Unmarshal([]byte(raw), &stored); err != nil {
			return err
		}
		if err := s.sessionAuthority(stored); err != nil {
			return err
		}
		actor := stored.Actor
		if actor.Kind != "human" || actor.Subject != op.Actor.Subject {
			return fail(401, "session_binding_failed", "The browser session does not bind this actor.")
		}
		if s.LocalIdentity && len(actor.Subject) > 6 && actor.Subject[:6] == "local:" {
			resolved, err := localActor(tx, actor.Subject)
			if err != nil {
				return err
			}
			actor = resolved
		} else if s.ResolveRoles != nil {
			actor.Roles = s.ResolveRoles(actor.Groups)
		}
		op.Actor = actor
	case "agent", "service":
		svc, err := serviceFrom(tx, op.Actor.Subject)
		if err != nil || !svc.Enabled || svc.Kind != op.Actor.Kind {
			return fail(403, "service_inactive", "The enrolled machine identity is no longer active.")
		}
		op.Actor.Scopes = svc.Scopes
	}
	return nil
}

func (s *Store) authorize(tx *sql.Tx, op *Operation, scope string, human bool) error {
	if err := s.currentActor(tx, op); err != nil {
		return err
	}
	return require(op.Actor, scope, human)
}

func retainDeniedNonce(tx *sql.Tx, op Operation) error {
	if op.ProofNonce == "" {
		return nil
	}
	_, err := tx.Exec("INSERT OR IGNORE INTO nonces VALUES(?,?,?)", op.Actor.Subject, op.ProofNonce, stamp())
	return err
}

func (s *Store) UseReadProof(op Operation) (Actor, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return Actor{}, err
	}
	defer tx.Rollback()
	op.Action = "proof.read.consumed"
	op.Resource = "api"
	op.Reason = "Consume one verified scoped proof for a read attempt"
	deny := func(cause error) (Actor, error) { _, err := s.deniedLocked(tx, op, cause); return Actor{}, err }
	if err = s.currentActor(tx, &op); err != nil {
		return deny(err)
	}
	if op.ProofNonce == "" {
		return deny(fail(401, "invalid_proof", "A read needs a fresh signed proof."))
	}
	if _, err = tx.Exec("INSERT INTO nonces VALUES(?,?,?)", op.Actor.Subject, op.ProofNonce, stamp()); err != nil {
		return deny(fail(409, "proof_replay", "The signed request proof already exists."))
	}
	id, err := appendAudit(tx, op, "consumed")
	if err != nil {
		return Actor{}, err
	}
	if err = tx.Commit(); err != nil {
		return Actor{}, err
	}
	s.notify(id)
	return op.Actor, nil
}

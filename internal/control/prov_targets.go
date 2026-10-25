// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// Target is a host that runs agentgate-hostd.
type Target struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	State        string   `json:"state"`
	Capabilities []string `json:"capabilities"`
	Hostname     string   `json:"hostname"`
	AgentVersion string   `json:"agent_version"`
	HostKeyID    string   `json:"host_key_id"`
	// HostPublicKey is the enrolled Ed25519 host key (base64url). A client
	// checks hostproto.KeyID of it against the fingerprint it pinned, then the
	// seal key signature against it.
	HostPublicKey string `json:"host_public_key,omitempty"`
	// EncryptionKey is the X25519 key the host enrolled with. Clients seal
	// to SealKey (signed by the host key), never to this unsigned value.
	EncryptionKey string `json:"encryption_key"`
	// SealKey is the host's secretseal.SignedKeyRecord, served verbatim; the
	// service stores it only after checking the host signature and cannot
	// produce one. SealKeyID and SealKeyNotAfter repeat its record fields.
	SealKey          json.RawMessage `json:"seal_key,omitempty"`
	SealKeyID        string          `json:"seal_key_id,omitempty"`
	SealKeyNotAfter  string          `json:"seal_key_not_after,omitempty"`
	JobKeyID         string          `json:"job_key_id"`
	LastSeen         string          `json:"last_seen_at,omitempty"`
	Online           bool            `json:"online"`
	HeartbeatSeconds int             `json:"heartbeat_seconds"`
	Created          string          `json:"created_at"`
	CreatedBy        string          `json:"created_by"`
	Updated          string          `json:"updated_at"`
	Revision         int             `json:"revision"`
	KernelVerified   bool            `json:"kernel_verified"`
	// RetiringSince is set while a retired target's host still has to
	// confirm the removal of its secrets; the target is then "retiring".
	RetiringSince string `json:"retiring_since,omitempty"`
	hostKey       string
	sealKey       string
	lastSequence  uint64
	lastSeenMS    int64
}

// TargetInput creates or renames a target.
type TargetInput struct {
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

const targetColumns = "id,name,state,capabilities,hostname,agent_version,host_key,host_key_id,encryption_key,job_key_id,last_sequence,last_seen,heartbeat_seconds,created,created_by,updated,revision,seal_key,retiring"

// TargetRetiring is the API state of an active target whose retirement
// waits for its host to confirm the removal of its secrets.
const TargetRetiring = "retiring"

func (s *Store) scanTarget(row rowScanner) (Target, error) {
	var t Target
	var caps string
	var retiring string
	err := row.Scan(&t.ID, &t.Name, &t.State, &caps, &t.Hostname, &t.AgentVersion, &t.hostKey, &t.HostKeyID, &t.EncryptionKey, &t.JobKeyID, &t.lastSequence, &t.lastSeenMS, &t.HeartbeatSeconds, &t.Created, &t.CreatedBy, &t.Updated, &t.Revision, &t.sealKey, &retiring)
	if err != nil {
		return t, err
	}
	t.HostPublicKey = t.hostKey
	if t.sealKey != "" {
		t.SealKey = json.RawMessage(t.sealKey)
		if rec, err := secretseal.ParseSignedKeyRecord([]byte(t.sealKey)); err == nil {
			t.SealKeyID, t.SealKeyNotAfter = rec.Record.KeyID, rec.Record.NotAfter
		}
	}
	if err = json.Unmarshal([]byte(caps), &t.Capabilities); err != nil {
		return t, err
	}
	if t.lastSeenMS > 0 {
		t.LastSeen = time.UnixMilli(t.lastSeenMS).UTC().Format(time.RFC3339Nano)
		limit := time.Duration(hostproto.MissedHeartbeatsLimit) * time.Duration(t.HeartbeatSeconds) * time.Second
		t.Online = t.State == "active" && s.now().Sub(time.UnixMilli(t.lastSeenMS)) <= limit
	}
	if retiring != "" && t.State == "active" {
		t.State, t.RetiringSince = TargetRetiring, retiring
	}
	return t, nil
}

// targetBy finds a live target by id, or by name among targets that are not retired.
func (s *Store) targetBy(q queryer, ref string) (Target, error) {
	t, err := s.scanTarget(q.QueryRow("SELECT "+targetColumns+" FROM targets WHERE id=?", ref))
	if errors.Is(err, sql.ErrNoRows) {
		t, err = s.scanTarget(q.QueryRow("SELECT "+targetColumns+" FROM targets WHERE name=? AND state<>'retired'", ref))
	}
	if errors.Is(err, sql.ErrNoRows) {
		return t, fail(404, "not_found", "The target does not exist.")
	}
	return t, err
}

// Targets lists every target, newest first.
func (s *Store) Targets() ([]Target, error) {
	rows, err := s.DB.Query("SELECT " + targetColumns + " FROM targets ORDER BY created DESC LIMIT 500")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Target{}
	for rows.Next() {
		t, err := s.scanTarget(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TargetDetail returns one target.
func (s *Store) TargetDetail(ref string) (Target, error) { return s.targetBy(s.DB, ref) }

func newEnrollmentToken() string { return "agtenr_" + randomToken() }

func (s *Store) issueEnrollment(tx *sql.Tx, targetID string, actor Actor) (map[string]any, error) {
	token := newEnrollmentToken()
	expires := s.now().Add(hostproto.EnrollmentTokenTTL)
	if _, err := tx.Exec("INSERT INTO enrollment_tokens VALUES(?,?,?,0,?,?)", digest([]byte(token)), targetID, expires.Unix(), stamp(), actor.Subject); err != nil {
		return nil, err
	}
	return map[string]any{"token": token, "expires_at": expires.UTC().Format(time.RFC3339), "single_use": true, "enroll_path": hostproto.PathEnroll}, nil
}

// CreateTarget records a pending target and returns its one-time enrollment
// token. The token is shown once and never stored for idempotent replay.
func (s *Store) CreateTarget(op Operation, in TargetInput) (any, error) {
	op.Action, op.Resource, op.Reason = "target.created", "target", safeReason(in.Reason)
	op.Idempotency = ""
	return s.Mutation(op, "targets:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if !hostproto.NamePattern.MatchString(in.Name) {
			return nil, fail(422, "invalid_target_name", "A target name matches ^[a-z0-9][a-z0-9-]{0,39}$.")
		}
		var count int
		if err := tx.QueryRow("SELECT count(*) FROM targets WHERE state<>'retired'").Scan(&count); err != nil {
			return nil, err
		}
		if count >= 256 {
			return nil, fail(409, "target_limit", "Retire a target before adding another.")
		}
		id, now := newID(), stamp()
		if _, err := tx.Exec("INSERT INTO targets VALUES(?,?,'pending','[]','','','','','','',0,0,?,?,?,?,1,'','')", id, in.Name, int(s.Provisioning.pollInterval()/time.Second), now, operation.Actor.Subject, now); err != nil {
			return nil, fail(409, "target_exists", "A live target already uses this name.")
		}
		enrollment, err := s.issueEnrollment(tx, id, operation.Actor)
		if err != nil {
			return nil, err
		}
		operation.Resource = "target:" + id
		t, err := s.targetBy(tx, id)
		return map[string]any{"target": t, "enrollment": enrollment}, err
	})
}

// IssueEnrollment creates a fresh one-time token for an existing target, for
// example after a job key rotation or a host reinstall. Enrolling again binds
// the new host key and retires the old one.
func (s *Store) IssueEnrollment(op Operation, ref string, in ReasonInput) (any, error) {
	op.Action, op.Resource, op.Reason = "target.enrollment.issued", "target:"+ref, safeReason(in.Reason)
	op.Idempotency = ""
	return s.Mutation(op, "targets:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		t, err := s.targetBy(tx, ref)
		if err != nil {
			return nil, err
		}
		if t.State == "retired" || t.State == TargetRetiring {
			return nil, fail(409, "target_retired", "A retired or retiring target cannot enroll.")
		}
		operation.Resource = "target:" + t.ID
		enrollment, err := s.issueEnrollment(tx, t.ID, operation.Actor)
		return map[string]any{"target": t, "enrollment": enrollment}, err
	})
}

// RenameTarget changes a target's name.
func (s *Store) RenameTarget(op Operation, ref string, in TargetInput) (any, error) {
	op.Action, op.Resource, op.Reason = "target.renamed", "target:"+ref, safeReason(in.Reason)
	return s.Mutation(op, "targets:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if !hostproto.NamePattern.MatchString(in.Name) {
			return nil, fail(422, "invalid_target_name", "A target name matches ^[a-z0-9][a-z0-9-]{0,39}$.")
		}
		t, err := s.targetBy(tx, ref)
		if err != nil {
			return nil, err
		}
		if t.State == "retired" || t.State == TargetRetiring {
			return nil, fail(409, "target_retired", "A retired or retiring target cannot change.")
		}
		operation.Resource, operation.Before = "target:"+t.ID, map[string]string{"name": t.Name}
		if _, err = tx.Exec("UPDATE targets SET name=?,updated=?,revision=revision+1 WHERE id=?", in.Name, stamp(), t.ID); err != nil {
			return nil, fail(409, "target_exists", "A live target already uses this name.")
		}
		return s.targetBy(tx, t.ID)
	})
}

// TargetRetireInput retires a target. Force finishes a retirement whose
// host cannot confirm the removal of its secrets (it is gone, or its key was
// never approved); those secrets are recorded as removal "unconfirmed".
type TargetRetireInput struct {
	Reason string `json:"reason"`
	Force  bool   `json:"force,omitempty"`
}

// RetireTarget retires a target. It refuses while the target has a launch
// that is not terminal, so no stop job is ever stranded on a retired host.
// When the host may still hold secret values, retiring first queues one
// secret-delete per secret (state deleting) and the target stays "retiring"
// (able to poll only for those jobs) until its host confirms every removal;
// the last confirmation retires it and revokes the host key. A host that can
// no longer poll can only be retired with force, which leaves the values on
// it and says so. Retiring again is idempotent.
func (s *Store) RetireTarget(op Operation, ref string, in TargetRetireInput) (any, error) {
	op.Action, op.Resource, op.Reason = "target.retired", "target:"+ref, safeReason(in.Reason)
	return s.Mutation(op, "targets:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		t, err := s.targetBy(tx, ref)
		if err != nil {
			return nil, err
		}
		operation.Resource = "target:" + t.ID
		if t.State == "retired" {
			return t, nil
		}
		var live int
		if err = tx.QueryRow("SELECT count(*) FROM launches WHERE target_id=? AND state NOT IN ('stopped','expired','failed','rejected','cancelled')", t.ID).Scan(&live); err != nil {
			return nil, err
		}
		if live != 0 {
			return nil, fail(409, "launches_active", "Stop every launch on this target before retiring it.")
		}
		operation.Before = map[string]string{"state": t.State}
		canPoll := t.State == "active" || t.State == TargetRetiring
		outstanding, err := s.queueTargetSecretRemoval(tx, t, operation.Actor, operation, "Retire the target: remove its secret from the host", canPoll && !in.Force)
		if err != nil {
			return nil, err
		}
		if len(outstanding) > 0 && !in.Force {
			if !canPoll {
				return nil, fail(409, "secrets_on_host", "The host of target "+t.Name+" may still hold "+itoa(len(outstanding))+" secret values but cannot collect removal jobs in state "+t.State+
					". Approve its host key so it can remove them, or retire with force, which leaves the values on the host (then wipe it).")
			}
			if t.State != TargetRetiring {
				now := stamp()
				if _, err = tx.Exec("UPDATE targets SET retiring=?,updated=?,revision=revision+1 WHERE id=?", now, now, t.ID); err != nil {
					return nil, err
				}
				// Nothing but the removals runs on a retiring target.
				if _, err = tx.Exec("UPDATE jobs SET state='cancelled',envelope='',completed=?,revision=revision+1 WHERE target_id=? AND type<>'secret-delete' AND state IN ('queued','delivered')", now, t.ID); err != nil {
					return nil, err
				}
				if _, err = tx.Exec("UPDATE enrollment_tokens SET used=1 WHERE target_id=? AND used=0", t.ID); err != nil {
					return nil, err
				}
			}
			operation.Action = "target.retirement.started"
			return s.targetBy(tx, t.ID)
		}
		if len(outstanding) > 0 {
			// Force: the host never confirmed these removals.
			if _, err = tx.Exec("UPDATE jobs SET state='cancelled',envelope='',completed=?,revision=revision+1 WHERE target_id=? AND type='secret-delete' AND state IN ('queued','delivered')", stamp(), t.ID); err != nil {
				return nil, err
			}
			for _, sec := range outstanding {
				if _, err = tx.Exec("UPDATE secrets SET state='deleted',removal='unconfirmed',updated=?,revision=revision+1 WHERE id=?", stamp(), sec.ID); err != nil {
					return nil, err
				}
				if _, err = appendAudit(tx, Operation{Actor: operation.Actor, Action: "secret.removal.unconfirmed", Resource: "secret:" + sec.ID, Reason: operation.Reason, RequestID: operation.RequestID, CorrelationID: operation.CorrelationID,
					Before: map[string]string{"state": sec.State}, After: map[string]string{"state": "deleted", "removal": "unconfirmed", "target_id": t.ID}}, "committed"); err != nil {
					return nil, err
				}
			}
			operation.After = map[string]any{"unconfirmed_secrets": len(outstanding)}
		}
		if err = s.finishRetirement(tx, t.ID); err != nil {
			return nil, err
		}
		return s.targetBy(tx, t.ID)
	})
}

// finishRetirement revokes the host key, cancels what is left and retires.
func (s *Store) finishRetirement(tx *sql.Tx, targetID string) error {
	now := stamp()
	if _, err := tx.Exec("UPDATE hostd_keys SET retired=? WHERE target_id=? AND retired=''", now, targetID); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE jobs SET state='cancelled',envelope='',completed=?,revision=revision+1 WHERE target_id=? AND state IN ('queued','delivered')", now, targetID); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE enrollment_tokens SET used=1 WHERE target_id=? AND used=0", targetID); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE secrets SET state='deleted',updated=?,revision=revision+1 WHERE target_id=? AND state<>'deleted'", now, targetID); err != nil {
		return err
	}
	_, err := tx.Exec("UPDATE targets SET state='retired',updated=?,revision=revision+1 WHERE id=?", now, targetID)
	return err
}

// KeyApprovalInput approves the host key a target enrolled with.
type KeyApprovalInput struct {
	HostKeyID string `json:"host_key_id"`
	Reason    string `json:"reason"`
}

// ApproveTargetKey activates an enrolled host key. The administrator types
// the fingerprint the host printed; it must equal the key the service bound.
func (s *Store) ApproveTargetKey(op Operation, ref string, in KeyApprovalInput) (any, error) {
	op.Action, op.Resource, op.Reason = "target.key.approved", "target:"+ref, safeReason(in.Reason)
	return s.Mutation(op, "targets:admin", true, func(tx *sql.Tx, operation *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		t, err := s.targetBy(tx, ref)
		if err != nil {
			return nil, err
		}
		operation.Resource = "target:" + t.ID
		if t.State != "awaiting_key_approval" {
			return nil, fail(409, "no_pending_key", "The target has no host key waiting for approval.")
		}
		if subtle.ConstantTimeCompare([]byte(in.HostKeyID), []byte(t.HostKeyID)) != 1 {
			return nil, fail(409, "fingerprint_mismatch", "The fingerprint differs from the key the host presented. Do not approve; issue a new token.")
		}
		operation.Before = map[string]string{"state": t.State, "host_key_id": t.HostKeyID}
		if _, err = tx.Exec("UPDATE targets SET state='active',last_seen=?,updated=?,revision=revision+1 WHERE id=? AND state='awaiting_key_approval'", s.now().UnixMilli(), stamp(), t.ID); err != nil {
			return nil, err
		}
		return s.targetBy(tx, t.ID)
	})
}

// TargetSealKey is GET /targets/{id}/seal-key: the host's signed seal key
// record, exactly as the host sent it, with the host key it must verify
// against. host_key_fingerprint is the service's claim and a convenience: a
// client recomputes it from host_public_key and compares it with its own pin.
func (s *Store) TargetSealKey(ref string) (map[string]any, error) {
	t, err := s.targetBy(s.DB, ref)
	if err != nil {
		return nil, err
	}
	if t.State != "active" {
		return nil, fail(409, "target_unavailable", "The target is not enrolled and active.")
	}
	if t.sealKey == "" {
		return nil, fail(404, "seal_key_unavailable", "The target's host has not published a host-signed seal key yet. Start a current agentgate-hostd on it and wait for its next poll.")
	}
	pub, err := hostproto.DecodeKey(t.hostKey)
	if err != nil {
		return nil, fail(503, "seal_key_unavailable", "The target's host key is unusable.")
	}
	return map[string]any{"target_id": t.ID, "host_key_id": t.HostKeyID, "host_public_key": t.hostKey,
		"host_key_fingerprint": secretseal.HostKeyFingerprint(pub), "seal_key_id": t.SealKeyID, "not_after": t.SealKeyNotAfter,
		"record": json.RawMessage(t.sealKey)}, nil
}

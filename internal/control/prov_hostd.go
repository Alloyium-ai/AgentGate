// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/ed25519"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"strings"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// hostFailure carries the last accepted sequence for a sequence rejection, so
// an honest host can resynchronise. It is set only after the signature
// verified.
type hostFailure struct {
	err          error
	lastSequence uint64
	sequence     bool
}

func (h *hostFailure) Error() string { return h.err.Error() }
func (h *hostFailure) Unwrap() error { return h.err }

func hostActor(id string) Actor { return Actor{Subject: "target:" + id, Kind: "host"} }

func hostOp(requestID, action, resource string) Operation {
	return Operation{Actor: Actor{Subject: "anonymous-host", Kind: "unknown"}, Action: action, Resource: resource, Reason: "Host protocol request", RequestID: requestID}
}

// EnrollHost binds a host key to the target that owns a one-time token.
func (s *Store) EnrollHost(raw []byte, requestID string) (hostproto.EnrollResponse, error) {
	op := hostOp(requestID, "target.enrolled", "target")
	resp, err := s.enrollHost(raw, &op)
	if err != nil {
		op.Action = "hostd.enroll.denied"
		if e := s.Denied(op, err); e != nil {
			return resp, e
		}
	}
	return resp, err
}

func (s *Store) enrollHost(raw []byte, op *Operation) (hostproto.EnrollResponse, error) {
	var resp hostproto.EnrollResponse
	env, err := hostproto.DecodeEnvelope(raw)
	if err != nil {
		return resp, fail(422, "invalid_envelope", "Supply one signed hostproto envelope.")
	}
	var req hostproto.EnrollRequest
	if err = hostproto.UnverifiedPayload(env, &req); err != nil {
		return resp, fail(422, "invalid_enrollment", "The enrollment payload does not match the protocol.")
	}
	public, err := hostproto.DecodeKey(req.PublicKey)
	if err != nil {
		return resp, fail(422, "invalid_enrollment", "The host public key is invalid.")
	}
	if err = hostproto.Open(env, hostproto.DomainEnroll, ed25519.PublicKey(public), &req); err != nil {
		return resp, fail(401, "invalid_signature", "The enrollment is not signed by the key it binds.")
	}
	now := s.now()
	if err = req.Check(now); err != nil {
		return resp, fail(422, "invalid_enrollment", strings.TrimPrefix(err.Error(), "hostproto: "))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.DB.Begin()
	if err != nil {
		return resp, err
	}
	defer tx.Rollback()
	hash := digest([]byte(req.Token))
	var stored, targetID string
	var expires int64
	var used int
	err = tx.QueryRow("SELECT token_hash,target_id,expires,used FROM enrollment_tokens WHERE token_hash=?", hash).Scan(&stored, &targetID, &expires, &used)
	if err != nil || subtle.ConstantTimeCompare([]byte(stored), []byte(hash)) != 1 {
		return resp, fail(401, "invalid_token", "The enrollment token is unknown, used or expired.")
	}
	op.Resource = "target:" + targetID
	if used != 0 || expires <= now.Unix() {
		return resp, fail(401, "invalid_token", "The enrollment token is unknown, used or expired.")
	}
	target, err := s.targetBy(tx, targetID)
	if err != nil {
		return resp, err
	}
	if target.State == "retired" {
		return resp, fail(409, "target_retired", "A retired target cannot enroll.")
	}
	var live int
	if err = tx.QueryRow("SELECT count(*) FROM launches WHERE target_id=? AND state NOT IN ('stopped','expired','failed','rejected','cancelled')", targetID).Scan(&live); err != nil {
		return resp, err
	}
	if live != 0 {
		return resp, fail(409, "launches_active", "The target has launches that are not terminal; stop them before enrolling again.")
	}
	if _, err = tx.Exec("UPDATE enrollment_tokens SET used=1 WHERE token_hash=? AND used=0", hash); err != nil {
		return resp, err
	}
	keyID := hostproto.KeyID(ed25519.PublicKey(public))
	stamped := stamp()
	if _, err = tx.Exec("UPDATE hostd_keys SET retired=? WHERE target_id=? AND retired=''", stamped, targetID); err != nil {
		return resp, err
	}
	if _, err = tx.Exec("INSERT INTO hostd_keys VALUES(?,?,?,?,?,'')", targetID, keyID, req.PublicKey, req.EncryptionKey, stamped); err != nil {
		return resp, fail(409, "key_reused", "This host key is already bound to the target; generate a new key.")
	}
	if _, err = tx.Exec("UPDATE jobs SET state='cancelled',envelope='',completed=?,revision=revision+1 WHERE target_id=? AND state IN ('queued','delivered')", stamped, targetID); err != nil {
		return resp, err
	}
	if _, err = tx.Exec("DELETE FROM host_nonces WHERE target_id=?", targetID); err != nil {
		return resp, err
	}
	if target.HostKeyID != "" {
		// Enrolling again replaces the host key: the old secrets were sealed
		// to the old host and are removed from the host (the jobs reach it
		// once its new key is approved) and must be stored again.
		if _, err = s.queueTargetSecretRemoval(tx, target, hostActor(targetID), op, "Re-enrollment replaces the host key; remove the secrets the previous key held", true); err != nil {
			return resp, err
		}
	}
	// The binding waits for an administrator to compare and approve the key
	// fingerprint: a token intercepted in transit cannot activate a foreign key.
	// A new host key invalidates the seal key record the old key signed.
	if _, err = tx.Exec("UPDATE targets SET state='awaiting_key_approval',capabilities=?,hostname=?,agent_version=?,host_key=?,host_key_id=?,encryption_key=?,job_key_id=?,last_sequence=0,last_seen=?,updated=?,revision=revision+1,seal_key='' WHERE id=?",
		jsonText(req.Capabilities), req.Hostname, req.AgentVersion, req.PublicKey, keyID, req.EncryptionKey, s.JobKeyID(), now.UnixMilli(), stamped, targetID); err != nil {
		return resp, err
	}
	resp = hostproto.EnrollResponse{TargetID: targetID, TargetName: target.Name, HostKeyID: keyID, JobKey: s.JobPublicKey(), JobKeyID: s.JobKeyID(), PollIntervalSeconds: target.HeartbeatSeconds, ServerTimeMS: now.UnixMilli()}
	resp.TokenMAC = hostproto.EnrollResponseMAC(req.Token, resp)
	audit := Operation{Actor: hostActor(targetID), Action: "target.enrolled", Resource: "target:" + targetID, Reason: "Bind a host key with a one-time token", RequestID: op.RequestID,
		Before: map[string]string{"state": target.State, "host_key_id": target.HostKeyID},
		After:  map[string]any{"state": "awaiting_key_approval", "host_key_id": keyID, "job_key_id": s.JobKeyID(), "capabilities": req.Capabilities, "hostname": req.Hostname}}
	id, err := appendAudit(tx, audit, "committed")
	if err != nil {
		return resp, err
	}
	if err = tx.Commit(); err != nil {
		return resp, err
	}
	s.notify(id)
	return resp, nil
}

// verifiedHost authenticates a signed host request: the target is active,
// the envelope verifies with its bound key, the timestamp is within the skew
// bound, the nonce is new and the sequence is greater than the last accepted.
// On success the nonce and sequence are recorded in tx.
func (s *Store) verifiedHost(tx *sql.Tx, env hostproto.Envelope, domain string, header hostproto.Header, dst any, headerOf func() hostproto.Header) (Target, error) {
	now := s.now()
	t, err := s.scanTarget(tx.QueryRow("SELECT "+targetColumns+" FROM targets WHERE id=?", header.HostID))
	if err != nil {
		return t, fail(401, "unknown_host", "The host is not enrolled.")
	}
	switch t.State {
	case "active", TargetRetiring:
	case "rekey_required":
		return t, fail(403, "rekey_required", "The service job key changed. Enroll this host again with a new token.")
	case "awaiting_key_approval":
		return t, fail(403, "key_approval_pending", "An administrator has not yet approved this host key fingerprint.")
	default:
		return t, fail(401, "unknown_host", "The host is not enrolled.")
	}
	key, err := hostproto.DecodeKey(t.hostKey)
	if err != nil {
		return t, fail(401, "unknown_host", "The host key is unusable.")
	}
	if err = hostproto.Open(env, domain, ed25519.PublicKey(key), dst); err != nil {
		return t, fail(401, "invalid_signature", "The request is not signed by the enrolled host key.")
	}
	h := headerOf()
	if h.HostID != t.ID {
		return t, fail(401, "invalid_signature", "The signed host id differs.")
	}
	if err = h.Check(now); err != nil {
		return t, fail(401, "stale_request", strings.TrimPrefix(err.Error(), "hostproto: "))
	}
	if _, err = tx.Exec("DELETE FROM host_nonces WHERE time<?", now.Add(-2*hostproto.MaxClockSkew).UnixMilli()); err != nil {
		return t, err
	}
	if _, err = tx.Exec("INSERT INTO host_nonces VALUES(?,?,?)", t.ID, h.Nonce, now.UnixMilli()); err != nil {
		return t, &hostFailure{err: fail(409, "replayed_request", "The request nonce was already used."), lastSequence: t.lastSequence, sequence: true}
	}
	if h.Sequence <= t.lastSequence {
		return t, &hostFailure{err: fail(409, "sequence_replayed", "The sequence is not greater than the last accepted sequence."), lastSequence: t.lastSequence, sequence: true}
	}
	if _, err = tx.Exec("UPDATE targets SET last_sequence=?,last_seen=? WHERE id=?", h.Sequence, now.UnixMilli(), t.ID); err != nil {
		return t, err
	}
	t.lastSequence, t.lastSeenMS = h.Sequence, now.UnixMilli()
	return t, nil
}

// PreauthenticateHost checks that a signed host request verifies with the
// key its target enrolled, before any of the request's work, and returns the
// target id to limit it by. It reads one row and verifies one signature,
// takes no store lock and records nothing; the request itself then runs the
// full check (state, timestamp, nonce, sequence) under the lock.
func (s *Store) PreauthenticateHost(raw []byte, domain string) (string, error) {
	env, err := hostproto.DecodeEnvelope(raw)
	if err != nil {
		return "", fail(422, "invalid_envelope", "Supply one signed hostproto envelope.")
	}
	var hostID string
	switch domain {
	case hostproto.DomainPoll:
		var p hostproto.PollRequest
		err, hostID = hostproto.UnverifiedPayload(env, &p), p.HostID
	case hostproto.DomainEvents:
		var p hostproto.EventsRequest
		err, hostID = hostproto.UnverifiedPayload(env, &p), p.HostID
	case hostproto.DomainResync:
		var p hostproto.ResyncRequest
		err, hostID = hostproto.UnverifiedPayload(env, &p), p.HostID
	default:
		return "", fail(404, "not_found", "The host endpoint does not exist.")
	}
	if err != nil || !hexID.MatchString(hostID) {
		return "", fail(422, "invalid_request", "The request payload does not match the protocol.")
	}
	var key string
	if err = s.DB.QueryRow("SELECT host_key FROM targets WHERE id=? AND state<>'retired' AND host_key<>''", hostID).Scan(&key); err != nil {
		return "", fail(401, "unknown_host", "The host is not enrolled.")
	}
	pub, err := hostproto.DecodeKey(key)
	if err != nil {
		return "", fail(401, "unknown_host", "The host key is unusable.")
	}
	if _, err = hostproto.Verify(env, domain, ed25519.PublicKey(pub)); err != nil {
		return "", fail(401, "invalid_signature", "The request is not signed by the enrolled host key.")
	}
	return hostID, nil
}

// hostRequest runs one authenticated host request. Failures before the
// signature verifies are audited as anonymous denials. After it verifies,
// the nonce and sequence advance even when the request is then refused, so
// a refused signed request can never be replayed later.
func (s *Store) hostRequest(raw []byte, domain, action string, op Operation, decode func(hostproto.Envelope) (hostproto.Header, error), dst any, headerOf func() hostproto.Header, work func(*sql.Tx, Target) (any, error)) (any, error) {
	env, err := hostproto.DecodeEnvelope(raw)
	if err != nil {
		return nil, s.hostDenied(op, fail(422, "invalid_envelope", "Supply one signed hostproto envelope."))
	}
	header, err := decode(env)
	if err != nil {
		return nil, s.hostDenied(op, fail(422, "invalid_request", "The request payload does not match the protocol."))
	}
	s.mu.Lock()
	tx, err := s.DB.Begin()
	if err != nil {
		s.mu.Unlock()
		return nil, err
	}
	defer tx.Rollback()
	target, err := s.verifiedHost(tx, env, domain, header, dst, headerOf)
	if err != nil {
		tx.Rollback()
		s.mu.Unlock()
		if target.ID != "" {
			op.Resource = "target:" + target.ID
		}
		return nil, s.hostDenied(op, err)
	}
	op.Actor = hostActor(target.ID)
	op.Resource = "target:" + target.ID
	if _, err = tx.Exec("SAVEPOINT host_work"); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	value, werr := work(tx, target)
	if werr != nil {
		if _, err = tx.Exec("ROLLBACK TO host_work"); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		_, code, _ := errorResult(werr)
		op.Action, op.After = action+".denied", map[string]string{"error_code": code}
		if _, err = appendAudit(tx, op, "denied"); err != nil {
			s.mu.Unlock()
			return nil, err
		}
	}
	if _, err = tx.Exec("RELEASE host_work"); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	var last int64
	tx.QueryRow("SELECT max(id) FROM audit").Scan(&last)
	err = tx.Commit()
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	s.notify(last)
	if werr != nil {
		return nil, werr
	}
	return value, nil
}

func (s *Store) hostDenied(op Operation, cause error) error {
	_, code, _ := errorResult(cause)
	if code == "persistence_unavailable" {
		return cause
	}
	op.Action = strings.TrimSuffix(op.Action, ".denied") + ".denied"
	if e := s.Denied(op, cause); e != nil {
		return e
	}
	return cause
}

// HostResync resets the last accepted sequence of a host that lost its
// counter. The request is signed by the enrolled key; replay is bounded by
// the timestamp skew and the nonce window.
func (s *Store) HostResync(raw []byte, requestID string) (hostproto.ResyncResponse, error) {
	op := hostOp(requestID, "hostd.resync", "target")
	env, err := hostproto.DecodeEnvelope(raw)
	if err != nil {
		return hostproto.ResyncResponse{}, s.hostDenied(op, fail(422, "invalid_envelope", "Supply one signed hostproto envelope."))
	}
	var req hostproto.ResyncRequest
	if err = hostproto.UnverifiedPayload(env, &req); err != nil {
		return hostproto.ResyncResponse{}, s.hostDenied(op, fail(422, "invalid_request", "The request payload does not match the protocol."))
	}
	resp, err := s.resync(env, req.HostID, requestID)
	if err != nil {
		op.Resource = "target:" + req.HostID
		return resp, s.hostDenied(op, err)
	}
	return resp, nil
}

func (s *Store) resync(env hostproto.Envelope, hostID, requestID string) (hostproto.ResyncResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	tx, err := s.DB.Begin()
	if err != nil {
		return hostproto.ResyncResponse{}, err
	}
	defer tx.Rollback()
	t, err := s.scanTarget(tx.QueryRow("SELECT "+targetColumns+" FROM targets WHERE id=?", hostID))
	if err != nil || (t.State != "active" && t.State != TargetRetiring) {
		return hostproto.ResyncResponse{}, fail(401, "unknown_host", "The host is not enrolled and active.")
	}
	key, err := hostproto.DecodeKey(t.hostKey)
	var req hostproto.ResyncRequest
	if err != nil || hostproto.Open(env, hostproto.DomainResync, ed25519.PublicKey(key), &req) != nil || req.HostID != t.ID {
		return hostproto.ResyncResponse{}, fail(401, "invalid_signature", "The request is not signed by the enrolled host key.")
	}
	if err = req.Check(now); err != nil {
		return hostproto.ResyncResponse{}, fail(401, "stale_request", strings.TrimPrefix(err.Error(), "hostproto: "))
	}
	if _, err = tx.Exec("DELETE FROM host_nonces WHERE time<?", now.Add(-2*hostproto.MaxClockSkew).UnixMilli()); err != nil {
		return hostproto.ResyncResponse{}, err
	}
	if _, err = tx.Exec("INSERT INTO host_nonces VALUES(?,?,?)", t.ID, req.Nonce, now.UnixMilli()); err != nil {
		return hostproto.ResyncResponse{}, fail(409, "replayed_request", "The request nonce was already used.")
	}
	if _, err = tx.Exec("UPDATE targets SET last_sequence=0,last_seen=? WHERE id=?", now.UnixMilli(), t.ID); err != nil {
		return hostproto.ResyncResponse{}, err
	}
	id, err := appendAudit(tx, Operation{Actor: hostActor(t.ID), Action: "target.sequence.reset", Resource: "target:" + t.ID, Reason: "host:" + req.Reason, RequestID: requestID, Before: map[string]uint64{"last_sequence": t.lastSequence}, After: map[string]uint64{"last_sequence": 0}}, "committed")
	if err != nil {
		return hostproto.ResyncResponse{}, err
	}
	if err = tx.Commit(); err != nil {
		return hostproto.ResyncResponse{}, err
	}
	s.notify(id)
	return hostproto.ResyncResponse{LastAcceptedSequence: 0, ServerTimeMS: now.UnixMilli()}, nil
}

// HostPoll records a heartbeat and delivers queued jobs.
func (s *Store) HostPoll(raw []byte, requestID string) (hostproto.PollResponse, error) {
	var req hostproto.PollRequest
	op := hostOp(requestID, "hostd.poll", "target")
	value, err := s.hostRequest(raw, hostproto.DomainPoll, "hostd.poll", op,
		func(env hostproto.Envelope) (hostproto.Header, error) {
			var pre hostproto.PollRequest
			err := hostproto.UnverifiedPayload(env, &pre)
			return pre.Header, err
		}, &req, func() hostproto.Header { return req.Header },
		func(tx *sql.Tx, t Target) (any, error) {
			if err := req.Check(s.now()); err != nil {
				return nil, fail(422, "invalid_poll", strings.TrimPrefix(err.Error(), "hostproto: "))
			}
			return s.pollWork(tx, t, req)
		})
	if err != nil {
		return hostproto.PollResponse{}, err
	}
	return value.(hostproto.PollResponse), nil
}

func (s *Store) pollWork(tx *sql.Tx, t Target, req hostproto.PollRequest) (hostproto.PollResponse, error) {
	now := s.now()
	if err := s.publishSealKey(tx, t, req.Heartbeat.SealKey); err != nil {
		return hostproto.PollResponse{}, err
	}
	beat := req.Heartbeat
	beat.SealKey = nil // stored on the target, not in every heartbeat row
	if _, err := tx.Exec("INSERT INTO host_heartbeats(target_id,time,sequence,heartbeat) VALUES(?,?,?,?)", t.ID, now.UnixMilli(), req.Sequence, jsonText(beat)); err != nil {
		return hostproto.PollResponse{}, err
	}
	if _, err := tx.Exec("DELETE FROM host_heartbeats WHERE target_id=? AND id<=(SELECT id FROM host_heartbeats WHERE target_id=? ORDER BY id DESC LIMIT 1 OFFSET 50)", t.ID, t.ID); err != nil {
		return hostproto.PollResponse{}, err
	}
	if jsonText(req.Heartbeat.Capabilities) != jsonText(t.Capabilities) || req.Heartbeat.AgentVersion != t.AgentVersion {
		if _, err := tx.Exec("UPDATE targets SET capabilities=?,agent_version=?,updated=?,revision=revision+1 WHERE id=?", jsonText(req.Heartbeat.Capabilities), req.Heartbeat.AgentVersion, stamp(), t.ID); err != nil {
			return hostproto.PollResponse{}, err
		}
		if _, err := appendAudit(tx, Operation{Actor: hostActor(t.ID), Action: "target.capabilities.changed", Resource: "target:" + t.ID, Reason: "The host reported different capabilities", RequestID: "hostd-" + newID(), Before: map[string]any{"capabilities": t.Capabilities, "agent_version": t.AgentVersion}, After: map[string]any{"capabilities": req.Heartbeat.Capabilities, "agent_version": req.Heartbeat.AgentVersion}}, "committed"); err != nil {
			return hostproto.PollResponse{}, err
		}
	}
	// A host that runs a launch the service considers ended gets a stop job.
	for _, id := range req.Heartbeat.RunningLaunches {
		l, err := launchFrom(tx, id)
		if err != nil || l.TargetID != t.ID || !TerminalState(l.State) {
			continue
		}
		if err = s.queueStop(tx, &l, "service-terminal", hostActor(t.ID), nil); err != nil {
			return hostproto.PollResponse{}, err
		}
	}
	rows, err := tx.Query("SELECT id,envelope,state,attempts FROM jobs WHERE target_id=? AND deadline>? AND (state='queued' OR (state='delivered' AND event_seq=0 AND attempts<5 AND delivered<?)) ORDER BY created,id LIMIT ?",
		t.ID, now.UnixMilli(), now.Add(-s.Provisioning.redelivery()).UnixMilli(), req.MaxJobs)
	if err != nil {
		return hostproto.PollResponse{}, err
	}
	type pending struct {
		id, envelope, state string
		attempts            int
	}
	list := []pending{}
	for rows.Next() {
		var p pending
		if err = rows.Scan(&p.id, &p.envelope, &p.state, &p.attempts); err != nil {
			rows.Close()
			return hostproto.PollResponse{}, err
		}
		list = append(list, p)
	}
	rows.Close()
	resp := hostproto.PollResponse{ServerTimeMS: now.UnixMilli(), PollIntervalSeconds: t.HeartbeatSeconds, AcceptedSequence: req.Sequence, Jobs: []hostproto.Envelope{}}
	for _, p := range list {
		var env hostproto.Envelope
		if err = json.Unmarshal([]byte(p.envelope), &env); err != nil || env.KeyID != t.JobKeyID {
			// A job signed by a key this host was not enrolled with is never
			// sent; it is cancelled and audited, and a launch queued for it fails.
			if err = s.cancelJobs(tx, "id=?", []any{p.id}, hostActor(t.ID), "job_key_mismatch", "The job is signed by job key "+env.KeyID+", but the host enrolled with "+t.JobKeyID+"; enroll the host again"); err != nil {
				return resp, err
			}
			continue
		}
		if _, err = tx.Exec("UPDATE jobs SET state='delivered',attempts=attempts+1,delivered=?,revision=revision+1 WHERE id=?", now.UnixMilli(), p.id); err != nil {
			return resp, err
		}
		if p.state == "queued" {
			if _, err = appendAudit(tx, Operation{Actor: hostActor(t.ID), Action: "job.delivered", Resource: "job:" + p.id, Reason: "Deliver a signed job to its host", RequestID: "hostd-" + newID()}, "committed"); err != nil {
				return resp, err
			}
		}
		resp.Jobs = append(resp.Jobs, env)
	}
	return resp, nil
}

// HostEvents appends ordered job events and applies their effects.
func (s *Store) HostEvents(jobID string, raw []byte, requestID string) (hostproto.EventsResponse, error) {
	var req hostproto.EventsRequest
	op := hostOp(requestID, "hostd.events", "job:"+jobID)
	value, err := s.hostRequest(raw, hostproto.DomainEvents, "hostd.events", op,
		func(env hostproto.Envelope) (hostproto.Header, error) {
			var pre hostproto.EventsRequest
			err := hostproto.UnverifiedPayload(env, &pre)
			return pre.Header, err
		}, &req, func() hostproto.Header { return req.Header },
		func(tx *sql.Tx, t Target) (any, error) {
			if err := req.Check(s.now()); err != nil {
				return nil, fail(422, "invalid_events", strings.TrimPrefix(err.Error(), "hostproto: "))
			}
			if req.JobID != jobID {
				return nil, fail(422, "invalid_events", "The signed job id differs from the path.")
			}
			return s.eventsWork(tx, t, req)
		})
	if err != nil {
		return hostproto.EventsResponse{}, err
	}
	return value.(hostproto.EventsResponse), nil
}

// publishSealKey stores the host's signed seal key record verbatim when it is
// new and verifies: signed by this target's enrolled host key, for this
// target, inside its validity window. The service never signs or edits one,
// so it cannot hand clients a key of its own. A record that does not verify is
// not stored and is audited once per distinct record; the poll still counts
// as a heartbeat, so a bad record never makes the host look lost.
func (s *Store) publishSealKey(tx *sql.Tx, t Target, raw json.RawMessage) error {
	if len(raw) == 0 || string(raw) == t.sealKey {
		return nil
	}
	reject := func(code string) error {
		sum := digest(raw)
		if s.rejectedSealKeys == nil {
			s.rejectedSealKeys = map[string]string{}
		}
		if s.rejectedSealKeys[t.ID] == sum {
			return nil
		}
		s.rejectedSealKeys[t.ID] = sum
		_, err := appendAudit(tx, Operation{Actor: hostActor(t.ID), Action: "target.seal_key.rejected", Resource: "target:" + t.ID, Reason: "The host sent a seal key record that does not verify", RequestID: "hostd-" + newID(), After: map[string]string{"error_code": code, "record_sha256": sum}}, "denied")
		return err
	}
	rec, err := secretseal.ParseSignedKeyRecord(raw)
	if err != nil {
		return reject("seal_key_malformed")
	}
	pub, err := hostproto.DecodeKey(t.hostKey)
	if err != nil {
		return reject("host_key_unusable")
	}
	if _, err = secretseal.VerifyKeyRecord(rec, ed25519.PublicKey(pub), secretseal.HostKeyFingerprint(pub), t.ID, s.now()); err != nil {
		return reject("seal_key_unverified")
	}
	if _, err = tx.Exec("UPDATE targets SET seal_key=?,updated=?,revision=revision+1 WHERE id=?", string(raw), stamp(), t.ID); err != nil {
		return err
	}
	delete(s.rejectedSealKeys, t.ID)
	_, err = appendAudit(tx, Operation{Actor: hostActor(t.ID), Action: "target.seal_key.published", Resource: "target:" + t.ID, Reason: "The host published a seal key signed by its enrolled key", RequestID: "hostd-" + newID(),
		After: map[string]string{"seal_key_id": rec.Record.KeyID, "not_before": rec.Record.NotBefore, "not_after": rec.Record.NotAfter, "host_key": rec.Record.HostKey, "record_sha256": digest(raw)}}, "committed")
	return err
}

func eventDigest(ev hostproto.Event) string {
	raw, _ := json.Marshal(ev)
	return digest(raw)
}

func (s *Store) eventsWork(tx *sql.Tx, t Target, req hostproto.EventsRequest) (hostproto.EventsResponse, error) {
	job, err := jobFrom(tx, req.JobID)
	if err != nil || job.TargetID != t.ID {
		return hostproto.EventsResponse{}, fail(404, "not_found", "The job does not exist for this host.")
	}
	if job.State == "queued" || job.State == "cancelled" && job.deliveredMS == 0 {
		return hostproto.EventsResponse{}, fail(409, "job_not_delivered", "The job was never delivered to this host.")
	}
	completed := len(job.Result) > 0
	for _, ev := range req.Events {
		sum := eventDigest(ev)
		if ev.Seq <= job.EventSeq {
			var stored string
			if err = tx.QueryRow("SELECT digest FROM job_events WHERE job_id=? AND seq=?", job.ID, ev.Seq).Scan(&stored); err != nil || stored != sum {
				return hostproto.EventsResponse{}, fail(409, "event_conflict", "An event with this sequence already holds different content.")
			}
			continue
		}
		if ev.Seq != job.EventSeq+1 {
			return hostproto.EventsResponse{}, fail(409, "event_gap", "Events must continue from the last accepted sequence.")
		}
		if completed {
			return hostproto.EventsResponse{}, fail(409, "job_completed", "The job already has its result.")
		}
		stored := ev
		if ev.Kind == hostproto.EventLog {
			stored.Message = ""
		}
		if _, err = tx.Exec("INSERT INTO job_events VALUES(?,?,?,?,?)", job.ID, ev.Seq, sum, jsonText(stored), stamp()); err != nil {
			return hostproto.EventsResponse{}, err
		}
		job.EventSeq = ev.Seq
		if _, err = tx.Exec("UPDATE jobs SET event_seq=?,revision=revision+1 WHERE id=?", job.EventSeq, job.ID); err != nil {
			return hostproto.EventsResponse{}, err
		}
		if err = s.applyEvent(tx, t, &job, ev); err != nil {
			return hostproto.EventsResponse{}, err
		}
		completed = ev.Kind == hostproto.EventResult
	}
	current, err := jobFrom(tx, job.ID)
	if err != nil {
		return hostproto.EventsResponse{}, err
	}
	return hostproto.EventsResponse{AcceptedThrough: current.EventSeq, Completed: len(current.Result) > 0, JobState: current.State}, nil
}

func (s *Store) applyEvent(tx *sql.Tx, t Target, job *JobRecord, ev hostproto.Event) error {
	actor := hostActor(t.ID)
	var l *launchRow
	if job.LaunchID != "" {
		row, err := launchFrom(tx, job.LaunchID)
		if err != nil {
			return err
		}
		l = &row
	}
	switch ev.Kind {
	case hostproto.EventProgress:
		if l != nil {
			return appendLaunchEvent(tx, l, "progress", actor.Subject, ev.Message, map[string]any{"job_id": job.ID})
		}
		return nil
	case hostproto.EventLog:
		if l == nil {
			return nil
		}
		return appendLog(tx, l, ev)
	case hostproto.EventState:
		if l == nil || (job.Type != hostproto.JobLaunch && job.Type != hostproto.JobStop) {
			return fail(422, "invalid_events", "Only launch and stop jobs report launch states.")
		}
		return s.applyLaunchState(tx, l, ev.State, actor)
	case hostproto.EventResult:
		return s.applyResult(tx, t, job, l, *ev.Result, actor)
	}
	return nil
}

func appendLog(tx *sql.Tx, l *launchRow, ev hostproto.Event) error {
	if l.logSeq >= maxLaunchLogLines || l.logBytes >= maxLaunchLogBytes {
		return nil
	}
	text := ev.Message
	if l.logBytes+len(text) > maxLaunchLogBytes {
		text = text[:maxLaunchLogBytes-l.logBytes]
		for len(text) > 0 && !jsonValidUTF8(text) {
			text = text[:len(text)-1]
		}
		text += "\n[output truncated at the 1 MiB launch log limit]"
	}
	l.logSeq++
	l.logBytes += len(text)
	if _, err := tx.Exec("INSERT INTO launch_logs VALUES(?,?,?,?,?)", l.ID, l.logSeq, ev.TimeMS, ev.Stream, text); err != nil {
		return err
	}
	_, err := tx.Exec("UPDATE launches SET log_seq=?,log_bytes=? WHERE id=?", l.logSeq, l.logBytes, l.ID)
	return err
}

func jsonValidUTF8(s string) bool {
	return strings.ToValidUTF8(s, "�") == s
}

func (s *Store) applyLaunchState(tx *sql.Tx, l *launchRow, state string, actor Actor) error {
	if TerminalState(l.State) {
		if state == StateRunning || state == StateProvisioning {
			if err := appendLaunchEvent(tx, l, "host_state", actor.Subject, "The host reports "+state+" for an ended launch; a stop is queued", nil); err != nil {
				return err
			}
			return s.queueStop(tx, l, "service-terminal", actor, nil)
		}
		return nil
	}
	steps := map[string]map[string][]string{
		StateProvisioning: {StateQueued: {StateProvisioning}},
		StateRunning:      {StateQueued: {StateProvisioning, StateRunning}, StateProvisioning: {StateRunning}},
		StateStopping:     {StateQueued: {StateStopping}, StateProvisioning: {StateStopping}, StateRunning: {StateStopping}},
	}[state][l.State]
	for _, to := range steps {
		if err := s.transitionLaunch(tx, l, transition{To: to, Reason: "The host reports " + to, Actor: actor}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyResult(tx *sql.Tx, t Target, job *JobRecord, l *launchRow, r hostproto.JobResult, actor Actor) error {
	var receipt string
	if r.SecretReceipt != nil && job.Type != hostproto.JobSecretPut {
		return fail(422, "invalid_result", "Only a secret-put result carries a secret receipt.")
	}
	if r.Receipt != nil {
		if l == nil {
			return fail(422, "invalid_receipt", "Only launch, stop and collect jobs carry receipts.")
		}
		bound := hostproto.Job{LaunchID: job.LaunchID, TargetID: job.TargetID, SpecDigest: job.SpecDigest, PolicyDigest: job.PolicyDigest}
		if err := r.Receipt.Check(bound); err != nil {
			return fail(422, "invalid_receipt", strings.TrimPrefix(err.Error(), "hostproto: "))
		}
		if err := receiptMatchesPlan(l, r.Receipt); err != nil {
			return err
		}
		raw, _ := json.Marshal(r.Receipt)
		receipt = string(raw)
	}
	state := map[string]string{hostproto.ResultSucceeded: "succeeded", hostproto.ResultFailed: "failed", hostproto.ResultRejected: "rejected"}[r.Status]
	result := map[string]any{"status": r.Status, "reason": r.Reason, "evidence_missing": r.EvidenceMissing, "receipt_digest": ""}
	if receipt != "" {
		result["receipt_digest"] = digest([]byte(receipt))
	}
	if _, err := tx.Exec("UPDATE jobs SET state=?,result=?,completed=?,envelope=CASE WHEN type IN ('secret-put') THEN '' ELSE envelope END,revision=revision+1 WHERE id=? AND result=''", state, jsonText(result), stamp(), job.ID); err != nil {
		return err
	}
	if _, err := appendAudit(tx, Operation{Actor: actor, Action: "job.completed", Resource: "job:" + job.ID, Run: job.LaunchID, Reason: "The host reported a job result", RequestID: "hostd-" + newID(), After: result}, "committed"); err != nil {
		return err
	}
	switch job.Type {
	case hostproto.JobSecretPut:
		return s.finishSecretPut(tx, t, job, r, actor)
	case hostproto.JobSecretDelete:
		return s.finishSecretDelete(tx, t, job, r, actor)
	case hostproto.JobLaunch, hostproto.JobStop, hostproto.JobCollect:
		return s.finishLaunch(tx, l, job, r, receipt, actor)
	}
	return nil
}

// finishSecretDelete records the host's answer to a secret-delete. A removal
// the host confirms deletes the secret, and the last one a retiring target
// confirms retires it. A refused removal on a retiring target is queued
// again (a bounded number of times); otherwise the secret is stored again.
func (s *Store) finishSecretDelete(tx *sql.Tx, t Target, job *JobRecord, r hostproto.JobResult, actor Actor) error {
	sec, err := scanSecret(tx.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", job.SecretID))
	if err != nil {
		return err
	}
	if sec.State != "deleting" {
		return nil
	}
	if r.Status == hostproto.ResultSucceeded {
		if _, err = tx.Exec("UPDATE secrets SET state='deleted',updated=?,revision=revision+1 WHERE id=? AND state='deleting'", stamp(), sec.ID); err != nil {
			return err
		}
		if _, err = appendAudit(tx, Operation{Actor: actor, Action: "secret.deleted", Resource: "secret:" + sec.ID, Reason: "The host confirmed the removal of the secret value", RequestID: "hostd-" + newID(),
			Before: map[string]string{"state": "deleting"}, After: map[string]string{"state": "deleted", "reason": reasonCodeText(r.Reason), "job_id": job.ID}}, "committed"); err != nil {
			return err
		}
		if t.State != TargetRetiring {
			return nil
		}
		var left int
		if err = tx.QueryRow("SELECT count(*) FROM secrets WHERE target_id=? AND state<>'deleted'", t.ID).Scan(&left); err != nil || left > 0 {
			return err
		}
		if err = s.finishRetirement(tx, t.ID); err != nil {
			return err
		}
		_, err = appendAudit(tx, Operation{Actor: actor, Action: "target.retired", Resource: "target:" + t.ID, Reason: "The host confirmed the removal of every secret; the target is retired and its host key revoked", RequestID: "hostd-" + newID(),
			Before: map[string]string{"state": TargetRetiring}, After: map[string]string{"state": "retired"}}, "committed")
		return err
	}
	after := map[string]string{"status": r.Status, "reason": reasonCodeText(r.Reason), "job_id": job.ID}
	if t.State == TargetRetiring {
		var attempts int
		if err = tx.QueryRow("SELECT count(*) FROM jobs WHERE secret_id=? AND type='secret-delete'", sec.ID).Scan(&attempts); err != nil {
			return err
		}
		after["state"] = "deleting"
		if attempts < maxSecretDeleteAttempts {
			if err = s.queueSecretDelete(tx, sec, Actor{Subject: "agentgate-scheduler", Kind: "system"}, nil, "Retry removing a secret of a retiring target"); err != nil {
				return err
			}
			after["retry"] = "queued"
		} else {
			after["retry"] = "exhausted: retire the target with force"
		}
	} else {
		if _, err = tx.Exec("UPDATE secrets SET state='stored',updated=?,revision=revision+1 WHERE id=? AND state='deleting'", stamp(), sec.ID); err != nil {
			return err
		}
		after["state"] = "stored"
	}
	_, err = appendAudit(tx, Operation{Actor: actor, Action: "secret.deletion.failed", Resource: "secret:" + sec.ID, Reason: "The host did not remove the secret value", RequestID: "hostd-" + newID(),
		Before: map[string]string{"state": "deleting"}, After: after}, "denied")
	return err
}

// receiptMatchesPlan checks the broker evidence against the launch it
// answers: broker counts only for the plan's upstreams, the stats bound to
// the plan's broker endpoint, and no broker evidence for a launch without
// secrets. The host is trusted for its own target (docs/PROVISIONING.md); this
// catches a confused or buggy host, not a malicious one.
func receiptMatchesPlan(l *launchRow, r *hostproto.Receipt) error {
	var plan LaunchPlan
	if err := json.Unmarshal([]byte(l.plan), &plan); err != nil {
		return err
	}
	if len(plan.Secrets) == 0 || plan.Broker == nil {
		if r.BrokerEvidence != nil || len(r.BrokerCounts) > 0 {
			return fail(422, "invalid_receipt", "The receipt carries broker evidence for a launch without brokered secrets.")
		}
		return nil
	}
	allowed := map[string]bool{}
	for _, sec := range plan.Secrets {
		for _, up := range sec.Upstreams {
			allowed[strings.TrimSuffix(up, ":443")] = true
		}
	}
	for upstream := range r.BrokerCounts {
		if !allowed[upstream] {
			return fail(422, "invalid_receipt", "The receipt counts broker requests to an upstream outside the plan.")
		}
	}
	if e := r.BrokerEvidence; e != nil && e.Missing == "" {
		if e.Listen != "tcp:"+plan.Broker.Address+":"+itoa(plan.Broker.Port) {
			return fail(422, "invalid_receipt", "The broker evidence is bound to another endpoint than the plan's broker.")
		}
		for _, route := range e.Routes {
			host, port, _ := strings.Cut(route.Upstream, ":")
			if !allowed[route.Upstream] && !(port == "443" && allowed[host]) {
				return fail(422, "invalid_receipt", "The broker evidence names an upstream outside the plan.")
			}
		}
	}
	return nil
}

// finishSecretPut records the host's answer to a secret-put. A success
// needs a receipt for exactly the relayed envelope (target, name, version,
// key and nonce); the service cannot verify its tag (only the sealing client
// can) and relays it verbatim. Anything else ends the secret failed.
func (s *Store) finishSecretPut(tx *sql.Tx, t Target, job *JobRecord, r hostproto.JobResult, actor Actor) error {
	sec, err := scanSecret(tx.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", job.SecretID))
	if err != nil {
		return err
	}
	if sec.State != "pending" {
		return nil
	}
	next, reason := "failed", r.Reason
	var receipt string
	if r.Status == hostproto.ResultSucceeded {
		rec := r.SecretReceipt
		switch {
		case rec == nil:
			reason = "receipt_missing"
		case sec.Envelope == nil || rec.TargetID != t.ID || rec.Name != sec.Name || rec.Format != hostproto.SecretReceiptFormat ||
			rec.Version != sec.Envelope.Version || rec.KeyID != sec.Envelope.KeyID || rec.Nonce != sec.Envelope.Nonce:
			reason = "receipt_mismatch"
		default:
			raw, _ := json.Marshal(rec)
			next, receipt = "stored", string(raw)
		}
	}
	if _, err = tx.Exec("UPDATE secrets SET state=?,receipt=?,updated=?,revision=revision+1 WHERE id=? AND state='pending'", next, receipt, stamp(), sec.ID); err != nil {
		return err
	}
	after := map[string]string{"state": next, "reason": reasonCodeText(reason), "ciphertext_sha256": sec.Fingerprint}
	action := "secret.store.failed"
	if next == "stored" {
		action = "secret.stored"
		after["value_fingerprint"] = r.SecretReceipt.Fingerprint
		after["seal_key_id"] = r.SecretReceipt.KeyID
	}
	_, err = appendAudit(tx, Operation{Actor: actor, Action: action, Resource: "secret:" + sec.ID, Reason: "The host answered a secret-put", RequestID: "hostd-" + newID(), Before: map[string]string{"state": "pending"}, After: after}, "committed")
	return err
}

func reasonCodeText(reason string) string {
	if len(reason) > 64 {
		return reason[:64]
	}
	return reason
}

// finishLaunch applies a launch, stop or collect result. A receipt that
// confirms cleanup ends the launch stopped or expired; anything else ends it
// failed, and a failed cleanup queues another stop.
func (s *Store) finishLaunch(tx *sql.Tx, l *launchRow, job *JobRecord, r hostproto.JobResult, receipt string, actor Actor) error {
	if TerminalState(l.State) || job.Type == hostproto.JobCollect {
		if receipt == "" || l.receipt != "" {
			return nil
		}
		if _, err := tx.Exec("UPDATE launches SET receipt=?,updated=?,revision=revision+1 WHERE id=? AND receipt=''", receipt, stamp(), l.ID); err != nil {
			return err
		}
		l.receipt, l.Revision = receipt, l.Revision+1
		if err := appendLaunchEvent(tx, l, "receipt", actor.Subject, "The host attached the evidence receipt", map[string]string{"job_id": job.ID, "receipt_digest": digest([]byte(receipt))}); err != nil {
			return err
		}
		_, err := appendAudit(tx, Operation{Actor: actor, Action: "launch.receipt.attached", Resource: "launch:" + l.ID, Run: l.ID, Reason: "Attach a late evidence receipt", RequestID: "hostd-" + newID(), After: map[string]string{"receipt_digest": digest([]byte(receipt)), "spec_digest": l.SpecDigest, "policy_digest": l.PolicyDigest}}, "committed")
		return err
	}
	if receipt == "" {
		missing := r.EvidenceMissing
		if missing == "" {
			missing = "receipt_missing"
		}
		if l.State == StateRequested || l.State == StateApprovalPending {
			return nil
		}
		return s.transitionLaunch(tx, l, transition{To: StateFailed, Reason: "host:" + r.Reason, EvidenceMissing: missing, Actor: actor})
	}
	var parsed hostproto.Receipt
	json.Unmarshal([]byte(receipt), &parsed)
	if !parsed.DomainEmpty || !parsed.EnforcementReleased {
		if err := s.transitionLaunch(tx, l, transition{To: StateFailed, Reason: "cleanup_incomplete", Receipt: receipt, Actor: actor}); err != nil {
			return err
		}
		return s.queueStop(tx, l, "cleanup-retry", actor, nil)
	}
	if r.Status != hostproto.ResultSucceeded {
		return s.transitionLaunch(tx, l, transition{To: StateFailed, Reason: "host:" + r.Reason, Receipt: receipt, Actor: actor})
	}
	if l.State != StateStopping {
		if err := s.transitionLaunch(tx, l, transition{To: StateStopping, Reason: "The agent ended: " + parsed.Reason, Actor: actor}); err != nil {
			return err
		}
	}
	to := StateStopped
	if l.StopReason == expiredReason || parsed.Reason == "expired" {
		to = StateExpired
	}
	return s.transitionLaunch(tx, l, transition{To: to, Reason: "The host confirmed an empty domain and released enforcement", Receipt: receipt, Actor: actor})
}

const expiredReason = "The launch reached its lifetime"

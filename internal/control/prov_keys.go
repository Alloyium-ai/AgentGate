// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// ProvisioningConfig bounds the job queue. Zero values select the defaults.
type ProvisioningConfig struct {
	// PollInterval is what hosts are told to use; heartbeat loss is
	// MissedHeartbeatsLimit intervals without a verified poll.
	PollInterval time.Duration
	// ApprovalTimeout cancels a launch that waits longer for approval.
	ApprovalTimeout time.Duration
	// Redelivery re-sends a delivered job that has no events after this long.
	Redelivery time.Duration
}

func (c ProvisioningConfig) pollInterval() time.Duration {
	if c.PollInterval <= 0 {
		return hostproto.DefaultPollInterval
	}
	return c.PollInterval
}
func (c ProvisioningConfig) approvalTimeout() time.Duration {
	if c.ApprovalTimeout <= 0 {
		return 24 * time.Hour
	}
	return c.ApprovalTimeout
}
func (c ProvisioningConfig) redelivery() time.Duration {
	if c.Redelivery <= 0 {
		return time.Minute
	}
	return c.Redelivery
}

func (s *Store) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// JobKeyFile is the job signing key's file name inside the store directory.
const JobKeyFile = "jobs.key"

func writePrivateKey(name string, key ed25519.PrivateKey) error {
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = f.Write(key); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func readPrivateKey(name string) (ed25519.PrivateKey, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("job key permissions differ")
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	return verifiedAuthority(raw)
}

// loadJobKey reads or creates jobs.key and reconciles it with the job_keys
// table. A key file that differs from the recorded active key retires the old
// key and marks every target enrolled with it as needing re-enrollment: those
// hosts would reject jobs signed by the new key, so nothing is queued for them.
func (s *Store) loadJobKey(dir string) error {
	name := filepath.Join(dir, JobKeyFile)
	key, err := readPrivateKey(name)
	if os.IsNotExist(err) {
		_, key, err = ed25519.GenerateKey(rand.Reader)
		if err == nil {
			err = writePrivateKey(name, key)
		}
		if err == nil {
			key, err = readPrivateKey(name)
		}
	}
	if err != nil {
		return fmt.Errorf("job key unavailable: %w", err)
	}
	s.JobKey = key
	public := key.Public().(ed25519.PublicKey)
	id := hostproto.KeyID(public)
	tx, err := s.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var active string
	err = tx.QueryRow("SELECT key_id FROM job_keys WHERE retired='' ORDER BY created DESC LIMIT 1").Scan(&active)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if active == id {
		return nil
	}
	if active != "" {
		if err = s.retireJobKeyLocked(tx, active, "job key file differs from the recorded active key"); err != nil {
			return err
		}
	}
	if _, err = tx.Exec("INSERT INTO job_keys VALUES(?,?,?,'')", id, hostproto.EncodeKey(public), stamp()); err != nil {
		return err
	}
	if _, err = appendAudit(tx, Operation{Actor: Actor{Subject: "deployment", Kind: "system"}, Action: "jobkey.activated", Resource: "jobkey:" + id, Reason: "Activate the host job signing key", RequestID: "jobkey-" + newID()}, "committed"); err != nil {
		return err
	}
	return tx.Commit()
}

// retireJobKeyLocked retires keyID. Every target bound to it that is not
// already retired or waiting for re-enrollment (active, retiring, or enrolled
// and waiting for its host key approval) moves to rekey_required: its host
// only accepts jobs signed by the key it enrolled with, so approving or using
// it later would strand it with every job silently refused. Each move and
// each cancelled job is audited.
func (s *Store) retireJobKeyLocked(tx *sql.Tx, keyID, reason string) error {
	if _, err := tx.Exec("UPDATE job_keys SET retired=? WHERE key_id=? AND retired=''", stamp(), keyID); err != nil {
		return err
	}
	system := Actor{Subject: "deployment", Kind: "system"}
	rows, err := tx.Query("SELECT id,state FROM targets WHERE job_key_id=? AND state IN ('active','awaiting_key_approval')", keyID)
	if err != nil {
		return err
	}
	type bound struct{ id, state string }
	moved := []bound{}
	for rows.Next() {
		var b bound
		if err = rows.Scan(&b.id, &b.state); err != nil {
			rows.Close()
			return err
		}
		moved = append(moved, b)
	}
	rows.Close()
	for _, b := range moved {
		if _, err = tx.Exec("UPDATE targets SET state='rekey_required',updated=?,revision=revision+1 WHERE id=?", stamp(), b.id); err != nil {
			return err
		}
		if _, err = appendAudit(tx, Operation{Actor: system, Action: "target.rekey.required", Resource: "target:" + b.id, Reason: "The job key the host enrolled with was retired; enroll the host again with a new token",
			RequestID: "jobkey-" + newID(), Before: map[string]string{"state": b.state, "job_key_id": keyID}, After: map[string]string{"state": "rekey_required"}}, "committed"); err != nil {
			return err
		}
	}
	if err = s.cancelJobs(tx, "key_id=? AND state IN ('queued','delivered')", []any{keyID}, system, "job_key_retired", "The job key that signed it was retired"); err != nil {
		return err
	}
	_, err = appendAudit(tx, Operation{Actor: system, Action: "jobkey.retired", Resource: "jobkey:" + keyID, Reason: reason, RequestID: "jobkey-" + newID(), After: map[string]int{"targets_rekey_required": len(moved)}}, "committed")
	return err
}

// cancelJobs cancels the jobs matching where, audits each one with code and
// reason, and fails a launch that was queued only for one of them (its host
// will never start it), so no launch waits silently for a job that is gone.
func (s *Store) cancelJobs(tx *sql.Tx, where string, args []any, actor Actor, code, reason string) error {
	rows, err := tx.Query("SELECT id,type,launch_id,state FROM jobs WHERE "+where, args...)
	if err != nil {
		return err
	}
	type job struct{ id, kind, launch, state string }
	list := []job{}
	for rows.Next() {
		var j job
		if err = rows.Scan(&j.id, &j.kind, &j.launch, &j.state); err != nil {
			rows.Close()
			return err
		}
		list = append(list, j)
	}
	rows.Close()
	for _, j := range list {
		if _, err = tx.Exec("UPDATE jobs SET state='cancelled',envelope='',completed=?,revision=revision+1 WHERE id=?", stamp(), j.id); err != nil {
			return err
		}
		if _, err = appendAudit(tx, Operation{Actor: actor, Action: "job.cancelled", Resource: "job:" + j.id, Run: j.launch, Reason: reason, RequestID: "jobkey-" + newID(),
			Before: map[string]string{"state": j.state, "type": j.kind}, After: map[string]string{"state": "cancelled", "reason": code}}, "committed"); err != nil {
			return err
		}
		if j.kind != hostproto.JobLaunch || j.launch == "" {
			continue
		}
		l, err := launchFrom(tx, j.launch)
		if err != nil {
			return err
		}
		if l.State == StateQueued {
			if err = s.transitionLaunch(tx, &l, transition{To: StateFailed, Reason: "Its launch job was cancelled: " + reason, EvidenceMissing: MissingNotStarted, Actor: actor}); err != nil {
				return err
			}
		}
	}
	return nil
}

// JobKeyID names the active job key.
func (s *Store) JobKeyID() string { return hostproto.KeyID(s.JobKey.Public().(ed25519.PublicKey)) }

// JobPublicKey returns the active job key in hostproto encoding.
func (s *Store) JobPublicKey() string {
	return hostproto.EncodeKey(s.JobKey.Public().(ed25519.PublicKey))
}

// RotateJobKey replaces the job signing key. It refuses while any launch is
// not terminal, because hosts enrolled with the old key reject jobs signed by
// the new one (including stops). Every active target moves to
// rekey_required and must enroll again with a new token. The old key file is
// kept as jobs.key.retired-<unix nanoseconds> for audit.
func (s *Store) RotateJobKey(dir, reason string) (string, error) {
	if err := reasonValid(reason); err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var live int
	if err := s.DB.QueryRow("SELECT count(*) FROM launches WHERE state NOT IN ('stopped','expired','failed','rejected','cancelled')").Scan(&live); err != nil {
		return "", err
	}
	if live != 0 {
		return "", fail(409, "launches_active", "Stop every launch before rotating the job key.")
	}
	_, next, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	name := filepath.Join(dir, JobKeyFile)
	staged := name + ".new"
	os.Remove(staged)
	if err = writePrivateKey(staged, next); err != nil {
		return "", err
	}
	old := s.JobKeyID()
	tx, err := s.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err = s.retireJobKeyLocked(tx, old, reason); err != nil {
		return "", err
	}
	public := next.Public().(ed25519.PublicKey)
	id := hostproto.KeyID(public)
	if _, err = tx.Exec("INSERT INTO job_keys VALUES(?,?,?,'')", id, hostproto.EncodeKey(public), stamp()); err != nil {
		return "", err
	}
	if _, err = appendAudit(tx, Operation{Actor: Actor{Subject: "deployment-administrator", Kind: "system"}, Action: "jobkey.rotated", Resource: "jobkey:" + id, Before: map[string]string{"key_id": old}, After: map[string]string{"key_id": id}, Reason: reason, RequestID: "jobkey-" + newID()}, "committed"); err != nil {
		return "", err
	}
	if err = os.Rename(name, fmt.Sprintf("%s.retired-%d", name, time.Now().UnixNano())); err != nil {
		return "", err
	}
	if err = os.Rename(staged, name); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	s.JobKey = next
	return hostproto.EncodeKey(public), nil
}

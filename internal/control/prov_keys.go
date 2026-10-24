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

func (s *Store) retireJobKeyLocked(tx *sql.Tx, keyID, reason string) error {
	if _, err := tx.Exec("UPDATE job_keys SET retired=? WHERE key_id=? AND retired=''", stamp(), keyID); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE targets SET state='rekey_required',updated=?,revision=revision+1 WHERE job_key_id=? AND state='active'", stamp(), keyID); err != nil {
		return err
	}
	if _, err := tx.Exec("UPDATE jobs SET state='cancelled',envelope='',completed=?,revision=revision+1 WHERE key_id=? AND state IN ('queued','delivered')", stamp(), keyID); err != nil {
		return err
	}
	_, err := appendAudit(tx, Operation{Actor: Actor{Subject: "deployment", Kind: "system"}, Action: "jobkey.retired", Resource: "jobkey:" + keyID, Reason: reason, RequestID: "jobkey-" + newID()}, "committed")
	return err
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

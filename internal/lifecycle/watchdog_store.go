// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
)

// OpenWatchdogStore must use a separate root-owned private file from the node
// journal. It retains terminal leases to reject replay after either process dies.
func OpenWatchdogStore(path string) (*SQLiteJournal, error) {
	journal, err := OpenJournal(path)
	if err != nil {
		return nil, err
	}
	_, err = journal.db.Exec(`CREATE TABLE IF NOT EXISTS watchdog_leases(run_id TEXT PRIMARY KEY,state TEXT NOT NULL,revision INTEGER NOT NULL,record TEXT NOT NULL);CREATE INDEX IF NOT EXISTS watchdog_active ON watchdog_leases(state);CREATE TABLE IF NOT EXISTS watchdog_stops(digest TEXT PRIMARY KEY,evidence TEXT NOT NULL);`)
	if err != nil {
		journal.Close()
		return nil, err
	}
	return journal, nil
}
func validWatchdogLease(lease WatchdogLease) error {
	b := lease.Ack.Binding
	if lease.NoDomain != (lease.RetiredBootID != "") || (lease.NoDomain && (lease.State != "stopped" || !identifier.MatchString(lease.RetiredBootID) || lease.RetiredBootID == b.BootID)) {
		return errors.New("watchdog boot retirement is invalid")
	}
	if b.validate(b.CgroupID == 0) != nil || lease.Revision == 0 || lease.HeartbeatDeadlineNS == 0 || lease.HeartbeatDeadlineNS > b.DeadlineNS || (lease.State != "armed" && lease.State != "active" && lease.State != "reserved" && lease.State != "stopped") {
		return errors.New("watchdog durable lease is invalid")
	}
	if ((lease.State == "reserved" || lease.State == "armed") && (lease.PreparationDeadlineNS == 0 || lease.HeartbeatDeadlineNS > lease.PreparationDeadlineNS)) || (lease.State == "reserved" && b.CgroupID != 0) {
		return errors.New("watchdog preparation reservation is invalid")
	}
	if (lease.State == "armed" || lease.State == "active") && b.CgroupID == 0 {
		return errors.New("watchdog execution lease requires an actual domain")
	}
	if lease.EffectiveDeadlineNS > b.DeadlineNS || ((lease.State == "reserved" || lease.State == "armed") && lease.EffectiveDeadlineNS != 0) || (lease.State == "active" && lease.EffectiveDeadlineNS != 0 && lease.HeartbeatDeadlineNS > lease.EffectiveDeadlineNS) {
		return errors.New("watchdog effective grant cutoff is invalid")
	}
	return nil
}
func (j *SQLiteJournal) LoadWatchdog(ctx context.Context) ([]WatchdogLease, error) {
	return j.loadWatchdog(ctx, true)
}
func (j *SQLiteJournal) WatchdogHistory(ctx context.Context) ([]WatchdogLease, error) {
	return j.loadWatchdog(ctx, false)
}
func (j *SQLiteJournal) loadWatchdog(ctx context.Context, active bool) ([]WatchdogLease, error) {
	query := `SELECT run_id,state,revision,record FROM watchdog_leases`
	if active {
		query += ` WHERE state IN ('reserved','armed','active')`
	}
	query += ` ORDER BY run_id`
	rows, err := j.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WatchdogLease{}
	for rows.Next() {
		var run, state, raw string
		var revision uint64
		if err = rows.Scan(&run, &state, &revision, &raw); err != nil {
			return nil, err
		}
		var lease WatchdogLease
		if json.Unmarshal([]byte(raw), &lease) != nil || lease.Ack.Binding.RunID != run || lease.State != state || lease.Revision != revision || validWatchdogLease(lease) != nil {
			return nil, errors.New("watchdog lease store is corrupt")
		}
		out = append(out, lease)
	}
	return out, rows.Err()
}
func (j *SQLiteJournal) SaveWatchdog(ctx context.Context, lease WatchdogLease, expected uint64) error {
	if expected >= math.MaxInt64 || lease.Revision != expected+1 || validWatchdogLease(lease) != nil || (lease.State == "active" && lease.EffectiveDeadlineNS == 0) {
		return ErrConflict
	}
	raw, err := json.Marshal(lease)
	if err != nil {
		return err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if expected == 0 {
		if lease.State != "reserved" {
			return errors.New("watchdog lease must begin with a durable preparation reservation")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO watchdog_leases VALUES(?,?,?,?)`, lease.Ack.Binding.RunID, lease.State, lease.Revision, string(raw)); err != nil {
			return ErrReplay
		}
	} else {
		var previous string
		if tx.QueryRowContext(ctx, `SELECT record FROM watchdog_leases WHERE run_id=? AND revision=?`, lease.Ack.Binding.RunID, expected).Scan(&previous) != nil {
			return ErrConflict
		}
		var prior WatchdogLease
		if json.Unmarshal([]byte(previous), &prior) != nil || validWatchdogLease(prior) != nil {
			return errors.New("watchdog prior lease is corrupt")
		}
		if prior.State == "stopped" && !reflect.DeepEqual(prior.Ack, lease.Ack) {
			return ErrReplay
		}
		if prior.EffectiveDeadlineNS != lease.EffectiveDeadlineNS && !(prior.State == "armed" && lease.State == "active" && prior.EffectiveDeadlineNS == 0 && lease.EffectiveDeadlineNS > 0) {
			return errors.New("watchdog effective grant cutoff is immutable")
		}
		permitted := prior.State == lease.State || (prior.State == "reserved" && lease.State == "armed") || (prior.State == "armed" && lease.State == "active") || lease.State == "stopped"
		old := prior.Ack
		if prior.State == "reserved" && lease.State == "armed" {
			old.Binding.CgroupID = lease.Ack.Binding.CgroupID
			old.Signature = lease.Ack.Signature
			old.IssuedNS = lease.Ack.IssuedNS
		}
		if (prior.NoDomain && (!lease.NoDomain || prior.RetiredBootID != lease.RetiredBootID)) || !permitted || !reflect.DeepEqual(old, lease.Ack) || prior.PreparationDeadlineNS != lease.PreparationDeadlineNS || (prior.State == "stopped" && lease.State != "stopped") {
			return errors.New("watchdog lease identity is immutable")
		}
		result, err := tx.ExecContext(ctx, `UPDATE watchdog_leases SET state=?,revision=?,record=? WHERE run_id=? AND revision=?`, lease.State, lease.Revision, string(raw), lease.Ack.Binding.RunID, expected)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return ErrConflict
		}
	}
	return tx.Commit()
}
func (j *SQLiteJournal) SaveWatchdogStop(ctx context.Context, e WatchdogStopEvidence) error {
	if !confirmedWatchdogStop(e) {
		return errors.New("watchdog stop evidence is invalid")
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = j.db.ExecContext(ctx, `INSERT INTO watchdog_stops VALUES(?,?) ON CONFLICT(digest) DO NOTHING`, e.Digest, string(raw))
	return err
}

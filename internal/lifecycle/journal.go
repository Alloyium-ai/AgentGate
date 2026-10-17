// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

type SQLiteJournal struct {
	db   *sql.DB
	path string
}

const journalSchema = `
PRAGMA application_id=1095191619;
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS lifecycle_proof_nonces(subject TEXT NOT NULL,nonce TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(subject,nonce));
CREATE INDEX IF NOT EXISTS lifecycle_proof_expiry ON lifecycle_proof_nonces(expires);
CREATE TABLE IF NOT EXISTS lifecycle_orphan_stops(digest TEXT PRIMARY KEY,evidence TEXT NOT NULL);
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS lifecycle_records (
 run_id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, node_id TEXT NOT NULL,
 boot_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK(generation>0),
 revision INTEGER NOT NULL CHECK(revision>0), record TEXT NOT NULL,
 UNIQUE(agent_id,node_id,boot_id,generation)
);
CREATE TABLE IF NOT EXISTS lifecycle_generations (
 agent_id TEXT NOT NULL,node_id TEXT NOT NULL,boot_id TEXT NOT NULL,
 generation INTEGER NOT NULL CHECK(generation>0),PRIMARY KEY(agent_id,node_id,boot_id)
);`

func OpenJournal(path string) (*SQLiteJournal, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
		return nil, errors.New("an absolute lifecycle journal path is required")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || parent != filepath.Dir(path) {
		return nil, errors.New("the lifecycle journal parent must be unlinked")
	}
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("the lifecycle journal directory must be private")
	}
	created := false
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		created = true
		err = file.Close()
	} else if os.IsExist(err) {
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("the lifecycle journal file must be private and regular")
		}
		err = nil
	}
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if !created {
		var applicationID int
		if err = db.QueryRow(`PRAGMA application_id`).Scan(&applicationID); err != nil || applicationID != 1095191619 {
			db.Close()
			return nil, errors.New("the existing database is not a lifecycle journal")
		}
	}
	if _, err = db.Exec(journalSchema); err != nil {
		db.Close()
		return nil, err
	}
	return &SQLiteJournal{db: db, path: path}, nil
}
func (j *SQLiteJournal) Close() error { return j.db.Close() }

func (j *SQLiteJournal) Save(ctx context.Context, record Record, expected uint64) error {
	if err := record.Binding.validate(record.Binding.CgroupID == 0); err != nil {
		return err
	}
	if expected >= math.MaxInt64 || record.Revision != expected+1 {
		return ErrConflict
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	b := record.Binding
	if expected == 0 {
		if record.State != "preparing" || record.Binding.CgroupID != 0 || record.Authorization != nil || record.Process != nil || len(record.Evidence) != 0 {
			return errors.New("lifecycle journal must begin with a held-domain reservation")
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO lifecycle_generations VALUES(?,?,?,?) ON CONFLICT(agent_id,node_id,boot_id) DO UPDATE SET generation=excluded.generation WHERE excluded.generation>lifecycle_generations.generation`, b.AgentID, b.NodeID, b.BootID, b.Generation)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrReplay
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO lifecycle_records VALUES(?,?,?,?,?,?,?)`, b.RunID, b.AgentID, b.NodeID, b.BootID, b.Generation, record.Revision, string(raw)); err != nil {
			return ErrReplay
		}
	} else {
		var priorJSON string
		if err = tx.QueryRowContext(ctx, `SELECT record FROM lifecycle_records WHERE run_id=? AND revision=?`, b.RunID, expected).Scan(&priorJSON); err != nil {
			return ErrConflict
		}
		var prior Record
		if err = json.Unmarshal([]byte(priorJSON), &prior); err != nil {
			return errors.New("the prior lifecycle record is invalid")
		}
		if err = recordTransition(prior, record); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE lifecycle_records SET revision=?,record=? WHERE run_id=? AND revision=? AND agent_id=? AND node_id=? AND boot_id=? AND generation=?`, record.Revision, string(raw), b.RunID, expected, b.AgentID, b.NodeID, b.BootID, b.Generation)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if count != 1 {
			return ErrConflict
		}
	}
	return tx.Commit()
}

type recordScanner interface{ Scan(...any) error }

func scanRecord(row recordScanner) (Record, error) {
	var run, agent, node, boot, raw string
	var generation, revision uint64
	if err := row.Scan(&run, &agent, &node, &boot, &generation, &revision, &raw); err != nil {
		return Record{}, err
	}
	var record Record
	if err := json.Unmarshal([]byte(raw), &record); err != nil {
		return record, errors.New("the lifecycle journal record is invalid")
	}
	binding := record.Binding
	if binding.RunID != run || binding.AgentID != agent || binding.NodeID != node || binding.BootID != boot || binding.Generation != generation || record.Revision != revision {
		return record, errors.New("the lifecycle journal record binding differs")
	}
	return record, binding.validate(binding.CgroupID == 0)
}
func (j *SQLiteJournal) Load(ctx context.Context) ([]Record, error) {
	rows, err := j.db.QueryContext(ctx, `SELECT run_id,agent_id,node_id,boot_id,generation,revision,record FROM lifecycle_records ORDER BY run_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []Record{}
	for rows.Next() {
		record, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}
func (j *SQLiteJournal) Lookup(ctx context.Context, runID string) (Record, error) {
	record, err := scanRecord(j.db.QueryRowContext(ctx, `SELECT run_id,agent_id,node_id,boot_id,generation,revision,record FROM lifecycle_records WHERE run_id=?`, runID))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	return record, err
}

func (j *SQLiteJournal) SaveOrphan(ctx context.Context, e Evidence) error {
	if err := e.Binding.validate(false); err != nil {
		return err
	}
	if err := checkEvidence(e, e.Binding, "stopped"); err != nil {
		return err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = j.db.ExecContext(ctx, `INSERT INTO lifecycle_orphan_stops VALUES(?,?) ON CONFLICT(digest) DO NOTHING`, e.Digest, string(raw))
	return err
}

// GenerationFloor reads the durable replay floor without allocating a generation.
// A caller must still use Prepare's atomic journal reservation for admission.
func (j *SQLiteJournal) GenerationFloor(ctx context.Context, agent, node, boot string) (uint64, error) {
	if !identifier.MatchString(agent) || !identifier.MatchString(node) || !identifier.MatchString(boot) {
		return 0, errors.New("the generation floor identity is invalid")
	}
	var generation int64
	var storageType string
	err := j.db.QueryRowContext(ctx, `SELECT generation,typeof(generation) FROM lifecycle_generations WHERE agent_id=? AND node_id=? AND boot_id=?`, agent, node, boot).Scan(&generation, &storageType)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil || storageType != "integer" || generation <= 0 || generation == math.MaxInt64 {
		return 0, errors.New("the durable generation floor is unavailable, invalid or exhausted")
	}
	return uint64(generation), nil
}

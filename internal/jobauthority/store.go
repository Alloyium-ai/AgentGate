// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	_ "modernc.org/sqlite"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var ErrConflict = errors.New("authority_conflict")
var ErrUnknown = errors.New("authority_unknown_grant")

type Store struct {
	db    *sql.DB
	epoch string
	lock  *os.File
}

const storeSchema = `PRAGMA application_id=1095191617; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS authority_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS authority_nonces(subject TEXT NOT NULL,nonce TEXT NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(subject,nonce));
CREATE TABLE IF NOT EXISTS authority_grants(grant_id TEXT PRIMARY KEY,node_id TEXT NOT NULL,run_id TEXT NOT NULL,domain_epoch TEXT NOT NULL UNIQUE,authorization BLOB NOT NULL,revoked INTEGER NOT NULL DEFAULT 0,receipt BLOB,seal_digest TEXT,UNIQUE(node_id,run_id));
`

func privatePath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
		return errors.New("authority_private_path_required")
	}
	parent := filepath.Dir(path)
	resolved, e := filepath.EvalSymlinks(parent)
	if e != nil || resolved != parent {
		return errors.New("authority_private_parent_required")
	}
	for ancestor := parent; ancestor != "/"; ancestor = filepath.Dir(ancestor) {
		st, e := os.Stat(ancestor)
		if e != nil || !st.IsDir() || st.Mode().Perm()&0022 != 0 {
			return errors.New("authority_parent_custody_invalid")
		}
		x, ok := st.Sys().(*syscall.Stat_t)
		if !ok || (x.Uid != 0 && x.Uid != uint32(os.Geteuid())) {
			return errors.New("authority_parent_custody_invalid")
		}
	}
	st, e := os.Stat(parent)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0077 != 0 {
		return errors.New("authority_private_parent_required")
	}
	if x, ok := st.Sys().(*syscall.Stat_t); !ok || x.Uid != uint32(os.Geteuid()) {
		return errors.New("authority_private_owner_required")
	}
	return nil
}
func OpenStore(path, epoch string) (*Store, error) {
	if !identifier.MatchString(epoch) {
		return nil, errors.New("authority_epoch_invalid")
	}
	if e := privatePath(path); e != nil {
		return nil, e
	}
	lock, e := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return nil, e
	}
	if e = checkPrivateFile(path + ".lock"); e != nil {
		lock.Close()
		return nil, e
	}
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		lock.Close()
		return nil, errors.New("authority_store_in_use")
	}
	success := false
	defer func() {
		if !success {
			lock.Close()
		}
	}()
	created := false
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e == nil {
		created = true
		e = f.Close()
	} else if os.IsExist(e) {
		e = checkPrivateFile(path)
	}
	if e != nil {
		return nil, e
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*Store, error) { db.Close(); return nil, e }
	if !created {
		var id int
		if e = db.QueryRow(`PRAGMA application_id`).Scan(&id); e != nil || id != 1095191617 {
			return fail(errors.New("authority_store_identity_invalid"))
		}
	}
	if _, e = db.Exec(storeSchema); e != nil {
		return fail(e)
	}
	if _, e = db.Exec(`INSERT OR IGNORE INTO authority_meta(key,value) VALUES('epoch',?)`, epoch); e != nil {
		return fail(e)
	}
	var saved string
	if e = db.QueryRow(`SELECT value FROM authority_meta WHERE key='epoch'`).Scan(&saved); e != nil || saved != epoch {
		return fail(errors.New("authority_epoch_differs"))
	}
	directory, e := os.Open(filepath.Dir(path))
	if e != nil {
		return fail(e)
	}
	e = directory.Sync()
	directory.Close()
	if e != nil {
		return fail(e)
	}
	success = true
	return &Store{db: db, epoch: saved, lock: lock}, nil
}
func checkPrivateFile(path string) error {
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0077 != 0 {
		return errors.New("authority_private_file_required")
	}
	x, ok := st.Sys().(*syscall.Stat_t)
	if !ok || x.Uid != uint32(os.Geteuid()) || x.Nlink != 1 {
		return errors.New("authority_private_owner_required")
	}
	return nil
}
func (s *Store) Close() error {
	e := s.db.Close()
	if s.lock != nil {
		_ = s.lock.Close()
	}
	return e
}
func (s *Store) Epoch() string { return s.epoch }
func (s *Store) Consume(ctx context.Context, subject, nonce string, expires, now int64) error {
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.ExecContext(ctx, `DELETE FROM authority_nonces WHERE expires < ?`, now); e != nil {
		return e
	}
	if _, e = tx.ExecContext(ctx, `INSERT INTO authority_nonces(subject,nonce,expires) VALUES(?,?,?)`, subject, nonce, expires); e != nil {
		return ErrConflict
	}
	return tx.Commit()
}
func (s *Store) SaveGrant(ctx context.Context, a lifecycle.Authorization) error {
	raw, e := json.Marshal(a)
	if e != nil {
		return e
	}
	_, e = s.db.ExecContext(ctx, `INSERT INTO authority_grants(grant_id,node_id,run_id,domain_epoch,authorization) VALUES(?,?,?,?,?)`, a.Binding.GrantID, a.Binding.NodeID, a.Binding.RunID, fmt.Sprintf("%s/%s/%d/%d", a.Binding.NodeID, a.Binding.BootID, a.Binding.CgroupID, a.Binding.Generation), raw)
	if e != nil {
		return ErrConflict
	}
	return nil
}
func (s *Store) Grant(ctx context.Context, id string) (lifecycle.Authorization, bool, error) {
	var a lifecycle.Authorization
	var raw []byte
	var revoked bool
	e := s.db.QueryRowContext(ctx, `SELECT authorization,revoked FROM authority_grants WHERE grant_id=?`, id).Scan(&raw, &revoked)
	if errors.Is(e, sql.ErrNoRows) {
		return a, false, ErrUnknown
	}
	if e != nil {
		return a, false, e
	}
	if e = lifecycle.DecodeTransport(strings.NewReader(string(raw)), &a); e != nil {
		return a, false, e
	}
	return a, revoked, nil
}
func (s *Store) Revoke(ctx context.Context, id string) error {
	r, e := s.db.ExecContext(ctx, `UPDATE authority_grants SET revoked=1 WHERE grant_id=?`, id)
	if e != nil {
		return e
	}
	n, e := r.RowsAffected()
	if e == nil && n != 1 {
		return ErrUnknown
	}
	return e
}
func (s *Store) SaveReceipt(ctx context.Context, id, seal string, revoked bool, r jobaudit.AuthorityReceipt) error {
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	result, e := s.db.ExecContext(ctx, `UPDATE authority_grants SET receipt=?,seal_digest=? WHERE grant_id=? AND revoked=? AND (seal_digest IS NULL OR seal_digest=?)`, raw, seal, id, revoked, seal)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e == nil && n != 1 {
		return ErrConflict
	}
	return e
}
func (s *Store) bindSigner(identity string) error {
	if _, e := s.db.Exec(`INSERT OR IGNORE INTO authority_meta(key,value) VALUES('signer',?)`, identity); e != nil {
		return e
	}
	var saved string
	if e := s.db.QueryRow(`SELECT value FROM authority_meta WHERE key='signer'`).Scan(&saved); e != nil {
		return e
	}
	if saved != identity {
		return errors.New("authority_signer_differs")
	}
	return nil
}

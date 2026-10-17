// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package localconfig

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

const schema = `CREATE TABLE IF NOT EXISTS config_versions(revision INTEGER PRIMARY KEY,record TEXT NOT NULL,signature TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS config_version_no_update BEFORE UPDATE ON config_versions BEGIN SELECT RAISE(ABORT,'immutable configuration'); END;
CREATE TRIGGER IF NOT EXISTS config_version_no_delete BEFORE DELETE ON config_versions BEGIN SELECT RAISE(ABORT,'immutable configuration'); END;
CREATE TABLE IF NOT EXISTS config_active(singleton INTEGER PRIMARY KEY CHECK(singleton=1),revision INTEGER NOT NULL REFERENCES config_versions(revision));
CREATE TABLE IF NOT EXISTS config_audit(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,kind TEXT NOT NULL,reason TEXT NOT NULL,request_id TEXT NOT NULL,time TEXT NOT NULL,before_json TEXT NOT NULL,after_json TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS config_audit_no_update BEFORE UPDATE ON config_audit BEGIN SELECT RAISE(ABORT,'append-only configuration audit'); END;
CREATE TRIGGER IF NOT EXISTS config_audit_no_delete BEFORE DELETE ON config_audit BEGIN SELECT RAISE(ABORT,'append-only configuration audit'); END;`

type Trust struct {
	Schema   string `json:"schema"`
	Instance string `json:"instance"`
	Public   string `json:"public_key"`
}
type Record struct {
	Schema   string   `json:"schema"`
	Instance string   `json:"instance"`
	Revision int64    `json:"revision"`
	Parent   int64    `json:"parent"`
	Settings Settings `json:"settings"`
}
type Operation struct {
	Actor, Kind, Reason, RequestID string
}
type Anchor struct {
	Revision int64  `json:"revision"`
	Digest   string `json:"digest"`
}
type Store struct {
	DB           *sql.DB
	Trust        Trust
	key          ed25519.PrivateKey
	anchorPath   string
	mu           sync.Mutex
	initializing bool
}

func validateDirectories(dir, trust string) error {
	if !filepath.IsAbs(dir) || !filepath.IsAbs(trust) || filepath.Clean(dir) != dir || filepath.Clean(trust) != trust {
		return errors.New("absolute clean state and trust paths required")
	}
	for _, path := range []string{dir, trust} {
		info, err := os.Lstat(path)
		actual, linkErr := filepath.EvalSymlinks(path)
		if err != nil || linkErr != nil || actual != path || !info.IsDir() || info.Mode().Perm() != 0700 {
			return errors.New("private unlinked state and trust directories required")
		}
	}
	if dir == trust || strings.HasPrefix(trust, dir+"/") || strings.HasPrefix(dir, trust+"/") {
		return errors.New("independent state and trust directories required")
	}
	return nil
}

func privateRead(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("private regular trust file required")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 65537))
}

func (s *Store) anchorLock() (func(), error) {
	fd, err := syscall.Open(filepath.Join(filepath.Dir(s.anchorPath), "anchor.lock"), syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "anchor.lock")
	if err = syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() { syscall.Flock(fd, syscall.LOCK_UN); file.Close() }, nil
}

func privateJSON(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if _, err = file.Write(data); err != nil {
		return err
	}
	return file.Sync()
}

func New(dir, trustDir string, settings Settings) (*Store, error) {
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(dir) || !filepath.IsAbs(trustDir) || dir == trustDir {
		return nil, errors.New("separate absolute state and trust directories required")
	}
	for _, name := range []string{dir, trustDir} {
		if err := os.Mkdir(name, 0700); err != nil {
			return nil, err
		}
	}
	if err := validateDirectories(dir, trustDir); err != nil {
		return nil, err
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	identity := make([]byte, 16)
	if _, err = rand.Read(identity); err != nil {
		return nil, err
	}
	trust := Trust{"agentgate.community.trust.v1", hex.EncodeToString(identity), base64.RawURLEncoding.EncodeToString(public)}
	if err = os.WriteFile(filepath.Join(dir, "config.key"), key, 0600); err != nil {
		return nil, err
	}
	if err = privateJSON(filepath.Join(trustDir, "trust.json"), trust); err != nil {
		return nil, err
	}
	if err = privateJSON(filepath.Join(trustDir, "anchor.json"), Anchor{}); err != nil {
		return nil, err
	}
	store, err := open(dir, trustDir, true)
	if err != nil {
		return nil, err
	}
	_, err = store.Publish(Operation{Actor: "deployment-administrator", Kind: "system", Reason: "Initialize the protected customer configuration.", RequestID: trust.Instance}, settings, 0)
	if err != nil {
		store.DB.Close()
		return nil, err
	}
	if _, err = store.Read(); err != nil {
		store.DB.Close()
		return nil, err
	}
	return store, nil
}

func Open(dir, trustDir string) (*Store, error) {
	return open(dir, trustDir, false)
}

func open(dir, trustDir string, initializing bool) (*Store, error) {
	if err := validateDirectories(dir, trustDir); err != nil {
		return nil, err
	}
	if !initializing {
		info, err := os.Lstat(filepath.Join(dir, "config.db"))
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("configuration database unavailable")
		}
	}
	data, err := privateRead(filepath.Join(trustDir, "trust.json"))
	if err != nil {
		return nil, err
	}
	var trust Trust
	if json.Unmarshal(data, &trust) != nil || trust.Schema != "agentgate.community.trust.v1" || len(trust.Instance) != 32 {
		return nil, errors.New("invalid local trust")
	}
	keyPath := filepath.Join(dir, "config.key")
	info, err := os.Lstat(keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, errors.New("private configuration key required")
	}
	key, err := privateRead(keyPath)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, errors.New("configuration key unavailable")
	}
	derived := ed25519.NewKeyFromSeed(key[:32])
	if !ed25519.PrivateKey(key).Equal(derived) || base64.RawURLEncoding.EncodeToString(derived.Public().(ed25519.PublicKey)) != trust.Public {
		return nil, errors.New("configuration key or trust differs")
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "config.db")+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)&_pragma=temp_store(MEMORY)")
	if err != nil {
		return nil, err
	}
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	if err = os.Chmod(filepath.Join(dir, "config.db"), 0600); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{DB: db, Trust: trust, key: derived, anchorPath: filepath.Join(trustDir, "anchor.json"), initializing: initializing}, nil
}

func (s *Store) Publish(op Operation, settings Settings, parent int64) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.anchorLock()
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	if !s.initializing {
		if _, err := s.readLocked(); err != nil {
			return Record{}, err
		}
	}
	if op.Actor != "deployment-administrator" || op.Kind != "system" || op.RequestID == "" || len(op.Reason) < 3 || len(op.Reason) > 512 {
		return Record{}, errors.New("trusted configuration administration required")
	}
	if err := settings.Validate(); err != nil {
		return Record{}, err
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRow("SELECT revision FROM config_active WHERE singleton=1").Scan(&current)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Record{}, err
	}
	if current != parent {
		return Record{}, errors.New("configuration parent conflict")
	}
	var before string
	if current > 0 {
		if err = tx.QueryRow("SELECT record FROM config_versions WHERE revision=?", current).Scan(&before); err != nil {
			return Record{}, err
		}
	}
	record := Record{"agentgate.community.config.v1", s.Trust.Instance, current + 1, current, settings}
	bytes, err := json.Marshal(record)
	if err != nil {
		return Record{}, err
	}
	signature := base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.key, bytes))
	if _, err = tx.Exec("INSERT INTO config_versions VALUES(?,?,?)", record.Revision, string(bytes), signature); err != nil {
		return Record{}, err
	}
	if _, err = tx.Exec("INSERT INTO config_audit(actor,kind,reason,request_id,time,before_json,after_json) VALUES(?,?,?,?,?,?,?)", op.Actor, op.Kind, op.Reason, op.RequestID, time.Now().UTC().Format(time.RFC3339Nano), before, string(bytes)); err != nil {
		return Record{}, err
	}
	if _, err = tx.Exec("INSERT INTO config_active VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET revision=excluded.revision", record.Revision); err != nil {
		return Record{}, err
	}
	if err = tx.Commit(); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *Store) Read() (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	unlock, err := s.anchorLock()
	if err != nil {
		return Record{}, err
	}
	defer unlock()
	return s.readLocked()
}
func (s *Store) readLocked() (Record, error) {
	data, err := privateRead(s.anchorPath)
	if err != nil {
		return Record{}, err
	}
	var anchor Anchor
	if json.Unmarshal(data, &anchor) != nil || anchor.Revision < 0 || anchor.Revision == 0 && !s.initializing || anchor.Revision > 0 && len(anchor.Digest) != 64 {
		return Record{}, errors.New("invalid independent configuration anchor")
	}
	var raw, signature string
	var revision int64
	if err = s.DB.QueryRow("SELECT v.revision,v.record,v.signature FROM config_active a JOIN config_versions v ON v.revision=a.revision WHERE a.singleton=1").Scan(&revision, &raw, &signature); err != nil {
		return Record{}, err
	}
	var record Record
	if json.Unmarshal([]byte(raw), &record) != nil || record.Schema != "agentgate.community.config.v1" || record.Instance != s.Trust.Instance || record.Revision != revision || record.Parent != revision-1 || record.Revision < 1 || record.Revision < anchor.Revision {
		return Record{}, errors.New("configuration binding or revision differs")
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || !ed25519.Verify(s.key.Public().(ed25519.PublicKey), []byte(raw), sig) {
		return Record{}, errors.New("configuration signature differs")
	}
	if err = record.Settings.Validate(); err != nil {
		return Record{}, err
	}
	hash := sha256.Sum256([]byte(raw))
	digest := hex.EncodeToString(hash[:])
	if record.Revision == anchor.Revision && anchor.Digest != digest {
		return Record{}, errors.New("configuration anchor differs")
	}
	if record.Revision > anchor.Revision {
		file, err := os.CreateTemp(filepath.Dir(s.anchorPath), ".anchor-")
		if err != nil {
			return Record{}, err
		}
		temporary := file.Name()
		defer os.Remove(temporary)
		if err = file.Chmod(0600); err == nil {
			err = json.NewEncoder(file).Encode(Anchor{record.Revision, digest})
		}
		if err == nil {
			err = file.Sync()
		}
		file.Close()
		if err != nil {
			return Record{}, err
		}
		if err = os.Rename(temporary, s.anchorPath); err != nil {
			return Record{}, err
		}
		directory, err := os.Open(filepath.Dir(s.anchorPath))
		if err != nil {
			return Record{}, err
		}
		err = directory.Sync()
		directory.Close()
		if err != nil {
			return Record{}, err
		}
		s.initializing = false
	}
	return record, nil
}

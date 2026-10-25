// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package secretseal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ErrStore never names a value or a path's contents.
var ErrStore = errors.New("secretseal: secret store custody is invalid")

// ErrLegacyStore reports a store directory that still holds the earlier
// two-file layout (NAME plus NAME.meta.json). Those files were replaced by
// two separate renames, so a failure between them could leave a value under
// another value's record. Such a store is refused whole: remove the files and
// seal every secret again.
var ErrLegacyStore = errors.New("secretseal: the secret store holds secrets in the earlier two-file format (NAME and NAME.meta.json); remove them and seal each secret again")

const (
	fingerprintKeyFile = ".fingerprint-key"
	recordSuffix       = ".secret"
	legacyMetaSuffix   = ".meta.json"
	pendingPrefix      = ".pending-"
	recordFormat       = EnvelopeFormat + ".record"
	// maxRecordBytes bounds a record: its metadata line plus the value.
	maxRecordBytes = 4096 + MaxValueBytes
)

// Store is the host's secret directory. Each secret name has exactly one
// record file, NAME.secret (root-owned, 0600), holding the value together
// with the accepted version, envelope nonce, sealed policy digest and keyed
// fingerprint. A record is committed by writing a fresh temporary file,
// fsyncing it, renaming it over NAME.secret once and fsyncing the directory,
// so a reader sees either the whole previous record or the whole new one and
// never a value next to another value's version or policy. A deletion commits
// a tombstone record the same way. The directory must be owned by the host
// agent's user, mode 0700, and outside every sandbox mount. The broker never
// reads a record: the host agent copies one verified value per launch into
// that launch's broker directory.
type Store struct {
	dir   string
	fpKey []byte
	// Validate, when set, must accept a value before it is stored (for
	// example broker.ValidSecret, so a value the broker cannot inject is
	// refused at secret-put time rather than at launch).
	Validate func([]byte) bool
	// ops performs the file system calls of a commit; nil is the real file
	// system. Tests replace it to fail or stop at each step.
	ops fileOps
}

// secretRecord is one name's committed state. Value is absent in a
// tombstone, which keeps the last version so an earlier envelope relayed
// again is still refused as a replay. On disk a record is its metadata as one
// line of JSON, a newline, then exactly ValueBytes bytes of value, so the
// value never passes through a JSON encoder's buffers.
type secretRecord struct {
	Format   string `json:"format"`
	TargetID string `json:"target_id"`
	Name     string `json:"name"`
	Version  uint64 `json:"version"`
	Nonce    string `json:"nonce"`
	// PolicyDigest is the injection policy the value was sealed for (the
	// HPKE associated data bound it); the value may be used only under it.
	PolicyDigest string `json:"policy_digest"`
	Fingerprint  string `json:"fingerprint"`
	UpdatedAt    string `json:"updated_at"`
	Deleted      bool   `json:"deleted,omitempty"`
	ValueBytes   int    `json:"value_bytes"`
	Value        []byte `json:"-"`
}

func (r *secretRecord) wipe() {
	if r != nil {
		clear(r.Value)
	}
}

// encode lays the record out as metadata line plus value.
func (r *secretRecord) encode() ([]byte, error) {
	meta := *r
	meta.Value, meta.ValueBytes = nil, len(r.Value)
	head, err := json.Marshal(&meta)
	if err != nil || bytes.IndexByte(head, '\n') >= 0 {
		return nil, ErrStore
	}
	out := make([]byte, 0, len(head)+1+len(r.Value))
	out = append(append(append(out, head...), '\n'), r.Value...)
	return out, nil
}

// fileOps is every file system call a record commit makes.
type fileOps interface {
	createTemp(path string) (int, error)
	write(fd int, data []byte) (int, error)
	fsync(fd int) error
	close(fd int) error
	rename(from, to string) error
	syncDir(dir string) error
	pwrite(fd int, data []byte, off int64) (int, error)
	unlink(path string) error
}

type osOps struct{}

func (osOps) createTemp(path string) (int, error) {
	return unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
}
func (osOps) write(fd int, data []byte) (int, error) { return unix.Write(fd, data) }
func (osOps) fsync(fd int) error                     { return unix.Fsync(fd) }
func (osOps) close(fd int) error                     { return unix.Close(fd) }
func (osOps) rename(from, to string) error           { return unix.Rename(from, to) }
func (osOps) pwrite(fd int, data []byte, off int64) (int, error) {
	return unix.Pwrite(fd, data, off)
}
func (osOps) unlink(path string) error { return unix.Unlink(path) }
func (osOps) syncDir(dir string) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	err = unix.Fsync(fd)
	unix.Close(fd)
	return err
}

func (s *Store) fs() fileOps {
	if s.ops != nil {
		return s.ops
	}
	return osOps{}
}

func checkDir(dir string) error {
	var st unix.Stat_t
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || unix.Lstat(dir, &st) != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != os.Geteuid() || st.Mode&0o077 != 0 {
		return ErrStore
	}
	return nil
}

// OpenStore opens dir, creating its random fingerprint key on first use. It
// refuses a directory that holds the earlier two-file layout
// (ErrLegacyStore), and under the store lock it zeroes and removes any
// temporary record a crash left behind.
func OpenStore(dir string) (*Store, error) {
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.scan(); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, fingerprintKeyFile)
	key, err := readPrivate(path, 32)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		if err := writePrivate(path, key, true); err != nil {
			// Another opener may have won the race; use its key.
			if key, err = readPrivate(path, 32); err != nil {
				return nil, ErrStore
			}
		}
	} else if err != nil {
		return nil, ErrStore
	}
	if len(key) != 32 {
		return nil, ErrStore
	}
	s.fpKey = key
	return s, nil
}

// scan refuses a legacy layout and sweeps temporary records. The caller
// holds the lock.
func (s *Store) scan() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return ErrStore
	}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasSuffix(name, legacyMetaSuffix), namePattern.MatchString(name):
			return ErrLegacyStore
		case strings.HasPrefix(name, pendingPrefix):
			if err := s.discard(filepath.Join(s.dir, name)); err != nil {
				return ErrStore
			}
		}
	}
	return nil
}

// discard zeroes and removes one temporary record (it may hold a value).
func (s *Store) discard(path string) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err == nil {
		var st unix.Stat_t
		if unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Size > 0 && st.Size <= maxRecordBytes {
			unix.Pwrite(fd, make([]byte, st.Size), 0)
			unix.Fsync(fd)
		}
		unix.Close(fd)
	}
	if err := unix.Unlink(path); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return nil
}

func (s *Store) recordPath(name string) string { return filepath.Join(s.dir, name+recordSuffix) }

// Fingerprint computes the stored-value fingerprint for display.
func (s *Store) Fingerprint(targetID, name string, value []byte) string {
	return Fingerprint(s.fpKey, targetID, name, value)
}

// Accept opens env, commits the value with its version, nonce, policy digest
// and fingerprint as one record, and returns the receipt. A replayed or older
// envelope is refused, so a relayed ciphertext cannot roll a rotated secret
// back. Any failure leaves the previous record exactly as it was.
func (s *Store) Accept(key *HostKey, env *Envelope, now time.Time) (*Receipt, error) {
	if env == nil || !namePattern.MatchString(env.Name) {
		return nil, ErrContext
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := s.scan(); err != nil {
		return nil, err
	}
	old, prev, err := s.openRecord(env.Name)
	if err != nil {
		return nil, err
	}
	defer closeRecord(old, prev)
	last := uint64(0)
	if prev != nil {
		if prev.TargetID != env.TargetID {
			return nil, ErrStore
		}
		last = prev.Version
	}
	opened, err := Open(key, env, last, now)
	if err != nil {
		return nil, err
	}
	defer opened.Wipe()
	if s.Validate != nil && !s.Validate(opened.Value) {
		return nil, ErrValue
	}
	fp := s.Fingerprint(env.TargetID, env.Name, opened.Value)
	rec := secretRecord{Format: recordFormat, TargetID: env.TargetID, Name: env.Name, Version: env.Version, Nonce: env.Nonce,
		PolicyDigest: env.PolicyDigest, Fingerprint: fp, UpdatedAt: now.UTC().Format(time.RFC3339), Value: opened.Value}
	if err := s.commit(env.Name, &rec); err != nil {
		return nil, err
	}
	// The previous value is unreachable now; overwrite its blocks too.
	s.zero(old)
	return opened.Receipt(fp), nil
}

// commit writes rec to a fresh temporary file, fsyncs it, renames it over the
// name's record and fsyncs the directory. Before the rename nothing a reader
// sees has changed; a failure removes the temporary file. The serialized
// record is wiped from memory afterwards.
func (s *Store) commit(name string, rec *secretRecord) error {
	raw, err := rec.encode()
	if err != nil {
		return err
	}
	defer clear(raw)
	if len(raw) > maxRecordBytes {
		return ErrStore
	}
	var nonce [8]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return ErrStore
	}
	fs := s.fs()
	tmp := filepath.Join(s.dir, pendingPrefix+hex.EncodeToString(nonce[:]))
	fd, err := fs.createTemp(tmp)
	if err != nil {
		return ErrStore
	}
	n, werr := fs.write(fd, raw)
	if werr == nil && n != len(raw) {
		werr = io.ErrShortWrite
	}
	if werr == nil {
		werr = fs.fsync(fd)
	}
	cerr := fs.close(fd)
	if werr != nil || cerr != nil {
		s.discard(tmp)
		return ErrStore
	}
	if err := fs.rename(tmp, s.recordPath(name)); err != nil {
		s.discard(tmp)
		return ErrStore
	}
	if err := fs.syncDir(s.dir); err != nil {
		// The rename happened; whether it survives a power loss is unknown.
		// Either record is whole, and the caller reports a failure.
		return ErrStore
	}
	return nil
}

// zero overwrites a replaced record's inode through the descriptor opened
// before the commit, so its value does not linger in freed blocks.
func (s *Store) zero(fd int) {
	if fd < 0 {
		return
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Size <= 0 || st.Size > maxRecordBytes {
		return
	}
	fs := s.fs()
	if _, err := fs.pwrite(fd, make([]byte, st.Size), 0); err == nil {
		fs.fsync(fd)
	}
}

// openRecord opens and parses name's record. fd is -1 and rec nil when the
// name has none; otherwise the caller runs closeRecord.
func (s *Store) openRecord(name string) (int, *secretRecord, error) {
	fd, err := unix.Open(s.recordPath(name), unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return -1, nil, nil
	}
	if err != nil {
		return -1, nil, ErrStore
	}
	raw, err := readFD(fd, maxRecordBytes)
	if err != nil {
		unix.Close(fd)
		return -1, nil, err
	}
	defer clear(raw)
	rec, err := s.parseRecord(name, raw)
	if err != nil {
		unix.Close(fd)
		return -1, nil, err
	}
	return fd, rec, nil
}

func closeRecord(fd int, rec *secretRecord) {
	rec.wipe()
	if fd >= 0 {
		unix.Close(fd)
	}
}

// parseRecord strictly decodes a record and checks it is whole: its own
// name, a plausible version, nonce and policy digest, exactly the value
// length its metadata states, and for a held value a fingerprint that this
// store's key recomputes from the value. The value is copied out; the caller
// wipes raw.
func (s *Store) parseRecord(name string, raw []byte) (*secretRecord, error) {
	nl := bytes.IndexByte(raw, '\n')
	if nl < 0 {
		return nil, ErrStore
	}
	var r secretRecord
	if strictDecode(raw[:nl], &r) != nil || r.ValueBytes != len(raw)-nl-1 {
		return nil, ErrStore
	}
	ok := r.Format == recordFormat && r.Name == name && targetPattern.MatchString(r.TargetID) && r.Version > 0 &&
		noncePattern.MatchString(r.Nonce) && keyIDPattern.MatchString(r.PolicyDigest)
	if r.Deleted {
		ok = ok && r.ValueBytes == 0 && r.Fingerprint == ""
	} else {
		ok = ok && r.ValueBytes > 0 && r.ValueBytes <= MaxValueBytes && validFingerprint(r.Fingerprint) &&
			s.Fingerprint(r.TargetID, r.Name, raw[nl+1:]) == r.Fingerprint
	}
	if !ok {
		return nil, ErrStore
	}
	if !r.Deleted {
		r.Value = append(make([]byte, 0, r.ValueBytes), raw[nl+1:]...)
	}
	return &r, nil
}

// lock takes the store's exclusive lock; the caller runs unlock.
func (s *Store) lock() (func(), error) {
	if err := checkDir(s.dir); err != nil {
		return nil, err
	}
	fd, err := unix.Open(filepath.Join(s.dir, ".lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, ErrStore
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		unix.Close(fd)
		return nil, ErrStore
	}
	return func() { unix.Flock(fd, unix.LOCK_UN); unix.Close(fd) }, nil
}

// StoredSecret is what the store records of a held value: never the value.
type StoredSecret struct {
	Version      uint64
	Fingerprint  string
	PolicyDigest string
}

// HeldSecret is a held value with its record. The caller runs Wipe.
type HeldSecret struct {
	StoredSecret
	Value []byte
}

// Wipe zeroes the value.
func (h *HeldSecret) Wipe() {
	if h != nil {
		clear(h.Value)
	}
}

// load reads name's record under the lock. A tombstone or no record is
// (nil, nil).
func (s *Store) load(name string) (*secretRecord, error) {
	if !namePattern.MatchString(name) {
		return nil, ErrContext
	}
	if s.fpKey == nil {
		return nil, ErrStore
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	fd, rec, err := s.openRecord(name)
	if err != nil || rec == nil {
		return nil, err
	}
	unix.Close(fd)
	if rec.Deleted {
		return nil, nil
	}
	return rec, nil
}

// Stored reports the accepted version, fingerprint and policy digest of name.
// ok is false when no value is held (never set, or deleted). The record is
// verified whole (its value reproduces its fingerprint) and the value is
// wiped before Stored returns.
func (s *Store) Stored(name string) (StoredSecret, bool, error) {
	rec, err := s.load(name)
	if err != nil || rec == nil {
		return StoredSecret{}, false, err
	}
	rec.wipe()
	return StoredSecret{Version: rec.Version, Fingerprint: rec.Fingerprint, PolicyDigest: rec.PolicyDigest}, true, nil
}

// Load returns name's value with its record, read from the one committed
// record file and verified whole. ok is false when no value is held.
func (s *Store) Load(name string) (*HeldSecret, bool, error) {
	rec, err := s.load(name)
	if err != nil || rec == nil {
		return nil, false, err
	}
	return &HeldSecret{StoredSecret: StoredSecret{Version: rec.Version, Fingerprint: rec.Fingerprint, PolicyDigest: rec.PolicyDigest},
		Value: rec.Value}, true, nil
}

// Delete commits a tombstone for name that keeps the last accepted version,
// then overwrites the replaced record with zeros. Without the tombstone a
// relayed copy of an earlier envelope (still inside MaxAge) would set the
// deleted value again. Deleting a name never set, or already deleted,
// succeeds.
func (s *Store) Delete(name string, now time.Time) error {
	if !namePattern.MatchString(name) {
		return ErrContext
	}
	unlock, err := s.lock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := s.scan(); err != nil {
		return err
	}
	fd, rec, err := s.openRecord(name)
	if err != nil {
		return err
	}
	defer closeRecord(fd, rec)
	if rec == nil || rec.Deleted {
		return nil
	}
	tomb := secretRecord{Format: recordFormat, TargetID: rec.TargetID, Name: rec.Name, Version: rec.Version, Nonce: rec.Nonce,
		PolicyDigest: rec.PolicyDigest, UpdatedAt: now.UTC().Format(time.RFC3339), Deleted: true}
	if err := s.commit(name, &tomb); err != nil {
		return err
	}
	s.zero(fd)
	return nil
}

// readFD reads a regular, singly linked 0600 file owned by this user.
func readFD(fd int, max int) ([]byte, error) {
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != os.Geteuid() ||
		st.Mode&0o077 != 0 || st.Size > int64(max) {
		return nil, ErrStore
	}
	buf := make([]byte, st.Size)
	n := 0
	for n < len(buf) {
		m, err := unix.Pread(fd, buf[n:], int64(n))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || m == 0 {
			clear(buf)
			return nil, ErrStore
		}
		n += m
	}
	return buf, nil
}

// readPrivate reads a regular, unlinked-elsewhere 0600 file owned by this user.
func readPrivate(path string, max int) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, ErrStore
	}
	defer unix.Close(fd)
	return readFD(fd, max)
}

// writePrivate writes data to path as a 0600 file through a fresh temporary
// file, fsync and rename, then fsyncs the directory. With exclusive set it
// refuses to replace an existing file. It is used for the fingerprint key.
func writePrivate(path string, data []byte, exclusive bool) error {
	dir := filepath.Dir(path)
	var nonce [8]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return ErrStore
	}
	tmp := filepath.Join(dir, ".tmp-"+hex.EncodeToString(nonce[:]))
	fd, err := unix.Open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return ErrStore
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		os.Remove(tmp)
		return ErrStore
	}
	if exclusive {
		err = unix.Renameat2(unix.AT_FDCWD, tmp, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE)
	} else {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return ErrStore
	}
	return osOps{}.syncDir(dir)
}

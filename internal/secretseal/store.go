// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package secretseal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// ErrStore never names a value or a path's contents.
var ErrStore = errors.New("secretseal: secret store custody is invalid")

const fingerprintKeyFile = ".fingerprint-key"

// Store is the host's secret directory: one root-owned 0600 file per secret
// name plus a metadata file holding the accepted version and fingerprint. The
// directory must be owned by the host agent's user, mode 0700, and outside
// every sandbox mount. Only the broker container for a launch receives a
// read-only bind of one secret file.
type Store struct {
	dir   string
	fpKey []byte
	// Validate, when set, must accept a value before it is stored (for
	// example broker.ValidSecret, so a value the broker cannot inject is
	// refused at secret-put time rather than at launch).
	Validate func([]byte) bool
}

type secretMeta struct {
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
	// Deleted marks a tombstone: the value is gone, the version stays, so an
	// earlier envelope relayed again is still refused as a replay.
	Deleted bool `json:"deleted,omitempty"`
}

func checkDir(dir string) error {
	var st unix.Stat_t
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || unix.Lstat(dir, &st) != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != os.Geteuid() || st.Mode&0o077 != 0 {
		return ErrStore
	}
	return nil
}

// OpenStore opens dir, creating its random fingerprint key on first use.
func OpenStore(dir string) (*Store, error) {
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	s := &Store{dir: dir}
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

// SecretPath is the file a broker configuration references for name.
func (s *Store) SecretPath(name string) (string, error) {
	if !namePattern.MatchString(name) {
		return "", ErrContext
	}
	return filepath.Join(s.dir, name), nil
}

// Fingerprint computes the stored-value fingerprint for display.
func (s *Store) Fingerprint(targetID, name string, value []byte) string {
	return Fingerprint(s.fpKey, targetID, name, value)
}

// Accept opens env, replaces the secret file atomically, records the version
// and returns the receipt. A replayed or older envelope is refused, so a
// relayed ciphertext cannot roll a rotated secret back.
func (s *Store) Accept(key *HostKey, env *Envelope, now time.Time) (*Receipt, error) {
	if err := checkDir(s.dir); err != nil {
		return nil, err
	}
	if env == nil || !namePattern.MatchString(env.Name) {
		return nil, ErrContext
	}
	lock, err := unix.Open(filepath.Join(s.dir, ".lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, ErrStore
	}
	defer unix.Close(lock)
	if err := unix.Flock(lock, unix.LOCK_EX); err != nil {
		return nil, ErrStore
	}
	defer unix.Flock(lock, unix.LOCK_UN)
	metaPath := filepath.Join(s.dir, env.Name+".meta.json")
	last := uint64(0)
	if raw, err := readPrivate(metaPath, 4096); err == nil {
		var m secretMeta
		if strictDecode(raw, &m) != nil || m.Name != env.Name || m.TargetID != env.TargetID {
			return nil, ErrStore
		}
		last = m.Version
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, ErrStore
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
	if err := writePrivate(filepath.Join(s.dir, env.Name), opened.Value, false); err != nil {
		return nil, err
	}
	meta, _ := json.Marshal(secretMeta{Format: EnvelopeFormat + ".meta", TargetID: env.TargetID, Name: env.Name, Version: env.Version,
		Nonce: env.Nonce, PolicyDigest: env.PolicyDigest, Fingerprint: fp, UpdatedAt: now.UTC().Format(time.RFC3339)})
	if err := writePrivate(metaPath, meta, false); err != nil {
		return nil, err
	}
	return opened.Receipt(fp), nil
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

func (s *Store) meta(name string) (*secretMeta, error) {
	raw, err := readPrivate(filepath.Join(s.dir, name+".meta.json"), 4096)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrStore
	}
	var m secretMeta
	if strictDecode(raw, &m) != nil || m.Name != name {
		return nil, ErrStore
	}
	return &m, nil
}

// StoredSecret is what the store records of a held value: never the value.
type StoredSecret struct {
	Version      uint64
	Fingerprint  string
	PolicyDigest string
}

// Stored reports the accepted version, fingerprint and policy digest of name.
// ok is false when no value is held (never set, or deleted). It never reads
// the value. A value stored under an earlier format without a policy digest
// is refused (ErrStore): it must be sealed again.
func (s *Store) Stored(name string) (StoredSecret, bool, error) {
	if !namePattern.MatchString(name) {
		return StoredSecret{}, false, ErrContext
	}
	unlock, err := s.lock()
	if err != nil {
		return StoredSecret{}, false, err
	}
	defer unlock()
	m, err := s.meta(name)
	if err != nil || m == nil || m.Deleted {
		return StoredSecret{}, false, err
	}
	var st unix.Stat_t
	if unix.Lstat(filepath.Join(s.dir, name), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o077 != 0 ||
		int(st.Uid) != os.Geteuid() || st.Nlink != 1 || !keyIDPattern.MatchString(m.PolicyDigest) {
		return StoredSecret{}, false, ErrStore
	}
	return StoredSecret{Version: m.Version, Fingerprint: m.Fingerprint, PolicyDigest: m.PolicyDigest}, true, nil
}

// Delete overwrites the value of name with zeros, removes it, and keeps a
// tombstone with the last accepted version under the store lock. Without the
// tombstone a relayed copy of an earlier envelope (still inside MaxAge) would
// set the deleted value again. Deleting a name never set, or already deleted,
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
	m, err := s.meta(name)
	if err != nil {
		return err
	}
	path := filepath.Join(s.dir, name)
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
	case err != nil:
		return ErrStore
	default:
		var st unix.Stat_t
		if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Geteuid() || st.Size > MaxValueBytes+1 {
			unix.Close(fd)
			return ErrStore
		}
		zeros := make([]byte, st.Size)
		_, werr := unix.Pwrite(fd, zeros, 0)
		serr := unix.Fsync(fd)
		unix.Close(fd)
		if werr != nil || serr != nil || unix.Unlink(path) != nil {
			return ErrStore
		}
	}
	if m == nil {
		return nil
	}
	m.Deleted, m.Fingerprint, m.UpdatedAt = true, "", now.UTC().Format(time.RFC3339)
	raw, _ := json.Marshal(m)
	if err := writePrivate(filepath.Join(s.dir, name+".meta.json"), raw, false); err != nil {
		return err
	}
	if d, err := os.Open(s.dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
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
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 || int(st.Uid) != os.Geteuid() ||
		st.Mode&0o077 != 0 || st.Size > int64(max) {
		return nil, ErrStore
	}
	buf := make([]byte, st.Size)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, ErrStore
	}
	return buf, nil
}

// writePrivate writes data to path as a 0600 file through a fresh temporary
// file, fsync and rename, then fsyncs the directory. With exclusive set it
// refuses to replace an existing file.
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
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

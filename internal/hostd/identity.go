// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

const (
	signingKeyName    = "host.key"
	encryptionKeyName = "box.key"
	identityName      = "identity.json"
	sequenceName      = "sequence"
)

// Keys are the host's long-lived private keys. They never leave the state
// directory and are never logged.
type Keys struct {
	Signing    ed25519.PrivateKey
	Encryption *ecdh.PrivateKey
}

// loadOrCreateKeys reads both keys, or creates them once (mode 0600).
func loadOrCreateKeys(stateDir string, random io.Reader) (Keys, error) {
	var keys Keys
	signing, err := loadOrCreateSeed(filepath.Join(stateDir, signingKeyName), random)
	if err != nil {
		return keys, err
	}
	keys.Signing = ed25519.NewKeyFromSeed(signing)
	box, err := loadOrCreateSeed(filepath.Join(stateDir, encryptionKeyName), random)
	if err != nil {
		return keys, err
	}
	keys.Encryption, err = ecdh.X25519().NewPrivateKey(box)
	return keys, err
}

func loadOrCreateSeed(path string, random io.Reader) ([]byte, error) {
	raw, err := readPrivateFile(path, 256)
	if err == nil {
		seed, decodeErr := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
		if decodeErr != nil || len(seed) != 32 {
			return nil, fmt.Errorf("hostd: %s is damaged; refusing to replace an existing key", path)
		}
		return seed, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	seed := make([]byte, 32)
	if _, err = io.ReadFull(random, seed); err != nil {
		return nil, err
	}
	if err = createFileExclusive(path, []byte(base64.RawURLEncoding.EncodeToString(seed)+"\n")); err != nil {
		return nil, err
	}
	return seed, nil
}

// Identity is what enrollment bound: the target id and the service job key.
type Identity struct {
	ServiceURL   string `json:"service_url"`
	TargetID     string `json:"target_id"`
	TargetName   string `json:"target_name"`
	HostKeyID    string `json:"host_key_id"`
	JobKey       string `json:"job_key"`
	JobKeyID     string `json:"job_key_id"`
	PollSeconds  int    `json:"poll_interval_seconds"`
	EnrolledAtMS int64  `json:"enrolled_at_ms"`
}

func (i Identity) jobKey() (ed25519.PublicKey, error) {
	raw, err := hostproto.DecodeKey(i.JobKey)
	if err != nil || hostproto.KeyID(raw) != i.JobKeyID {
		return nil, errors.New("hostd: the pinned job key is damaged")
	}
	return ed25519.PublicKey(raw), nil
}

func loadIdentity(stateDir string) (Identity, error) {
	var id Identity
	raw, err := readPrivateFile(filepath.Join(stateDir, identityName), 16<<10)
	if err != nil {
		return id, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&id); err != nil {
		return id, fmt.Errorf("hostd: identity: %w", err)
	}
	if _, err = id.jobKey(); err != nil {
		return id, err
	}
	return id, nil
}

// HostKey is what an administrator compares on the host console: the key id
// the service shows and approves (ed25519:...), and the SHA-256 fingerprint
// of the whole key that sealing clients pin (SHA256:...).
type HostKey struct {
	ID          string `json:"host_key_id"`
	Fingerprint string `json:"host_key_fingerprint"`
}

// readHostKey reads the enrolled signing key without creating one.
func readHostKey(stateDir string) (HostKey, error) {
	raw, err := readPrivateFile(filepath.Join(stateDir, signingKeyName), 256)
	if err != nil {
		return HostKey{}, err
	}
	seed, err := base64.RawURLEncoding.Strict().DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != 32 {
		return HostKey{}, errors.New("hostd: the host key file is damaged")
	}
	public := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	return HostKey{ID: hostproto.KeyID(public), Fingerprint: secretseal.HostKeyFingerprint(public)}, nil
}

// ApprovalLines are the lines install and status print for the operator.
func ApprovalLines(id Identity, key HostKey) []string {
	name := id.TargetName
	if name == "" {
		name = id.TargetID
	}
	return []string{
		"host key id (compare and approve this): " + key.ID,
		"host key fingerprint (SHA-256 of the key; sealing clients pin it): " + key.Fingerprint,
		"An administrator compares the id with the one the service shows for target " + name + ", then approves it:",
		"  agentgate target approve-key " + name + " --host-key-id " + key.ID,
	}
}

func saveIdentity(stateDir string, id Identity) error {
	raw, err := json.MarshalIndent(id, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(stateDir, identityName), append(raw, '\n'), 0o600)
}

// Sequence is the strictly increasing counter shared by every signed request.
// The next value is persisted before the request leaves the host, so a crash
// can leave a gap (accepted) but never a repeat.
type Sequence struct {
	mu   sync.Mutex
	path string
}

func newSequence(stateDir string) *Sequence {
	return &Sequence{path: filepath.Join(stateDir, sequenceName)}
}

func (s *Sequence) current() (uint64, error) {
	raw, err := readPrivateFile(s.path, 64)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, errors.New("hostd: the sequence file is damaged; refusing to guess")
	}
	return value, nil
}

func (s *Sequence) store(value uint64) error {
	return writeFileAtomic(s.path, []byte(strconv.FormatUint(value, 10)+"\n"), 0o600)
}

// Next reserves and durably records the next sequence.
func (s *Sequence) Next() (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.current()
	if err != nil {
		return 0, err
	}
	if value >= 1<<53 {
		return 0, errors.New("hostd: the sequence is exhausted")
	}
	value++
	return value, s.store(value)
}

// AdvancePast moves the counter forward past a value the service reports it
// accepted. It never moves backwards.
func (s *Sequence) AdvancePast(accepted uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, err := s.current()
	if err != nil || accepted <= value || accepted >= 1<<53 {
		return err
	}
	return s.store(accepted)
}

func newNonce(random io.Reader) (string, error) {
	raw := make([]byte, 18)
	if _, err := io.ReadFull(random, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

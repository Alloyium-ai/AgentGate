// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package secretseal

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// KnownTargetsFormat identifies the client's pin file.
const KnownTargetsFormat = "agentgate.known-targets.v1"

// PinStatus is the result of checking a host key against the client's pins.
type PinStatus int

const (
	PinUnknown PinStatus = iota
	PinMatch
	PinMismatch
)

// KnownTargets is the client-side pin file: target id to host key
// fingerprint, mode 0600 in the user's configuration directory. It is the
// out-of-band anchor that keeps the service from substituting a host key.
type KnownTargets struct {
	path    string
	entries map[string]string
}

type knownFile struct {
	Format  string       `json:"format"`
	Targets []knownEntry `json:"targets"`
}

type knownEntry struct {
	TargetID string `json:"target_id"`
	HostKey  string `json:"host_key"`
}

// LoadKnownTargets reads path; a missing file is an empty set.
func LoadKnownTargets(path string) (*KnownTargets, error) {
	k := &KnownTargets{path: path, entries: map[string]string{}}
	raw, err := readPrivate(path, 1<<20)
	if errors.Is(err, os.ErrNotExist) {
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	var f knownFile
	if strictDecode(raw, &f) != nil || f.Format != KnownTargetsFormat {
		return nil, ErrStore
	}
	for _, e := range f.Targets {
		if !targetPattern.MatchString(e.TargetID) || k.entries[e.TargetID] != "" {
			return nil, ErrStore
		}
		k.entries[e.TargetID] = e.HostKey
	}
	return k, nil
}

// Check compares a host key fingerprint with the pin for targetID.
func (k *KnownTargets) Check(targetID, fingerprint string) PinStatus {
	pinned, ok := k.entries[targetID]
	switch {
	case !ok:
		return PinUnknown
	case pinned == fingerprint:
		return PinMatch
	}
	return PinMismatch
}

// Pin records a fingerprint for a target that has none. It never replaces a
// different existing pin: re-enrolling a target requires removing the old
// pin deliberately.
func (k *KnownTargets) Pin(targetID, fingerprint string) error {
	if !targetPattern.MatchString(targetID) || len(fingerprint) < 8 {
		return ErrContext
	}
	if old, ok := k.entries[targetID]; ok {
		if old == fingerprint {
			return nil
		}
		return ErrFingerprint
	}
	k.entries[targetID] = fingerprint
	f := knownFile{Format: KnownTargetsFormat}
	for id, fp := range k.entries {
		f.Targets = append(f.Targets, knownEntry{TargetID: id, HostKey: fp})
	}
	sort.Slice(f.Targets, func(i, j int) bool { return f.Targets[i].TargetID < f.Targets[j].TargetID })
	raw, _ := json.MarshalIndent(f, "", "  ")
	if err := os.MkdirAll(filepath.Dir(k.path), 0o700); err != nil {
		return ErrStore
	}
	return writePrivate(k.path, raw, false)
}

// SealForTarget is the client's whole path for `agentgate secret set`: check
// the host key against the pin (pinning it first when trustOnFirstUse is set
// and none exists), verify the signed seal key, and seal value. The caller
// shows the returned status and fingerprint to the operator, keeps the
// Sealed value, and verifies the host's receipt with Sealed.VerifyReceipt.
func SealForTarget(known *KnownTargets, trustOnFirstUse bool, rec *SignedKeyRecord, hostPub ed25519.PublicKey,
	targetID, name string, value []byte, now time.Time) (*Sealed, PinStatus, error) {
	if known == nil || len(hostPub) != ed25519.PublicKeySize {
		return nil, PinUnknown, ErrFingerprint
	}
	fp := HostKeyFingerprint(hostPub)
	status := known.Check(targetID, fp)
	switch status {
	case PinMismatch:
		return nil, status, ErrFingerprint
	case PinUnknown:
		if !trustOnFirstUse {
			return nil, status, ErrFingerprint
		}
		// Verify before pinning so a malformed record never creates a pin.
		if _, err := VerifyKeyRecord(rec, hostPub, fp, targetID, now); err != nil {
			return nil, status, err
		}
		if err := known.Pin(targetID, fp); err != nil {
			return nil, status, err
		}
	}
	pub, err := VerifyKeyRecord(rec, hostPub, fp, targetID, now)
	if err != nil {
		return nil, status, err
	}
	sealed, err := SealAt(pub, targetID, name, value, now)
	return sealed, status, err
}

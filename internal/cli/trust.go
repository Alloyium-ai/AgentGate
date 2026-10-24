// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"sort"
)

// KnownTargetsFormat identifies the client-side host key pin file.
const KnownTargetsFormat = "agentgate.cli.known-targets.v1"

const knownTargetsFile = "known-targets.json"

var hostKeyIDPattern = regexp.MustCompile(`^ed25519:[a-f0-9]{32}$`)

// KnownTarget pins the host key an administrator approved for one target of
// one service. It is the client's out-of-band anchor: secret set refuses a
// target whose service-reported key differs from the pin. HostKeyID is the
// hostproto key id the administrator compared with the host console;
// HostKeyFingerprint (secretseal.HostKeyFingerprint, SHA256:...) is added
// once a verified host public key was seen. EncryptionKey is the X25519 key
// the service reported at approval time; it is used only with secret set
// --allow-unsigned-key.
type KnownTarget struct {
	Server             string `json:"server"`
	TargetID           string `json:"target_id"`
	TargetName         string `json:"target_name"`
	HostKeyID          string `json:"host_key_id"`
	HostKeyFingerprint string `json:"host_key_fingerprint,omitempty"`
	EncryptionKey      string `json:"encryption_key,omitempty"`
	PinnedAt           string `json:"pinned_at"`
	Source             string `json:"source"`
}

type knownTargets struct {
	Format  string        `json:"format"`
	Targets []KnownTarget `json:"targets"`
}

func (s store) loadTrust() (*knownTargets, error) {
	k := &knownTargets{Format: KnownTargetsFormat, Targets: []KnownTarget{}}
	raw, err := s.readPrivate(knownTargetsFile, maxConfigBytes)
	if errors.Is(err, os.ErrNotExist) {
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(k); err != nil || k.Format != KnownTargetsFormat {
		return nil, trustError("trust_file_invalid", "The host key pin file "+s.dir+"/"+knownTargetsFile+" is damaged.", "Restore it from a backup; do not delete it unless you will compare every host key again.")
	}
	seen := map[string]bool{}
	for _, t := range k.Targets {
		key := t.Server + "\x00" + t.TargetID
		if seen[key] || !hostKeyIDPattern.MatchString(t.HostKeyID) {
			return nil, trustError("trust_file_invalid", "The host key pin file "+s.dir+"/"+knownTargetsFile+" is damaged.", "Restore it from a backup.")
		}
		seen[key] = true
	}
	return k, nil
}

func (k *knownTargets) find(server, targetID string) *KnownTarget {
	for i := range k.Targets {
		if k.Targets[i].Server == server && k.Targets[i].TargetID == targetID {
			return &k.Targets[i]
		}
	}
	return nil
}

// pin records entry. A different existing pin is replaced only when replace
// is set (an administrator approved a new key); the previous pin is returned.
func (s store) pin(entry KnownTarget, replace bool) (*KnownTarget, error) {
	if !hostKeyIDPattern.MatchString(entry.HostKeyID) {
		return nil, usageError("a host key fingerprint is ed25519: and 32 lowercase hex characters")
	}
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	k, err := s.loadTrust()
	if err != nil {
		return nil, err
	}
	var previous *KnownTarget
	if old := k.find(entry.Server, entry.TargetID); old != nil {
		if subtle.ConstantTimeCompare([]byte(old.HostKeyID), []byte(entry.HostKeyID)) == 1 {
			merged := *old
			if entry.HostKeyFingerprint != "" {
				if merged.HostKeyFingerprint != "" && merged.HostKeyFingerprint != entry.HostKeyFingerprint {
					return nil, trustError("host_key_pin_mismatch", "Target "+entry.TargetName+" is pinned to host key fingerprint "+merged.HostKeyFingerprint+", not "+entry.HostKeyFingerprint+".", "Do not trust this host until you know why.")
				}
				merged.HostKeyFingerprint = entry.HostKeyFingerprint
			}
			if entry.EncryptionKey != "" && (merged.EncryptionKey == "" || replace) {
				merged.EncryptionKey = entry.EncryptionKey
			}
			if merged == *old {
				return nil, nil
			}
			*old = merged
		} else {
			if !replace {
				return nil, trustError("host_key_pin_mismatch", "Target "+entry.TargetName+" is pinned to host key "+old.HostKeyID+", not "+entry.HostKeyID+".",
					"If the host was re-enrolled on purpose, approve the new key with agentgate target approve-key NAME (which replaces the pin); otherwise do not trust this host.")
			}
			copied := *old
			previous = &copied
			*old = entry
		}
	} else {
		k.Targets = append(k.Targets, entry)
	}
	sort.Slice(k.Targets, func(i, j int) bool {
		if k.Targets[i].Server != k.Targets[j].Server {
			return k.Targets[i].Server < k.Targets[j].Server
		}
		return k.Targets[i].TargetID < k.Targets[j].TargetID
	})
	raw, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return nil, err
	}
	return previous, s.writePrivate(knownTargetsFile, append(raw, '\n'))
}

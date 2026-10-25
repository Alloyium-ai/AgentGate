// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package localconfig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

type authorityPin struct {
	Schema   string `json:"schema"`
	Instance string `json:"instance"`
	Public   string `json:"public_key"`
}

func (s *Store) PinAuthority(public string) error {
	key, err := base64.RawURLEncoding.DecodeString(public)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != public {
		return errors.New("invalid application authority")
	}
	return privateJSON(filepath.Join(filepath.Dir(s.anchorPath), "authority.json"), authorityPin{"agentgate.community.authority.v1", s.Trust.Instance, public})
}
func (s *Store) VerifyAuthority(public string) error {
	data, err := privateRead(filepath.Join(filepath.Dir(s.anchorPath), "authority.json"))
	if err != nil {
		return err
	}
	var pin authorityPin
	if json.Unmarshal(data, &pin) != nil || pin.Schema != "agentgate.community.authority.v1" || pin.Instance != s.Trust.Instance || pin.Public != public {
		return errors.New("application authority differs from independent trust")
	}
	return nil
}

type jobKeyPin struct {
	Schema   string `json:"schema"`
	Instance string `json:"instance"`
	Public   string `json:"public_key"`
}

func (s *Store) jobKeyPath() string { return filepath.Join(filepath.Dir(s.anchorPath), "jobkey.json") }

// PinJobKey records the host job signing key in the independent trust
// directory. With replace, an existing pin is replaced atomically (key
// rotation); without it, an existing pin is an error.
func (s *Store) PinJobKey(public string, replace bool) error {
	key, err := base64.RawURLEncoding.DecodeString(public)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != public {
		return errors.New("invalid job key")
	}
	pin := jobKeyPin{"agentgate.community.jobkey.v1", s.Trust.Instance, public}
	if !replace {
		return privateJSON(s.jobKeyPath(), pin)
	}
	staged := s.jobKeyPath() + ".new"
	os.Remove(staged)
	if err = privateJSON(staged, pin); err != nil {
		return err
	}
	return os.Rename(staged, s.jobKeyPath())
}

// VerifyJobKey checks the job key against its pin. It reports os.ErrNotExist
// when no pin exists yet (a deployment created before job keys).
func (s *Store) VerifyJobKey(public string) error {
	if _, err := os.Lstat(s.jobKeyPath()); os.IsNotExist(err) {
		return os.ErrNotExist
	}
	data, err := privateRead(s.jobKeyPath())
	if err != nil {
		return err
	}
	var pin jobKeyPin
	if json.Unmarshal(data, &pin) != nil || pin.Schema != "agentgate.community.jobkey.v1" || pin.Instance != s.Trust.Instance || pin.Public != public {
		return errors.New("job key differs from independent trust")
	}
	return nil
}

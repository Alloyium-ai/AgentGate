// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package localconfig

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
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

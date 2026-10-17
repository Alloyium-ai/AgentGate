// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package localconfig

import (
	"errors"
	"os"
	"path/filepath"
)

// Snapshot retains the signer. The independent trust and anchor stay in separate custody.
func (s *Store) Snapshot(dir string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !filepath.IsAbs(dir) {
		return errors.New("snapshot requires an absolute private directory")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	if _, err := s.DB.Exec("VACUUM INTO ?", filepath.Join(dir, "config.db")); err != nil {
		return err
	}
	if err := os.Chmod(filepath.Join(dir, "config.db"), 0600); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(dir, "config.key"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(s.key); err != nil {
		return err
	}
	return f.Sync()
}

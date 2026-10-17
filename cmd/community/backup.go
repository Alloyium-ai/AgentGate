// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"alloyium.local/kernel-poc/internal/control"
	"alloyium.local/kernel-poc/internal/localconfig"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type backupManifest struct {
	Schema   string            `json:"schema"`
	Instance string            `json:"instance"`
	Revision int64             `json:"config_revision"`
	Files    map[string]string `json:"sha256"`
}

func fileHash(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

var snapshotFiles = []string{"data/control.db", "data/authority.key", "data/manifest.json", "config/config.db", "config/config.key"}

func backup(config *localconfig.Store, store *control.Store, record localconfig.Record, dest string) error {
	if !filepath.IsAbs(dest) {
		return errors.New("backup requires an absolute private directory")
	}
	if err := os.Mkdir(dest, 0700); err != nil {
		return err
	}
	if err := config.Snapshot(filepath.Join(dest, "config")); err != nil {
		return err
	}
	if err := store.Backup(filepath.Join(dest, "data")); err != nil {
		return err
	}
	m := backupManifest{"agentgate.community.backup.v1", record.Instance, record.Revision, map[string]string{}}
	for _, path := range snapshotFiles {
		value, err := fileHash(filepath.Join(dest, path))
		if err != nil {
			return err
		}
		m.Files[path] = value
	}
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dest, "manifest.json"), data, 0600); err != nil {
		return err
	}
	dir, err := os.Open(dest)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func copyPrivate(source, dest string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err = io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
func restore(source, dest, trust string) error {
	if !filepath.IsAbs(source) || !filepath.IsAbs(dest) {
		return errors.New("restore requires absolute paths")
	}
	var m backupManifest
	if err := jsonFile(filepath.Join(source, "manifest.json"), &m); err != nil {
		return err
	}
	if m.Schema != "agentgate.community.backup.v1" || len(m.Files) != len(snapshotFiles) {
		return errors.New("unsupported Community backup")
	}
	for _, path := range snapshotFiles {
		value, err := fileHash(filepath.Join(source, path))
		if err != nil || value != m.Files[path] {
			return errors.New("backup file differs from its manifest")
		}
	}
	if err := os.Mkdir(dest, 0700); err != nil {
		return errors.New("restore requires a fresh destination")
	}
	configDir := filepath.Join(dest, "config")
	if err := os.Mkdir(configDir, 0700); err != nil {
		return err
	}
	for _, name := range []string{"config.db", "config.key"} {
		if err := copyPrivate(filepath.Join(source, "config", name), filepath.Join(configDir, name)); err != nil {
			return err
		}
	}
	config, err := localconfig.Open(configDir, trust)
	if err != nil {
		return err
	}
	defer config.DB.Close()
	record, err := config.Read()
	if err != nil {
		return err
	}
	if record.Instance != m.Instance || record.Revision != m.Revision {
		return errors.New("restored configuration differs from the independent trust")
	}
	var application control.BackupManifest
	if err = jsonFile(filepath.Join(source, "data", "manifest.json"), &application); err != nil {
		return err
	}
	if err = config.VerifyAuthority(application.Authority); err != nil {
		return err
	}
	return control.RestoreNew(filepath.Join(source, "data"), filepath.Join(dest, "data"))
}

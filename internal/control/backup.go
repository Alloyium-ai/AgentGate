// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type BackupManifest struct {
	Version     string `json:"version"`
	DatabaseSHA string `json:"database_sha256"`
	Authority   string `json:"authority"`
	Created     string `json:"created_at"`
	KeySHA      string `json:"authority_key_sha256,omitempty"`
	JobKeySHA   string `json:"job_key_sha256,omitempty"`
}

func (s *Store) Backup(dir string) error {
	key, err := verifiedAuthority(s.Authority)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(dir) {
		return errors.New("backup requires an absolute private directory")
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return err
	}
	op := Operation{Actor: Actor{Subject: "deployment-administrator", Kind: "system", Scopes: []string{"backup:write"}}, Action: "backup.created", Resource: "database", Reason: "Create a consistent database and signing-key snapshot", RequestID: newID()}
	if _, err := s.Mutation(op, "backup:write", false, func(*sql.Tx, *Operation) (any, error) {
		return map[string]string{"snapshot": "SQLite VACUUM INTO"}, nil
	}); err != nil {
		return err
	}
	if _, err := s.DB.Exec("VACUUM INTO ?", filepath.Join(dir, "control.db")); err != nil {
		return err
	}
	databaseSHA, err := fileDigest(filepath.Join(dir, "control.db"))
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "authority.key"), s.Authority, 0600); err != nil {
		return err
	}
	manifest := BackupManifest{Version: "control-backup-v2", DatabaseSHA: databaseSHA, Authority: EncodePublic(key.Public().(ed25519.PublicKey)), Created: stamp(), KeySHA: digest(key)}
	if len(s.JobKey) == ed25519.PrivateKeySize {
		if err = os.WriteFile(filepath.Join(dir, JobKeyFile), s.JobKey, 0600); err != nil {
			return err
		}
		manifest.JobKeySHA = digest(s.JobKey)
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600)
}
func RestoreNew(backup, dest string) error {
	if !filepath.IsAbs(dest) || !filepath.IsAbs(backup) {
		return errors.New("restore requires absolute private directories")
	}
	data, err := os.ReadFile(filepath.Join(backup, "manifest.json"))
	if err != nil {
		return err
	}
	var m BackupManifest
	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}
	if m.Version != "control-backup-v1" && m.Version != "control-backup-v2" {
		return errors.New("unsupported backup format")
	}
	databaseSHA, err := fileDigest(filepath.Join(backup, "control.db"))
	if err != nil {
		return err
	}
	key, err := os.ReadFile(filepath.Join(backup, "authority.key"))
	if err != nil {
		return err
	}
	authority, err := verifiedAuthority(key)
	if err != nil {
		return err
	}
	if databaseSHA != m.DatabaseSHA || EncodePublic(authority.Public().(ed25519.PublicKey)) != m.Authority ||
		(m.Version == "control-backup-v2" && m.KeySHA == "") || (m.KeySHA != "" && digest(key) != m.KeySHA) {
		return errors.New("backup content or authority binding differs")
	}
	if err = os.Mkdir(dest, 0700); err != nil {
		return errors.New("restore requires a fresh destination; preserve the existing volume")
	}
	if err = copyDatabase(filepath.Join(backup, "control.db"), filepath.Join(dest, "control.db")); err != nil {
		return err
	}
	copied, err := fileDigest(filepath.Join(dest, "control.db"))
	if err != nil || copied != m.DatabaseSHA {
		return errors.New("restored database differs from the manifest")
	}
	if err = os.WriteFile(filepath.Join(dest, "authority.key"), key, 0600); err != nil {
		return err
	}
	// A backup without a job key restores with a fresh one; every target then
	// needs re-enrollment (see loadJobKey).
	if m.JobKeySHA != "" {
		jobKey, err := os.ReadFile(filepath.Join(backup, JobKeyFile))
		if err != nil {
			return err
		}
		if _, err = verifiedAuthority(jobKey); err != nil || digest(jobKey) != m.JobKeySHA {
			return errors.New("backup job key differs from the manifest")
		}
		if err = writePrivateKey(filepath.Join(dest, JobKeyFile), jobKey); err != nil {
			return err
		}
	}

	s, err := OpenStore(dest)
	if err != nil {
		return err
	}
	defer s.DB.Close()
	op := Operation{Actor: Actor{Subject: "deployment-administrator", Kind: "system", Scopes: []string{"backup:write"}}, Action: "backup.restored", Resource: "database", Reason: "Restore a verified snapshot and revoke old browser sessions", RequestID: newID()}
	_, err = s.Mutation(op, "backup:write", false, func(tx *sql.Tx, _ *Operation) (any, error) {
		_, e := tx.Exec("DELETE FROM sessions")
		if e != nil {
			return nil, e
		}
		_, e = tx.Exec("DELETE FROM login_states")
		if e != nil {
			return nil, e
		}
		// API tokens are credentials like sessions: a restore revokes them.
		_, e = tx.Exec("UPDATE api_tokens SET revoked=? WHERE revoked=''", stamp())
		return map[string]string{"sessions": "revoked", "login_states": "revoked", "api_tokens": "revoked", "authority": m.Authority}, e
	})
	return err
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
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
func copyDatabase(source, dest string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	out, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err = io.Copy(out, input); err != nil {
		return err
	}
	return out.Sync()
}

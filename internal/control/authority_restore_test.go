// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRestoreRejectsInconsistentAuthorityBeforeDestination(t *testing.T) {
	for _, format := range []string{"control-backup-v1", "control-backup-v2"} {
		for _, offset := range []int{0, ed25519.SeedSize} {
			t.Run(fmt.Sprintf("%s/byte-%d", format, offset), func(t *testing.T) {
				root := t.TempDir()
				s, err := OpenStore(filepath.Join(root, "original"))
				if err != nil {
					t.Fatal(err)
				}
				defer s.DB.Close()
				backup := filepath.Join(root, "snapshot")
				if err = s.Backup(backup); err != nil {
					t.Fatal(err)
				}
				keyPath := filepath.Join(backup, "authority.key")
				good, err := os.ReadFile(keyPath)
				if err != nil {
					t.Fatal(err)
				}
				corrupt := append([]byte(nil), good...)
				corrupt[offset] ^= 1
				if err = os.WriteFile(keyPath, corrupt, 0600); err != nil {
					t.Fatal(err)
				}
				var m BackupManifest
				data, err := os.ReadFile(filepath.Join(backup, "manifest.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err = json.Unmarshal(data, &m); err != nil {
					t.Fatal(err)
				}
				m.Version = format
				m.KeySHA = digest(corrupt) // The consistency check must reject even a matching digest.
				if format == "control-backup-v1" {
					m.KeySHA = ""
				}
				data, _ = json.Marshal(m)
				if err = os.WriteFile(filepath.Join(backup, "manifest.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
				dest := filepath.Join(root, "restored")
				if err = RestoreNew(backup, dest); err == nil {
					t.Fatal("inconsistent authority restored")
				}
				if _, err = os.Stat(dest); !os.IsNotExist(err) {
					t.Fatal("denied restore created a destination")
				}
				message := []byte("original authority remains valid after failed restore")
				if !ed25519.Verify(s.Authority.Public().(ed25519.PublicKey), message, ed25519.Sign(s.Authority, message)) {
					t.Fatal("failed restore changed the original authority")
				}
				if err = os.WriteFile(keyPath, good, 0600); err != nil {
					t.Fatal(err)
				}
				m.KeySHA = digest(good)
				if format == "control-backup-v1" {
					m.KeySHA = ""
				}
				data, _ = json.Marshal(m)
				if err = os.WriteFile(filepath.Join(backup, "manifest.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
				if err = RestoreNew(backup, dest); err != nil {
					t.Fatal(err)
				}
				restored, err := OpenStore(dest)
				if err != nil {
					t.Fatal(err)
				}
				defer restored.DB.Close()
				if !ed25519.Verify(s.Authority.Public().(ed25519.PublicKey), message, ed25519.Sign(restored.Authority, message)) {
					t.Fatal("restored authority cannot sign under the original public key")
				}
			})
		}
	}
}

func TestOpenStoreRejectsCorruptAuthority(t *testing.T) {
	for _, offset := range []int{0, ed25519.SeedSize} {
		t.Run(fmt.Sprintf("byte-%d", offset), func(t *testing.T) {
			dir := t.TempDir()
			s, err := OpenStore(dir)
			if err != nil {
				t.Fatal(err)
			}
			s.DB.Close()
			path := filepath.Join(dir, "authority.key")
			key, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			key[offset] ^= 1
			if err = os.WriteFile(path, key, 0600); err != nil {
				t.Fatal(err)
			}
			if opened, err := OpenStore(dir); err == nil {
				opened.DB.Close()
				t.Fatal("corrupt authority loaded")
			}
		})
	}
}

func TestRestoreBindsCompleteKeyDigestAndPublicAuthority(t *testing.T) {
	for _, change := range []string{"missing-digest", "wrong-digest", "other-consistent-key"} {
		t.Run(change, func(t *testing.T) {
			root := t.TempDir()
			s, err := OpenStore(filepath.Join(root, "original"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.DB.Close()
			backup := filepath.Join(root, "snapshot")
			if err = s.Backup(backup); err != nil {
				t.Fatal(err)
			}
			var m BackupManifest
			path := filepath.Join(backup, "manifest.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(data, &m); err != nil {
				t.Fatal(err)
			}
			switch change {
			case "missing-digest":
				m.KeySHA = ""
			case "wrong-digest":
				m.KeySHA = digest([]byte("other"))
			case "other-consistent-key":
				key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
				if err = os.WriteFile(filepath.Join(backup, "authority.key"), key, 0600); err != nil {
					t.Fatal(err)
				}
				m.KeySHA = digest(key)
			}
			data, _ = json.Marshal(m)
			if err = os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			dest := filepath.Join(root, "restored")
			if err = RestoreNew(backup, dest); err == nil {
				t.Fatal("altered key binding restored")
			}
			if _, err = os.Stat(dest); !os.IsNotExist(err) {
				t.Fatal("denied restore created a destination")
			}
		})
	}
}

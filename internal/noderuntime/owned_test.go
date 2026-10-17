// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnedNodeFileRejectsLinksAndSharedSecrets(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "key")
	seed := make([]byte, 32)
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	key, err := privateKey(path)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		t.Fatal(err)
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = privateKey(path); err == nil {
		t.Fatal("a shared private key was accepted")
	}
	_ = os.Chmod(path, 0600)
	link := filepath.Join(root, "linked")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err = readOwned(link, 64, true); err == nil {
		t.Fatal("a linked private key was accepted")
	}
	hard := filepath.Join(root, "hard")
	if err = os.Link(path, hard); err != nil {
		t.Fatal(err)
	}
	if _, err = readOwned(path, 64, true); err == nil {
		t.Fatal("a multiply linked private key was accepted")
	}
}
func TestPrivateKeyRejectsInconsistentPublicBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "key")
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	key[len(key)-1] ^= 1
	if err := os.WriteFile(path, key, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := privateKey(path); err == nil {
		t.Fatal("an inconsistent private key was accepted")
	}
}

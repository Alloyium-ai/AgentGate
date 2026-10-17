// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"alloyium.local/kernel-poc/internal/controlclient"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCustomerKeysArePrivateAndNeverOverwritten(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := nodeKeys(dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "public-keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	var public map[string]string
	if err = json.Unmarshal(data, &public); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"node", "agent"} {
		path := filepath.Join(dir, name+".key")
		key, err := os.ReadFile(path)
		if err != nil || len(key) != ed25519.PrivateKeySize {
			t.Fatal("the customer signing key is invalid")
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("the customer signing key is not private")
		}
		if public[name] != controlclient.EncodeKey(ed25519.NewKeyFromSeed(key[:32]).Public().(ed25519.PublicKey)) {
			t.Fatal("the customer public key does not match the signer")
		}
	}
	if public["node"] == public["agent"] {
		t.Fatal("node and agent share a signing key")
	}
	if err = nodeKeys(dir); err == nil {
		t.Fatal("an existing customer signer was overwritten")
	}
}

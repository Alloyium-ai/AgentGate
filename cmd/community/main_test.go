// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"alloyium.local/kernel-poc/internal/control"
	"alloyium.local/kernel-poc/internal/localconfig"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCustomerInitializeBootstrapAndRestore(t *testing.T) {
	root := t.TempDir()
	state, trust := filepath.Join(root, "state"), filepath.Join(root, "trust")
	t.Setenv("AGENTGATE_STATE_DIR", state)
	t.Setenv("AGENTGATE_TRUST_DIR", trust)
	settings := filepath.Join(root, "settings.json")
	if err := os.WriteFile(settings, []byte(`{"schema":"agentgate.community.settings.v1","public_url":"https://community.example.test","listen":"127.0.0.1:8930","session_seconds":1800,"auth_mode":"local","group_roles":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"init", settings}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"init", settings}); err == nil {
		t.Fatal("existing customer trust was overwritten")
	}
	input := filepath.Join(root, "first-admin.json")
	if err := os.WriteFile(input, []byte(`{"username":"operator","name":"Synthetic operator","password":"synthetic-only-passphrase-2026"}`), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(input)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	original := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = original }()
	if err = run([]string{"first-admin"}); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(root, "snapshot")
	if err = run([]string{"backup", snapshot}); err != nil {
		t.Fatal(err)
	}
	restored := filepath.Join(root, "restored")
	if err = run([]string{"restore", snapshot, restored}); err != nil {
		t.Fatal(err)
	}
	store, err := control.OpenStore(filepath.Join(restored, "data"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.DB.Close()
	users, err := store.Users()
	if err != nil || len(users) != 1 || users[0].Username != "operator" {
		t.Fatal("restore lost the local administrator", err)
	}
	var count int
	if err = store.DB.QueryRow("SELECT count(*) FROM sessions").Scan(&count); err != nil || count != 0 {
		t.Fatal("restore retained browser credentials")
	}
	if err = run([]string{"restore", snapshot, restored}); err == nil {
		t.Fatal("restore overwrote existing state")
	}
	// A new configuration revision prevents a stale state restore with the independent anchor.
	config, err := localconfig.Open(filepath.Join(state, "config"), trust)
	if err != nil {
		t.Fatal(err)
	}
	defer config.DB.Close()
	var next localconfig.Settings
	data, _ := os.ReadFile(settings)
	json.Unmarshal(data, &next)
	next.SessionSeconds = 900
	if _, err = config.Publish(localconfig.Operation{Actor: "deployment-administrator", Kind: "system", Reason: "Advance the independently anchored revision", RequestID: "synthetic"}, next, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = config.Read(); err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"restore", snapshot, filepath.Join(root, "stale")}); err == nil {
		t.Fatal("restore accepted an older anchored configuration")
	}
}

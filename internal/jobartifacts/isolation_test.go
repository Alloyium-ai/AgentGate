// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobartifacts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDockerStreamRootRejectsAnotherJobAndCleansAfterStop(t *testing.T) {
	root := t.TempDir()
	store, err := New(root, "node", 32)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	current := binding()
	first, err := store.Prepare(current, hashBytes([]byte("source")), []byte("source"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err = store.OnlyJob(current); err != nil {
			t.Fatalf("the single prepared job was rejected on check %d: %v", i, err)
		}
	}
	other := current
	other.RunID = "another-owned-run"
	second, err := store.Prepare(other, hashBytes([]byte("other")), []byte("other"))
	if err != nil {
		t.Fatal(err)
	}
	if err = store.OnlyJob(current); err == nil {
		t.Fatal("the target could see another job's input")
	}
	if err = store.Remove(other); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(second.Directory); !os.IsNotExist(err) {
		t.Fatal("the other job's stream directory remains", err)
	}
	if err = store.OnlyJob(current); err != nil {
		t.Fatal("the single current job remained blocked", err)
	}
	if err = store.Remove(current); err != nil {
		t.Fatal(err)
	}
	if err = store.Remove(current); err != nil {
		t.Fatal("terminal cleanup was not retryable", err)
	}
	if _, err = os.Lstat(first.Directory); !os.IsNotExist(err) {
		t.Fatal("the current job's stream directory remains", err)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatal("the target stream root is not empty", entries, err)
	}
}

func TestDockerStreamCleanupRejectsForeignEntry(t *testing.T) {
	store, err := New(t.TempDir(), "node", 32)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	current := binding()
	streams, err := store.Prepare(current, hashBytes(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(streams.Directory, "foreign")
	if err = os.WriteFile(foreign, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err = store.Remove(current); err == nil {
		t.Fatal("a foreign file disappeared under terminal cleanup")
	}
	if _, err = os.Lstat(foreign); err != nil {
		t.Fatal("cleanup removed a foreign file", err)
	}
}

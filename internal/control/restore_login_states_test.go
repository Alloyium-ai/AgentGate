// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package control

import (
	"path/filepath"
	"testing"
	"time"
)

func TestIndependentRestoreClearsPendingLoginStates(t *testing.T) {
	root := t.TempDir()
	s, err := OpenStore(filepath.Join(root, "original"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("INSERT INTO login_states VALUES(?,?,?,?,?)", digest([]byte("pending-review-state")), "synthetic-nonce", "synthetic-verifier", digest([]byte("synthetic-browser-binding")), time.Now().Add(5*time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	snapshot := filepath.Join(root, "snapshot")
	if err = s.Backup(snapshot); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	dest := filepath.Join(root, "restored")
	if err = RestoreNew(snapshot, dest); err != nil {
		t.Fatal(err)
	}
	restored, err := OpenStore(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.DB.Close()
	var pending int
	if err = restored.DB.QueryRow("SELECT COUNT(*) FROM login_states").Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("RESTORE_RETAINS_PENDING_LOGIN_STATES count=%d", pending)
	}
}

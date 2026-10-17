// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package control

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupRestorePreservesPolicyAndAudit(t *testing.T) {
	root := t.TempDir()
	s, err := OpenStore(filepath.Join(root, "original"))
	if err != nil {
		t.Fatal(err)
	}
	v := publish(t, s, createVersion(t, s))
	key := EncodePublic(s.Authority.Public().(ed25519.PublicKey))
	backup := filepath.Join(root, "backup")
	if err = s.Backup(backup); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	restored := filepath.Join(root, "restored")
	if err = RestoreNew(backup, restored); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(restored)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	if EncodePublic(s.Authority.Public().(ed25519.PublicKey)) != key {
		t.Fatal("restore changed the authority key")
	}
	kept, err := versionFrom(s.DB, v.ID)
	if err != nil || kept.Digest != v.Digest {
		t.Fatal("restore lost immutable policy")
	}
	var n int
	s.DB.QueryRow("SELECT COUNT(*) FROM audit WHERE action='backup.restored'").Scan(&n)
	if n != 1 {
		t.Fatal("restore lacks audit provenance")
	}
	if err = RestoreNew(backup, restored); err == nil {
		t.Fatal("restore replaced an existing volume")
	}
	if err = os.WriteFile(filepath.Join(backup, "control.db"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = RestoreNew(backup, filepath.Join(root, "bad-restore")); err == nil {
		t.Fatal("corrupt backup restored")
	}
}

func TestMigrationTwoPreservesExistingHistory(t *testing.T) {
	root := t.TempDir()
	s, err := OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	v := publish(t, s, createVersion(t, s))
	if _, err = s.DB.Exec("PRAGMA user_version=1"); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	s, err = OpenStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	var version int
	s.DB.QueryRow("PRAGMA user_version").Scan(&version)
	if version != 4 {
		t.Fatal("migration did not set schema four")
	}
	kept, err := versionFrom(s.DB, v.ID)
	if err != nil || kept.Digest != v.Digest {
		t.Fatal("migration changed an immutable version")
	}
	var indexes int
	s.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name IN ('audit_action_time','audit_time','audit_version_time')").Scan(&indexes)
	if indexes != 3 {
		t.Fatal("migration omitted audit indexes")
	}
}

func TestRestoreRequiresFreshHumanApprovalBeforeAdmission(t *testing.T) {
	root := t.TempDir()
	s, err := OpenStore(filepath.Join(root, "original"))
	if err != nil {
		t.Fatal(err)
	}
	v := publish(t, s, createVersion(t, s))
	agent, _ := enroll(t, s, "synthetic-restore-agent", "agent", []string{"request:create"})
	node, _ := enroll(t, s, "synthetic-restore-node", "service", []string{"admission:write"})
	request := func(store *Store) PolicyRequest {
		value, e := store.RequestPolicy(Operation{Actor: agent}, RequestPolicy{VersionID: v.ID, Reason: "Request the restore fixture"})
		if e != nil {
			t.Fatal(e)
		}
		q := value.(PolicyRequest)
		value, e = store.DecideRequest(humanOp(store), q.ID, etag(1), Decision{State: "approved", Reason: "Approve one exact restore fixture"})
		if e != nil {
			t.Fatal(e)
		}
		return value.(PolicyRequest)
	}
	old := request(s)
	snapshot := filepath.Join(root, "snapshot")
	if err = s.Backup(snapshot); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	dest := filepath.Join(root, "restored")
	if err = RestoreNew(snapshot, dest); err != nil {
		t.Fatal(err)
	}
	s, err = OpenStore(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	input := AdmitInput{old.ID, "restore-fixture-run", "synthetic-node", "boot", "42", "/var/lib/restore/workspace/", "9007199254740993", "Admit a verified restore fixture"}
	_, err = s.Admit(Operation{Actor: node}, input)
	_, code, _ := errorResult(err)
	if code != "request_restore_fenced" {
		t.Fatalf("restore accepted an old approval: %v", err)
	}
	fresh := request(s)
	input.RequestID = fresh.ID
	if _, err = s.Admit(Operation{Actor: node}, input); err != nil {
		t.Fatalf("fresh human approval failed after restore: %v", err)
	}
}

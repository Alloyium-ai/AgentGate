// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTaskboardSnapshotRequiresExactOwnedLiveTask(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the protected snapshot custody test requires root")
	}
	root := t.TempDir()
	target := Target{BridgeSource: root, BridgeTaskID: 42}
	path := filepath.Join(root, "task.json")
	write := func(task int, expires time.Time) {
		t.Helper()
		raw := fmt.Sprintf(`{"protocol":"agentgate.taskboard-read.v1","task":{"id":%d},"valid_until":%q}`, task, expires.UTC().Format(time.RFC3339Nano))
		if err := os.WriteFile(path, []byte(raw), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(42, time.Now().Add(10*time.Second))
	if err := readBridgeSnapshot(target); err != nil {
		t.Fatal(err)
	}
	write(43, time.Now().Add(10*time.Second))
	if err := readBridgeSnapshot(target); err == nil {
		t.Fatal("a different task passed the scoped bridge readback")
	}
	write(42, time.Now().Add(-time.Second))
	if err := readBridgeSnapshot(target); err == nil {
		t.Fatal("a stale taskboard result passed the bridge readback")
	}
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	}
	if err := readBridgeSnapshot(target); err == nil {
		t.Fatal("a mutable snapshot passed the bridge readback")
	}
}

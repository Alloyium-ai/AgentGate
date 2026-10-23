// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestPilotBridgeRejectsChangedSocketAndForeignRoute(t *testing.T) {
	good := pilotBridgeReadback{TaskID: 42, ProjectID: 7, Status: "Backlog", SocketDevice: 1, SocketInode: 2, ForeignStatus: http.StatusForbidden, UpstreamNoTokenStatus: http.StatusUnauthorized, TokenAbsent: true, SnapshotValidUntil: time.Now().Add(15 * time.Second).Format(time.RFC3339Nano)}
	if !samePilotBridge(good, good, 42) {
		t.Fatal("a valid one-task readback was rejected")
	}
	for name, change := range map[string]func(*pilotBridgeReadback){
		"wrong task":      func(v *pilotBridgeReadback) { v.TaskID++ },
		"new socket":      func(v *pilotBridgeReadback) { v.SocketInode++ },
		"foreign read":    func(v *pilotBridgeReadback) { v.ForeignStatus = http.StatusOK },
		"public upstream": func(v *pilotBridgeReadback) { v.UpstreamNoTokenStatus = http.StatusOK },
		"token path":      func(v *pilotBridgeReadback) { v.TokenAbsent = false },
		"no snapshot":     func(v *pilotBridgeReadback) { v.SnapshotValidUntil = "" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := good
			change(&changed)
			if samePilotBridge(good, changed, 42) {
				t.Fatal("a changed pilot bridge gained qualification")
			}
		})
	}
}

func TestPilotSnapshotRequiresExactTaskAndFreshExpiry(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the target snapshot custody uses a root-owned bridge")
	}
	root := t.TempDir()
	path := filepath.Join(root, "task.json")
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	now := time.Now()
	write := func(task int, expiry time.Time) {
		t.Helper()
		raw, marshalErr := json.Marshal(map[string]any{"protocol": "agentgate.taskboard-read.v1", "task": map[string]any{"id": task, "project_id": 7, "status": "Backlog", "title": "Owned task"}, "valid_until": expiry.Format(time.RFC3339Nano)})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if writeErr := os.WriteFile(path, raw, 0644); writeErr != nil {
			t.Fatal(writeErr)
		}
	}
	write(42, now.Add(15*time.Second))
	snapshot, err := pilotTaskSnapshot(rootFD, "task.json", 42, now)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.matches(42, 7, "Backlog", "Owned task") ||
		snapshot.matches(42, 8, "Backlog", "Owned task") ||
		snapshot.matches(42, 7, "In Progress", "Owned task") ||
		snapshot.matches(42, 7, "Backlog", "Changed task") {
		t.Fatal("mounted task and authenticated task matching differs")
	}
	for _, sample := range []struct {
		name   string
		task   int
		expiry time.Time
	}{
		{"stale", 42, now.Add(-time.Second)},
		{"long-lived", 42, now.Add(time.Minute)},
		{"foreign-task", 43, now.Add(15 * time.Second)},
	} {
		t.Run(sample.name, func(t *testing.T) {
			write(sample.task, sample.expiry)
			if _, readErr := pilotTaskSnapshot(rootFD, "task.json", 42, now); readErr == nil {
				t.Fatal("a stale, unbounded, or foreign snapshot gained qualification")
			}
		})
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(filepath.Join(root, "outside"), path); err != nil {
		t.Fatal(err)
	}
	if _, err = pilotTaskSnapshot(rootFD, "task.json", 42, now); err == nil {
		t.Fatal("a linked snapshot gained qualification")
	}
}

func TestPilotBridgeRequestUsesOnlyTheOwnedSocketAndBoundsReplies(t *testing.T) {
	path := filepath.Join(t.TempDir(), "taskboard.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/task":
			_, _ = w.Write([]byte(`{"id":42,"project_id":7,"status":"Backlog","title":"Pilot"}`))
		case "/api/tasks/1":
			w.WriteHeader(http.StatusForbidden)
		case "/auth-probe":
			_, _ = w.Write([]byte(`{"task_id":42,"upstream_status":401}`))
		case "/oversized":
			_, _ = w.Write([]byte(strings.Repeat("x", 4097)))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	client := pilotBridgeClient(path)
	defer client.CloseIdleConnections()
	for route, status := range map[string]int{"/task": http.StatusOK, "/api/tasks/1": http.StatusForbidden, "/auth-probe": http.StatusOK} {
		response, requestErr := pilotBridgeRequest(context.Background(), client, route)
		if requestErr != nil || response.status != status {
			t.Fatalf("the local route %s differs: %v %d", route, requestErr, response.status)
		}
	}
	if _, err = pilotBridgeRequest(context.Background(), client, "/oversized"); err == nil {
		t.Fatal("an oversized bridge reply was accepted")
	}
}

func TestPilotBridgeUsesRetainedRootAndRejectsSymlinkEscape(t *testing.T) {
	root, err := os.MkdirTemp(os.TempDir(), "pb-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	outside, err := os.MkdirTemp(os.TempDir(), "po-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(outside)
	if err := os.MkdirAll(filepath.Join(root, "run/agentgate/taskboard"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "run/secrets"), 0750); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "run/agentgate/taskboard/taskboard.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	rootFD, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	fd, err := openPilotTargetPath(rootFD, "run/agentgate/taskboard/taskboard.sock")
	if err != nil {
		t.Fatal(err)
	}
	var found unix.Stat_t
	if err = unix.Fstat(fd, &found); err != nil || found.Mode&unix.S_IFMT != unix.S_IFSOCK {
		t.Fatal("the retained root did not reach its socket", err)
	}
	unix.Close(fd)
	if _, err = openPilotTargetPath(rootFD, "run/secrets/taskboard-token"); err != unix.ENOENT {
		t.Fatal("an absent token did not remain absent", err)
	}
	if err = os.Symlink(filepath.Join(outside, "token"), filepath.Join(root, "run/secrets/taskboard-token")); err != nil {
		t.Fatal(err)
	}
	if _, err = openPilotTargetPath(rootFD, "run/secrets/taskboard-token"); err == nil || err == unix.ENOENT {
		t.Fatal("a symlinked token appeared absent", err)
	}
	if err = os.Rename(filepath.Join(root, "run/agentgate/taskboard"), filepath.Join(root, "run/agentgate/old")); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(outside, filepath.Join(root, "run/agentgate/taskboard")); err != nil {
		t.Fatal(err)
	}
	if _, err = openPilotTargetPath(rootFD, "run/agentgate/taskboard/taskboard.sock"); err == nil {
		t.Fatal("a symlinked bridge mount was accepted")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestLifecycleWorkerActualTree(t *testing.T) {
	path := os.Getenv("AGENTGATE_LIFECYCLE_WORKER")
	if path == "" {
		t.Skip("the measured static lifecycle worker is required")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.Command(path)
	command.Env = []string{}
	command.Stdin = strings.NewReader("T")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Kill(-command.Process.Pid, unix.SIGKILL); err != nil && err != unix.ESRCH {
			t.Error(err)
		}
		_ = command.Wait()
	}()
	type outcome struct {
		raw []byte
		err error
	}
	result := make(chan outcome, 1)
	go func() { wire := make([]byte, 96); _, err := io.ReadFull(stdout, wire); result <- outcome{wire, err} }()
	var wire []byte
	select {
	case actual := <-result:
		if actual.err != nil {
			t.Fatal(actual.err)
		}
		wire = actual.raw
	case <-ctx.Done():
		t.Fatal("the worker did not emit three actual records")
	}
	actors, err := DecodeLifecycleRecords(wire)
	if err != nil {
		t.Fatal(err)
	}
	if actors[0].PID != uint32(command.Process.Pid) {
		t.Fatal("the root PID differs from the launched process")
	}
	snapshots := []processSnapshot{}
	for _, actor := range actors {
		snapshot, err := inspectProcess(int(actor.PID), path, hash)
		if err != nil {
			t.Fatal(err)
		}
		if len(snapshot.Tasks) != 1 || snapshot.StartTimeTicks == 0 || snapshot.Cgroup == "" {
			t.Fatal("the actual process identity is incomplete")
		}
		if len(snapshots) > 0 && snapshot.Cgroup != snapshots[0].Cgroup {
			t.Fatal("the actual child left the root cgroup")
		}
		snapshots = append(snapshots, snapshot)
	}
	if output := os.Getenv("AGENTGATE_LIFECYCLE_WORKER_RECEIPT"); output != "" {
		encoded, err := json.MarshalIndent(struct {
			Artifact  string            `json:"artifact_sha256"`
			Wire      []byte            `json:"wire"`
			Processes []processSnapshot `json:"processes"`
			Scope     string            `json:"scope"`
		}{hash, wire, snapshots, "worker-topology-only; no lifecycle, kernel or termination coverage"}, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(output, encoded, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

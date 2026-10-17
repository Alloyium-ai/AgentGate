// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package heldprocess

import (
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestExitedUsesTheRetainedPIDFD(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	pidfd := -1
	cmd := exec.Command("/bin/cat")
	cmd.Stdin = reader
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
	}()
	h := &Held{pidfd: pidfd, done: make(chan struct{})}
	if dead, err := h.Exited(); err != nil || dead {
		t.Fatal("a live held identity looked exited", dead, err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if dead, err := h.Exited(); err != nil || !dead {
		t.Fatal("the reaped PIDFD did not prove exit", dead, err)
	}
}
func TestExitedRejectsMissingCustody(t *testing.T) {
	h := &Held{pidfd: -1, done: make(chan struct{})}
	if dead, err := h.Exited(); err == nil || dead {
		t.Fatal("missing PIDFD custody proved exit")
	}
}

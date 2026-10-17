// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package kernel

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func stoppedSingleThread(pid int) error {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return err
	}
	end := strings.LastIndex(string(raw), ")")
	if end < 0 {
		return errors.New("the stopped process identity is incomplete")
	}
	fields := strings.Fields(string(raw)[end+1:])
	if len(fields) < 1 || (fields[0] != "T" && fields[0] != "t") {
		return errors.New("the job process is not stopped")
	}
	threads, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return err
	}
	if len(threads) != 1 || threads[0].Name() != strconv.Itoa(pid) {
		return errors.New("the job process has an unheld thread")
	}
	return nil
}

// VerifyQuiescent requires one stopped single-thread helper and no child domain.
// The trusted callback also verifies its exact measured barrier and PID identity.
func (r *Runtime) VerifyQuiescent(verifyHeld func() error) error {
	if r == nil || verifyHeld == nil || r.ID == 0 || r.Domain == "" {
		return errors.New("a measured owned quarantine is required")
	}
	if err := verifyHeld(); err != nil {
		return err
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(r.Domain, &st); err != nil {
		return err
	}
	if st.Ino != r.ID {
		return errors.New("the quarantined domain inode differs")
	}
	entries, err := os.ReadDir(r.Domain)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			return errors.New("the quarantine contains an unverified child domain")
		}
	}
	path := filepath.Join(r.Domain, "cgroup.procs")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	pids := strings.Fields(string(raw))
	if len(pids) != 1 {
		return errors.New("the quarantine requires exactly one held process")
	}
	pid, err := strconv.Atoi(pids[0])
	if err != nil || pid <= 1 {
		return errors.New("the quarantine process ID is invalid")
	}
	if err = stoppedSingleThread(pid); err != nil {
		return err
	}
	if err = verifyHeld(); err != nil {
		return err
	}
	again, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(again) != string(raw) {
		return errors.New("the quarantine membership changed")
	}
	return stoppedSingleThread(pid)
}

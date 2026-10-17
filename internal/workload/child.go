// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package workload

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"runtime"
	"syscall"
)

// Child reads the declaration only after the enforcer moves it into the installed domain.
func Child() error {
	gate := os.NewFile(3, "workload admission")
	if gate == nil {
		return errors.New("workload admission barrier unavailable")
	}
	job, err := Read(gate)
	gate.Close()
	if err != nil {
		return err
	}
	if err = job.CheckFiles(); err != nil {
		return err
	}
	return execChild(job, restrictChild)
}

// Thread security state must stay on the thread that executes the workload.
// Keep the thread locked on errors; the child caller exits instead of reusing it.
func execChild(job Job, prepare func(Job) error) error {
	runtime.LockOSThread()
	if err := prepare(job); err != nil {
		return err
	}
	flags, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		return err
	}
	if flags != 1 {
		return errors.New("workload privilege restriction differs before exec")
	}
	// Do not inherit the node's credentials or loader options into the workload.
	environment := []string{"PATH=/usr/bin:/bin", "HOME=" + job.Workspace, "TMPDIR=" + job.Workspace, "LANG=C.UTF-8"}
	return syscall.Exec(job.Executable, append([]string{job.Executable}, job.Arguments...), environment)
}

func restrictChild(job Job) error {
	var err error
	if err = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if err = syscall.Setgroups(nil); err != nil {
		return err
	}
	if err = syscall.Setgid(65534); err != nil {
		return err
	}
	if err = syscall.Setuid(65534); err != nil {
		return err
	}
	if err = os.Chdir(job.Workspace); err != nil {
		return err
	}
	return nil
}

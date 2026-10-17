// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobartifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// VerifyRunningExecutable measures the kernel's current executable reference.
// A replacement pathname cannot substitute bytes for the running artifact.
func VerifyRunningExecutable(expected string) error {
	return VerifyProcessExecutable(os.Getpid(), expected)
}

// VerifyProcessExecutable measures the kernel reference and the protected path.
// The caller must retain and check the process start identity around this call.
func VerifyProcessExecutable(pid int, expected string) error {
	if pid <= 0 {
		return errors.New("the measured process identity is invalid")
	}
	proc := "/proc/" + strconv.Itoa(pid) + "/exe"
	path, err := os.Readlink(proc)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("the running executable path differs")
	}
	if err = VerifyExecutable(path, expected); err != nil {
		return err
	}
	f, err := os.Open(proc)
	if err != nil {
		return err
	}
	defer f.Close()
	var opened, current unix.Stat_t
	if err = unix.Fstat(int(f.Fd()), &opened); err != nil {
		return err
	}
	if err = unix.Lstat(path, &current); err != nil {
		return err
	}
	if opened.Dev != current.Dev || opened.Ino != current.Ino || opened.Size != current.Size {
		return errors.New("the running executable inode differs")
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(f, (1<<30)+1))
	if err != nil {
		return err
	}
	if n != opened.Size || n > 1<<30 || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("the running executable digest differs")
	}
	return nil
}

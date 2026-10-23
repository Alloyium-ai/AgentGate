// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package runtimeclosure

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestVerifyAtPinsFilesInsideTheTargetRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("target file custody requires root")
	}
	root := t.TempDir()
	parent := filepath.Join(root, "opt", "runtime")
	if err := os.MkdirAll(parent, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "a.so")
	if err := os.WriteFile(path, []byte("alpha"), 0644); err != nil {
		t.Fatal(err)
	}
	file := pin("/opt/runtime/a.so", "alpha")
	set, err := New([]File{file})
	if err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	rootFile := os.NewFile(uintptr(fd), "owned target root")
	defer rootFile.Close()
	measurement, err := set.VerifyAt(context.Background(), rootFile)
	if err != nil || measurement.Digest != set.Digest() {
		t.Fatal("the exact target runtime file failed", err)
	}
	if err := os.WriteFile(path, []byte("other"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = set.VerifyAt(context.Background(), rootFile); !errors.Is(err, ErrDigest) {
		t.Fatal("a changed target runtime file passed", err)
	}
	if err := os.Chmod(filepath.Join(root, "opt"), 0777); err != nil {
		t.Fatal(err)
	}
	if _, err = set.VerifyAt(context.Background(), rootFile); !errors.Is(err, ErrCustody) {
		t.Fatal("a writable target runtime parent passed", err)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNamespaceHandlePinsTheKindAndInode(t *testing.T) {
	want, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	file, err := namespaceHandle(os.Getpid(), "mnt", want, unix.CLONE_NEWNS)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if file.Fd() == 0 {
		t.Fatal("namespace descriptor is absent")
	}
	if file, err = namespaceHandle(os.Getpid(), "mnt", "mnt:[1]", unix.CLONE_NEWNS); err == nil {
		file.Close()
		t.Fatal("a replaced namespace identity was accepted")
	}
	if file, err = namespaceHandle(os.Getpid(), "mnt", want, unix.CLONE_NEWNET); err == nil {
		file.Close()
		t.Fatal("a different namespace type was accepted")
	}
}

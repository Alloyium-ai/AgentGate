// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDurableDaemonStateHasOneOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owner")
	first, err := acquireOwner(path)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := acquireOwner(path); err == nil {
		second.Close()
		t.Fatal("two daemons acquired the same state")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := acquireOwner(path)
	if err != nil {
		t.Fatal(err)
	}
	next.Close()
	linked := path + ".linked"
	if err = os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	if next, err = acquireOwner(linked); err == nil {
		next.Close()
		t.Fatal("a linked owner file was accepted")
	}
}

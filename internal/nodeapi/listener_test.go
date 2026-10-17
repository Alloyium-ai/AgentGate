// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSocketRestartKeepsLiveAndForeignPaths(t *testing.T) {
	f := newFixture(t)
	if err := removeStaleSocket(f.server.config.SocketPath); err == nil {
		t.Fatal("a live node socket was removed")
	}
	stale := filepath.Join(f.root, "stale.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: stale, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err = os.Chmod(stale, 0660); err != nil {
		t.Fatal(err)
	}
	listener.Close()
	if err = removeStaleSocket(stale); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatal("the stale socket remained")
	}
	foreign := filepath.Join(f.root, "foreign")
	if err = os.WriteFile(foreign, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = removeStaleSocket(foreign); err == nil {
		t.Fatal("a foreign path was removed")
	}
	if _, err = os.Lstat(foreign); err != nil {
		t.Fatal("the foreign path changed")
	}
}

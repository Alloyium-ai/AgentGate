// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobartifacts

import (
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

func TestRuntimeTraversalModesKeepPrivateStateSeparate(t *testing.T) {
	for _, test := range []struct {
		mode uint32
		gid  uint32
		want bool
	}{{0700, 0, false}, {0711, 0, true}, {0755, 0, true}, {0710, 0, false}, {0710, 65534, true}, {0701, 0, true}} {
		if got := runtimeTraversable(unix.Stat_t{Mode: test.mode, Gid: test.gid}); got != test.want {
			t.Fatal(test, got)
		}
	}
	if ValidateRuntimeTraversal(t.TempDir()) == nil {
		t.Fatal("a private parent reached runtime admission")
	}
}
func TestStreamDirectoryUsesItsExplicitModeDespiteNodeUmask(t *testing.T) {
	store, err := New(t.TempDir(), "node", 16)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	streams, err := store.Prepare(binding(), hashBytes(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(streams.Directory)
	if err != nil || info.Mode().Perm() != 0711 {
		t.Fatal("the owned stream directory blocks traversal", info, err)
	}
}

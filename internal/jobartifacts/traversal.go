// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobartifacts

import (
	"errors"
	"golang.org/x/sys/unix"
	"path/filepath"
)

func runtimeTraversable(st unix.Stat_t) bool {
	return st.Mode&0001 != 0 || (st.Gid == 65534 && st.Mode&0010 != 0)
}

// ValidateRuntimeTraversal rejects basic directory modes that block the fixed
// runtime UID/GID. It changes no directory, ACL or file permission.
func ValidateRuntimeTraversal(root string) error {
	if !canonical(root) {
		return errors.New("the runtime stream root is invalid")
	}
	if err := privateParents(filepath.Join(root, "entry")); err != nil {
		return err
	}
	for path := root; ; path = filepath.Dir(path) {
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		if !runtimeTraversable(st) {
			return errors.New("a job stream parent blocks runtime UID65534 traversal")
		}
		if path == "/" {
			return nil
		}
	}
}

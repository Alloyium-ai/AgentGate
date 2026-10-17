// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import "golang.org/x/sys/unix"

func readSocketStat(path string, out *syscallStat) error {
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return err
	}
	out.UID, out.GID = stat.Uid, stat.Gid
	return nil
}

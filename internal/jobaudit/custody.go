// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobaudit

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
)

// openProtected creates only a new root-owned log below verified directory FDs.
func openProtected(path string) (*os.File, int, error) {
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
		return nil, -1, errors.New("the audit requires a canonical protected path")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, -1, err
	}
	fail := func(err error) (*os.File, int, error) { unix.Close(fd); return nil, -1, err }
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return fail(err)
		}
		var stat unix.Stat_t
		if unix.Fstat(next, &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 {
			unix.Close(next)
			return fail(errors.New("the audit directory custody differs"))
		}
		unix.Close(fd)
		fd = next
	}
	var parent unix.Stat_t
	if unix.Fstat(fd, &parent) != nil || parent.Mode&0077 != 0 {
		return fail(errors.New("the audit parent must be private"))
	}
	fileFD, err := unix.Openat(fd, parts[len(parts)-1], unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return fail(err)
	}
	return os.NewFile(uintptr(fileFD), path), fd, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// ListenUnix creates only an owned private UDS. An active or unverified existing path fails closed.
// The caller provisions the parent directory. An owned refused stale socket permits restart.
func ListenUnix(path string, gid *int) (*net.UnixListener, error) {
	if e := socketParent(path, gid); e != nil {
		return nil, e
	}
	if len(path) > 100 {
		return nil, errors.New("authority_socket_path_bound")
	}
	if e := removeStaleSocket(path); e != nil {
		return nil, e
	}
	listener, e := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if e != nil {
		return nil, e
	}
	fail := func(e error) (*net.UnixListener, error) { listener.Close(); return nil, e }
	mode := os.FileMode(0600)
	if gid != nil {
		if *gid < 0 {
			return fail(errors.New("authority_socket_gid_invalid"))
		}
		if e = os.Chown(path, os.Geteuid(), *gid); e != nil {
			return fail(e)
		}
		mode = 0660
	}
	if e = os.Chmod(path, mode); e != nil {
		return fail(e)
	}
	st, e := os.Lstat(path)
	if e != nil || st.Mode()&os.ModeSocket == 0 || st.Mode().Perm() != mode {
		return fail(errors.New("authority_socket_mode_invalid"))
	}
	x, ok := st.Sys().(*syscall.Stat_t)
	if !ok || x.Uid != uint32(os.Geteuid()) || filepath.Dir(path) == "/" {
		return fail(errors.New("authority_socket_owner_invalid"))
	}
	return listener, nil
}

func socketParent(path string, gid *int) error {
	if gid == nil {
		return privatePath(path)
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.HasPrefix(path, "/tmp/") || path == "/tmp" {
		return errors.New("authority_private_path_required")
	}
	parent := filepath.Dir(path)
	resolved, e := filepath.EvalSymlinks(parent)
	if e != nil || resolved != parent {
		return errors.New("authority_private_parent_required")
	}
	st, e := os.Stat(parent)
	if e != nil || !st.IsDir() || st.Mode().Perm()&0027 != 0 {
		return errors.New("authority_private_parent_required")
	}
	x, ok := st.Sys().(*syscall.Stat_t)
	if !ok || x.Uid != uint32(os.Geteuid()) || *gid < 0 || x.Gid != uint32(*gid) {
		return errors.New("authority_private_owner_required")
	}
	return nil
}

func removeStaleSocket(path string) error {
	st, e := os.Lstat(path)
	if os.IsNotExist(e) {
		return nil
	}
	if e != nil || st.Mode()&os.ModeSocket == 0 {
		return errors.New("authority_socket_exists")
	}
	x, ok := st.Sys().(*syscall.Stat_t)
	if !ok || x.Uid != uint32(os.Geteuid()) || st.Mode().Perm()&0007 != 0 {
		return errors.New("authority_socket_custody_invalid")
	}
	conn, e := net.DialTimeout("unix", path, 100*time.Millisecond)
	if e == nil {
		conn.Close()
		return errors.New("authority_socket_active")
	}
	if !errors.Is(e, syscall.ECONNREFUSED) {
		return errors.New("authority_socket_state_unknown")
	}
	current, e := os.Lstat(path)
	if e != nil || !os.SameFile(st, current) {
		return errors.New("authority_socket_changed")
	}
	return os.Remove(path)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func (s *Server) listener() (*net.UnixListener, unix.Stat_t, error) {
	path := s.config.SocketPath
	var owned unix.Stat_t
	if os.Geteuid() != 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/tmp" || strings.HasPrefix(path, "/tmp/") || s.config.SocketGID > 2147483647 {
		return nil, owned, errors.New("a root-owned private node socket is required")
	}
	parent := filepath.Dir(path)
	actual, err := filepath.EvalSymlinks(parent)
	if err != nil || actual != parent {
		return nil, owned, errors.New("the node socket parent is linked or unavailable")
	}
	var info unix.Stat_t
	if err = unix.Stat(parent, &info); err != nil || info.Uid != 0 || info.Mode&0022 != 0 || info.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, owned, errors.New("the node socket parent must remain root-owned and unwritable by callers")
	}
	if err = removeStaleSocket(path); err != nil {
		return nil, owned, err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, owned, errors.New("the node socket cannot bind")
	}
	listener.SetUnlinkOnClose(false)
	if err = unix.Lstat(path, &owned); err != nil {
		listener.Close()
		return nil, owned, errors.New("the node socket identity is unavailable")
	}
	if err = os.Chown(path, 0, int(s.config.SocketGID)); err == nil {
		err = os.Chmod(path, 0660)
	}
	if err == nil {
		err = unix.Lstat(path, &owned)
	}
	if err != nil {
		listener.Close()
		removeOwnedSocket(path, owned)
		return nil, owned, errors.New("the node socket ownership cannot bind")
	}
	return listener, owned, nil
}

// A private stale socket can remain after a node crash. Never unlink a live peer.
func removeStaleSocket(path string) error {
	var prior unix.Stat_t
	err := unix.Lstat(path, &prior)
	if errors.Is(err, syscall.ENOENT) {
		return nil
	}
	if err != nil || prior.Mode&unix.S_IFMT != unix.S_IFSOCK || prior.Uid != 0 || prior.Mode&0007 != 0 {
		return errors.New("the existing node socket is not a private owned socket")
	}
	connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
	if dialErr == nil {
		connection.Close()
		return errors.New("the node socket already has a live listener")
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return errors.New("the existing node socket liveness is unknown")
	}
	var current unix.Stat_t
	if unix.Lstat(path, &current) != nil || current.Dev != prior.Dev || current.Ino != prior.Ino {
		return errors.New("the existing node socket identity changed")
	}
	return os.Remove(path)
}

func removeOwnedSocket(path string, owned unix.Stat_t) {
	var current unix.Stat_t
	if unix.Lstat(path, &current) == nil && current.Dev == owned.Dev && current.Ino == owned.Ino && current.Mode&unix.S_IFMT == unix.S_IFSOCK {
		_ = os.Remove(path)
	}
}

// Serve binds no TCP endpoint. The peer context comes only from SO_PEERCRED.
func (s *Server) Serve(ctx context.Context) error {
	listener, owned, err := s.listener()
	if err != nil {
		return err
	}
	defer listener.Close()
	defer removeOwnedSocket(s.config.SocketPath, owned)
	readTimeout := s.config.RequestTimeout
	if readTimeout > 30*time.Second {
		readTimeout = 30 * time.Second
	}
	server := &http.Server{Handler: s, ConnContext: connectionContext, ReadHeaderTimeout: s.config.ReadHeaderTimeout, ReadTimeout: readTimeout, MaxHeaderBytes: 16384}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err = <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		cleanup, cancel := context.WithTimeout(context.Background(), s.config.ShutdownTimeout)
		defer cancel()
		err = server.Shutdown(cleanup)
		if err != nil {
			_ = server.Close()
			return errors.New("the node server shutdown is incomplete")
		}
		return nil
	}
}

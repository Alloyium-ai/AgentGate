// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package jobartifacts measures immutable runtime artifacts and owns job streams.
package jobartifacts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func canonical(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && path != "/tmp" && !strings.HasPrefix(path, "/tmp/") && !strings.ContainsRune(path, 0)
}
func privateParents(path string) error {
	for path = filepath.Dir(path); ; path = filepath.Dir(path) {
		var st unix.Stat_t
		if err := unix.Lstat(path, &st); err != nil {
			return err
		}
		if st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&022 != 0 {
			return errors.New("the runtime artifact parent custody differs")
		}
		if path == "/" {
			return nil
		}
	}
}
func sameArtifact(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}

// VerifyExecutable measures one root-owned regular file through a retained FD.
// It rejects linked paths and writable parents before it hashes the bounded file.
func VerifyExecutable(path, expected string) error { return verifyFile(path, expected, 1<<30, true) }

// VerifyDataFile measures a bounded immutable object without granting execution.
func VerifyDataFile(path, expected string, maximum int64) error {
	if maximum <= 0 || maximum > 1<<30 {
		return errors.New("the immutable artifact size bound is invalid")
	}
	return verifyFile(path, expected, maximum, false)
}

func verifyFile(path, expected string, maximum int64, executable bool) error {
	decoded, err := hex.DecodeString(expected)
	if !canonical(path) || err != nil || len(decoded) != 32 || expected != strings.ToLower(expected) {
		return errors.New("the runtime artifact requires a canonical path and exact digest")
	}
	if err = privateParents(path); err != nil {
		return err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	var first, last unix.Stat_t
	if err = unix.Fstat(fd, &first); err != nil {
		return err
	}
	if first.Mode&unix.S_IFMT != unix.S_IFREG || (executable && first.Mode&0111 == 0) || first.Uid != 0 || first.Mode&022 != 0 || first.Size <= 0 || first.Size > maximum {
		return errors.New("the immutable executable custody or size differs")
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(file, first.Size+1))
	if err != nil {
		return err
	}
	if count != first.Size || hex.EncodeToString(hash.Sum(nil)) != expected {
		return errors.New("the actual runtime executable digest differs")
	}
	if err = unix.Fstat(fd, &last); err != nil {
		return err
	}
	if !sameArtifact(first, last) {
		return errors.New("the runtime executable changed during measurement")
	}
	return nil
}

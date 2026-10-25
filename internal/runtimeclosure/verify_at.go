// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package runtimeclosure

import (
	"context"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

const targetResolve = unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS

func targetParents(root int, path string) error {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		fd, err := unix.Openat2(root, parent, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: targetResolve,
		})
		if err != nil {
			return ErrCustody
		}
		var st unix.Stat_t
		err = unix.Fstat(fd, &st)
		_ = unix.Close(fd)
		if err != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 {
			return ErrCustody
		}
		if parent == "/" {
			return nil
		}
	}
}

func targetOpen(root int, expected File) (retained, error) {
	if targetParents(root, expected.Path) != nil {
		return retained{}, ErrCustody
	}
	fd, err := unix.Openat2(root, expected.Path, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
		Resolve: targetResolve,
	})
	if err != nil {
		return retained{}, ErrCustody
	}
	file := os.NewFile(uintptr(fd), expected.Path)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !exact(st, expected) {
		_ = file.Close()
		return retained{}, ErrCustody
	}
	return retained{expected: expected, file: file, initial: st}, nil
}

// VerifyAt hashes a runtime closure under a retained Docker root descriptor.
// The caller must first measure the Docker image and its read-only root.
func (s Set) VerifyAt(ctx context.Context, root *os.File) (Measurement, error) {
	if ctx == nil || root == nil || s.digest == "" {
		return Measurement{}, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return Measurement{}, err
	}
	var rootStat unix.Stat_t
	if unix.Fstat(int(root.Fd()), &rootStat) != nil || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return Measurement{}, ErrCustody
	}
	opened := []retained{}
	defer func() {
		for _, file := range opened {
			_ = file.file.Close()
		}
	}()
	for _, expected := range s.files {
		if err := ctx.Err(); err != nil {
			return Measurement{}, err
		}
		file, err := targetOpen(int(root.Fd()), expected)
		if err != nil {
			return Measurement{}, err
		}
		opened = append(opened, file)
		actual, err := hashFile(ctx, file.file, expected.Bytes)
		if err != nil || actual != expected.SHA256 {
			return Measurement{}, ErrDigest
		}
	}
	for _, file := range opened {
		if err := ctx.Err(); err != nil {
			return Measurement{}, err
		}
		again, err := targetOpen(int(root.Fd()), file.expected)
		if err != nil {
			return Measurement{}, ErrChanged
		}
		var current unix.Stat_t
		stablePath := unix.Fstat(int(again.file.Fd()), &current) == nil && stable(file.initial, current)
		_ = again.file.Close()
		if !stablePath || unix.Fstat(int(file.file.Fd()), &current) != nil || !stable(file.initial, current) {
			return Measurement{}, ErrChanged
		}
		if _, err = file.file.Seek(0, io.SeekStart); err != nil {
			return Measurement{}, ErrChanged
		}
		actual, err := hashFile(ctx, file.file, file.expected.Bytes)
		if err != nil || actual != file.expected.SHA256 {
			return Measurement{}, ErrChanged
		}
	}
	var finalRoot unix.Stat_t
	if unix.Fstat(int(root.Fd()), &finalRoot) != nil || !stable(rootStat, finalRoot) {
		return Measurement{}, ErrChanged
	}
	return Measurement{Protocol: Version, Digest: s.digest, Files: s.Files(), TotalBytes: s.total}, nil
}

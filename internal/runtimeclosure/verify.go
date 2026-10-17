// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package runtimeclosure

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type retained struct {
	expected File
	file     *os.File
	initial  unix.Stat_t
}
type fileHasher func(context.Context, *os.File, int64) (string, error)

func parents(path string) error {
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		var st unix.Stat_t
		if unix.Lstat(parent, &st) != nil || st.Uid != 0 || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0022 != 0 {
			return ErrCustody
		}
		if parent == "/" {
			return nil
		}
	}
}
func exact(st unix.Stat_t, f File) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == 0 && st.Gid == f.GID && st.Mode&07777 == f.Mode && st.Mode&0022 == 0 && st.Nlink == 1 && st.Size == f.Bytes
}
func stable(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid && a.Size == b.Size && a.Nlink == b.Nlink && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}
func openFile(f File) (retained, error) {
	var first, opened unix.Stat_t
	if parents(f.Path) != nil || unix.Lstat(f.Path, &first) != nil || !exact(first, f) {
		return retained{}, ErrCustody
	}
	fd, err := unix.Open(f.Path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return retained{}, ErrCustody
	}
	file := os.NewFile(uintptr(fd), f.Path)
	if unix.Fstat(fd, &opened) != nil || !stable(first, opened) {
		file.Close()
		return retained{}, ErrChanged
	}
	return retained{f, file, first}, nil
}
func hashFile(ctx context.Context, file *os.File, expected int64) (string, error) {
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var count int64
	for {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		n, err := file.Read(buffer)
		if n > 0 {
			count += int64(n)
			if count > expected {
				return "", ErrChanged
			}
			_, _ = hash.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", ErrCustody
		}
	}
	if count != expected {
		return "", ErrChanged
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func (f retained) unchanged() error {
	var opened, current unix.Stat_t
	if unix.Fstat(int(f.file.Fd()), &opened) != nil || unix.Lstat(f.expected.Path, &current) != nil || parents(f.expected.Path) != nil || !stable(f.initial, opened) || !stable(f.initial, current) || !exact(current, f.expected) {
		return ErrChanged
	}
	return nil
}

// Verify retains every file descriptor until the complete set passes readback.
// It returns metadata only. The caller must bind the digest to its signed job.
func (s Set) Verify(ctx context.Context) (Measurement, error) { return s.verify(ctx, hashFile) }
func (s Set) verify(ctx context.Context, hash fileHasher) (Measurement, error) {
	if ctx == nil || s.digest == "" {
		return Measurement{}, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return Measurement{}, err
	}
	opened := []retained{}
	defer func() {
		for _, file := range opened {
			file.file.Close()
		}
	}()
	for _, expected := range s.files {
		if err := ctx.Err(); err != nil {
			return Measurement{}, err
		}
		file, err := openFile(expected)
		if err != nil {
			return Measurement{}, err
		}
		opened = append(opened, file)
		digest, err := hash(ctx, file.file, expected.Bytes)
		if err != nil {
			return Measurement{}, err
		}
		if digest != expected.SHA256 {
			return Measurement{}, ErrDigest
		}
	}
	for _, file := range opened {
		if err := ctx.Err(); err != nil {
			return Measurement{}, err
		}
		if err := file.unchanged(); err != nil {
			return Measurement{}, err
		}
		// A same-size write can reuse coarse inode timestamps. Rehash each
		// retained descriptor after the complete first pass.
		if _, err := file.file.Seek(0, io.SeekStart); err != nil {
			return Measurement{}, ErrChanged
		}
		digest, err := hashFile(ctx, file.file, file.expected.Bytes)
		if err != nil {
			return Measurement{}, err
		}
		if digest != file.expected.SHA256 || file.unchanged() != nil {
			return Measurement{}, ErrChanged
		}
	}
	if err := ctx.Err(); err != nil {
		return Measurement{}, err
	}
	return Measurement{Protocol: Version, Digest: s.digest, Files: s.Files(), TotalBytes: s.total}, nil
}

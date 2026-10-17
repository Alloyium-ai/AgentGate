// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobartifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

const TreeVersion = "agentgate.immutable-tree.v1"
const MaxTreeEntries = 20000
const MaxTreeBytes = int64(1 << 30)
const MaxTreeFileBytes = int64(64 << 20)

type treeEntry struct {
	Path, Kind     string
	Mode           uint32
	GID            uint32
	Size           int64
	SHA256, Target string
}

func treeMetadata(path string) (unix.Stat_t, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return st, err
	}
	if st.Uid != 0 {
		return st, errors.New("the immutable tree entry owner differs")
	}
	kind := st.Mode & unix.S_IFMT
	if kind != unix.S_IFLNK && st.Mode&022 != 0 {
		return st, errors.New("an immutable tree entry permits external writes")
	}
	if kind != unix.S_IFDIR && kind != unix.S_IFREG && kind != unix.S_IFLNK {
		return st, errors.New("the immutable tree contains an unsupported object")
	}
	return st, nil
}
func treeFile(ctx context.Context, path string, expected unix.Stat_t) (string, error) {
	if expected.Size < 0 || expected.Size > MaxTreeFileBytes || expected.Nlink != 1 {
		return "", errors.New("the immutable file size or link count differs")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var got unix.Stat_t
	if err = unix.Fstat(fd, &got); err != nil {
		return "", err
	}
	if got.Dev != expected.Dev || got.Ino != expected.Ino || got.Mode != expected.Mode || got.Uid != expected.Uid || got.Gid != expected.Gid || got.Size != expected.Size {
		return "", errors.New("the immutable file inode changed")
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	var size int64
	for {
		if err = ctx.Err(); err != nil {
			return "", err
		}
		n, e := f.Read(buffer)
		if n > 0 {
			size += int64(n)
			if size > MaxTreeFileBytes {
				return "", errors.New("the immutable file exceeds its bound")
			}
			_, _ = hash.Write(buffer[:n])
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return "", e
		}
	}
	if size != expected.Size {
		return "", errors.New("the immutable file changed size")
	}
	if err = unix.Fstat(fd, &got); err != nil {
		return "", err
	}
	if got.Mtim != expected.Mtim || got.Ctim != expected.Ctim || got.Size != expected.Size {
		return "", errors.New("the immutable file changed during measurement")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func measureEntry(ctx context.Context, root, path, relative string) (treeEntry, error) {
	st, err := treeMetadata(path)
	if err != nil {
		return treeEntry{}, err
	}
	entry := treeEntry{Path: relative, Mode: st.Mode & 0777, GID: st.Gid}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		entry.Kind = "directory"
	case unix.S_IFREG:
		entry.Kind = "file"
		entry.Size = st.Size
		entry.SHA256, err = treeFile(ctx, path, st)
	case unix.S_IFLNK:
		entry.Kind = "symlink"
		entry.Mode = 0
		entry.Target, err = os.Readlink(path)
		if err != nil {
			break
		}
		target, e := filepath.EvalSymlinks(path)
		if e != nil {
			return entry, e
		}
		if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
			return entry, errors.New("the immutable tree link leaves its package root")
		}
		if !utf8.ValidString(entry.Target) || strings.ContainsAny(entry.Target, "\x00\n\r") {
			return entry, errors.New("the immutable tree link target is ambiguous")
		}
	}
	return entry, err
}

// DigestTree includes sorted relative paths, types, modes, groups, file bytes
// and contained symlink targets. Absolute mount paths and timestamps add no data.
func DigestTree(ctx context.Context, root string) (string, error) {
	if ctx == nil || !canonical(root) {
		return "", errors.New("a canonical immutable package root is required")
	}
	if err := privateParents(filepath.Join(root, "entry")); err != nil {
		return "", err
	}
	initial, err := treeMetadata(root)
	if err != nil {
		return "", err
	}
	if initial.Mode&unix.S_IFMT != unix.S_IFDIR {
		return "", errors.New("the immutable package root is not a directory")
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(TreeVersion + "\n"))
	count := 0
	var size int64
	err = walkTree(ctx, root, 0, func(path string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if !utf8.ValidString(relative) || strings.ContainsAny(relative, "\x00\n\r") || len(relative) > 4096 {
			return errors.New("the immutable package path is ambiguous or excessive")
		}
		count++
		if count > MaxTreeEntries {
			return errors.New("the immutable tree entry bound is exceeded")
		}
		entry, err := measureEntry(ctx, root, path, relative)
		if err != nil {
			return err
		}
		size += entry.Size
		if size > MaxTreeBytes {
			return errors.New("the immutable tree byte bound is exceeded")
		}
		raw, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		_, _ = hash.Write(raw)
		_, _ = hash.Write([]byte("\n"))
		return nil
	})
	if err != nil {
		return "", err
	}
	current, err := treeMetadata(root)
	if err != nil {
		return "", err
	}
	if current.Dev != initial.Dev || current.Ino != initial.Ino || current.Mtim != initial.Mtim || current.Ctim != initial.Ctim {
		return "", errors.New("the immutable package root changed during measurement")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
func VerifyTree(ctx context.Context, root, expected string) error {
	if !validSHA(expected) {
		return errors.New("the immutable package digest is invalid")
	}
	got, err := DigestTree(ctx, root)
	if err != nil {
		return err
	}
	if got != expected {
		return errors.New("the immutable package bytes differ from the enrolled digest")
	}
	return nil
}
func validSHA(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == value
}

func walkTree(ctx context.Context, path string, depth int, visit func(string) error) error {
	if depth > 32 {
		return errors.New("the immutable tree depth bound is exceeded")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := visit(path); err != nil {
		return err
	}
	st, err := treeMetadata(path)
	if err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	entries, err := f.ReadDir(MaxTreeEntries + 1)
	closeErr := f.Close()
	if err != nil && err != io.EOF {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) > MaxTreeEntries {
		return errors.New("the immutable directory entry bound is exceeded")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if err = walkTree(ctx, filepath.Join(path, entry.Name()), depth+1, visit); err != nil {
			return err
		}
	}
	return nil
}

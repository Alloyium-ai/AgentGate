//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package credentialstage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"golang.org/x/sys/unix"
)

const requiredSeals = unix.F_SEAL_SEAL | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_WRITE
const requiredFlags = unix.ST_RDONLY | unix.ST_NOEXEC | unix.ST_NOSUID | unix.ST_NODEV

func procFD(fd int) string { return "/proc/thread-self/fd/" + strconv.Itoa(fd) }

func namespaceFile() (*os.File, unix.Stat_t, error) {
	f, err := os.Open("/proc/thread-self/ns/mnt")
	if err != nil {
		return nil, unix.Stat_t{}, errors.New("mount namespace descriptor is unavailable")
	}
	var stat unix.Stat_t
	kind, kindErr := unix.IoctlRetInt(int(f.Fd()), unix.NS_GET_NSTYPE)
	if unix.Fstat(int(f.Fd()), &stat) != nil || kindErr != nil || kind != unix.CLONE_NEWNS {
		f.Close()
		return nil, unix.Stat_t{}, errors.New("mount namespace descriptor identity is invalid")
	}
	return f, stat, nil
}

func (s *Stage) prepareNamespace(ctx context.Context) error {
	original, before, err := namespaceFile()
	if err != nil {
		return err
	}
	defer original.Close()
	if err = unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return errors.New("private credential mount namespace cannot create")
	}
	if err = unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return errors.New("credential namespace propagation cannot become private")
	}
	ns, after, err := namespaceFile()
	if err != nil {
		return err
	}
	s.namespace = ns
	if before.Dev == after.Dev && before.Ino == after.Ino {
		return errors.New("credential namespace did not separate from its parent")
	}
	s.measurement.NamespaceDevice, s.measurement.NamespaceInode = uint64(after.Dev), after.Ino
	for _, pinned := range s.pinned {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = s.mountCredential(pinned); err != nil {
			return err
		}
	}
	return nil
}

// pinTarget traverses every component with O_NOFOLLOW in the new namespace.
// Root ownership and non-writable parents prevent runtime rename substitution.
// The placeholder has no bytes and cannot supply another credential on failure.
func pinTarget(path string) (*os.File, *os.File, unix.Stat_t, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || path == "/tmp" || strings.HasPrefix(path, "/tmp/") || strings.ContainsRune(path, 0) {
		return nil, nil, unix.Stat_t{}, errors.New("credential target path is invalid")
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, unix.Stat_t{}, errors.New("credential target root is unavailable")
	}
	parent := os.NewFile(uintptr(fd), "credential-parent")
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	for _, part := range parts[:len(parts)-1] {
		var stat unix.Stat_t
		if unix.Fstat(int(parent.Fd()), &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			parent.Close()
			return nil, nil, unix.Stat_t{}, errors.New("credential target parent is not protected")
		}
		next, e := unix.Openat(int(parent.Fd()), part, unix.O_PATH|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
		parent.Close()
		if e != nil {
			return nil, nil, unix.Stat_t{}, errors.New("credential target parent cannot pin without links")
		}
		parent = os.NewFile(uintptr(next), "credential-parent")
	}
	var stat unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &stat) != nil || stat.Uid != 0 || stat.Mode&0022 != 0 {
		parent.Close()
		return nil, nil, unix.Stat_t{}, errors.New("credential target parent is not protected")
	}
	targetFD, err := unix.Openat(int(parent.Fd()), parts[len(parts)-1], unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		parent.Close()
		return nil, nil, unix.Stat_t{}, errors.New("credential target placeholder is unavailable")
	}
	target := os.NewFile(uintptr(targetFD), "credential-target")
	if unix.Fstat(targetFD, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != 0 || stat.Mode&0222 != 0 || stat.Nlink != 1 || stat.Size != 0 {
		target.Close()
		parent.Close()
		return nil, nil, unix.Stat_t{}, errors.New("credential target must be an empty protected regular placeholder")
	}
	return parent, target, stat, nil
}

func (s *Stage) mountCredential(pinned *lifecycle.PinnedCredential) error {
	seals, err := unix.FcntlInt(pinned.File.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&requiredSeals != requiredSeals {
		return errors.New("credential custody lost its required seals")
	}
	var source unix.Stat_t
	if unix.Fstat(int(pinned.File.Fd()), &source) != nil || source.Uid != pinned.RuntimeUID || source.Mode&0777 != 0400 {
		return errors.New("credential custody metadata differs")
	}
	parent, target, placeholder, err := pinTarget(pinned.Reference.ExposedPath)
	if err != nil {
		return err
	}
	s.targets = append(s.targets, parent, target)
	if err = unix.Mount(procFD(int(pinned.File.Fd())), procFD(int(target.Fd())), "", unix.MS_BIND, ""); err != nil {
		return errors.New("sealed credential descriptor cannot bind")
	}
	// Reopen only the mounted target through its retained protected parent.
	// The original target descriptor still names the covered placeholder.
	fd, err := unix.Openat(int(parent.Fd()), filepath.Base(pinned.Reference.ExposedPath), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("mounted credential identity cannot open")
	}
	mounted := os.NewFile(uintptr(fd), "credential-mount")
	s.targets = append(s.targets, mounted)
	if err = unix.Mount("", procFD(fd), "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOEXEC|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return errors.New("credential mount restrictions cannot apply")
	}
	var actual unix.Stat_t
	var fs unix.Statfs_t
	var statx unix.Statx_t
	actualSeals, sealErr := unix.FcntlInt(mounted.Fd(), unix.F_GET_SEALS, 0)
	if unix.Fstat(fd, &actual) != nil || actual.Dev != source.Dev || actual.Ino != source.Ino || actual.Mode != source.Mode || actual.Uid != source.Uid || unix.Fstatfs(fd, &fs) != nil || uint64(fs.Flags)&uint64(requiredFlags) != uint64(requiredFlags) || sealErr != nil || actualSeals != seals || unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &statx) != nil || statx.Mask&unix.STATX_MNT_ID == 0 {
		return errors.New("credential mount identity or restrictions differ from sealed custody")
	}
	info, err := os.ReadFile("/proc/thread-self/mountinfo")
	if err != nil || verifyPrivateMount(info, statx.Mnt_id) != nil {
		return errors.New("credential mount private propagation cannot verify")
	}
	s.measurement.Files = append(s.measurement.Files, FileMeasurement{ReferenceID: pinned.Reference.ID, ExposedPath: pinned.Reference.ExposedPath, Digest: pinned.Reference.Digest, Seals: seals, MountFlags: uint64(fs.Flags), MountID: statx.Mnt_id, Device: uint64(actual.Dev), Inode: actual.Ino, TargetDevice: uint64(placeholder.Dev), TargetInode: placeholder.Ino, Private: true})
	return nil
}

func verifyPrivateMount(raw []byte, mountID uint64) error {
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] != strconv.FormatUint(mountID, 10) {
			continue
		}
		separator := slices.Index(fields, "-")
		if separator < 6 {
			break
		}
		for _, field := range fields[6:separator] {
			if strings.HasPrefix(field, "shared:") || strings.HasPrefix(field, "master:") || strings.HasPrefix(field, "propagate_from:") {
				return errors.New("credential mount has propagation peers")
			}
		}
		options := strings.Split(fields[5], ",")
		for _, required := range []string{"ro", "noexec", "nosuid", "nodev"} {
			if !slices.Contains(options, required) {
				return errors.New("credential mount options are incomplete")
			}
		}
		return nil
	}
	return errors.New("credential mount ID is absent from namespace readback")
}

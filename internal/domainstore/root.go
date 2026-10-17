// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package domainstore

import (
	"bufio"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MeasureRoot supplies facts only. A trusted node qualification must bind these
// facts and its independent receipt before Config can qualify execution.
func MeasureRoot(prefix, receipt string) (RootProof, error) {
	canonical, pathErr := filepath.EvalSymlinks(RootPath)
	if pathErr != nil || canonical != RootPath {
		return RootProof{}, errors.New("the cgroup root path is linked or unavailable")
	}
	p := RootProof{MountRoot: "/", MountPoint: RootPath, JobDepth: 1, OwnedPrefix: prefix, QualificationReceiptDigest: receipt}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return p, errors.New("the current boot identity is unavailable")
	}
	p.BootID = strings.TrimSpace(string(boot))
	fd, err := unix.Open(RootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return p, errors.New("the cgroup root is unavailable")
	}
	defer unix.Close(fd)
	var info unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &info) != nil || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || info.Uid != 0 || info.Mode&0022 != 0 {
		return p, errors.New("the cgroup root custody differs")
	}
	p.Device = uint64(info.Dev)
	p.RootInode = info.Ino
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return p, errors.New("the cgroup mount identity is unavailable")
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	found := false
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || fields[4] != RootPath {
			continue
		}
		separator := 0
		for i, value := range fields {
			if value == "-" {
				separator = i
				break
			}
		}
		if separator == 0 || separator+1 >= len(fields) || fields[separator+1] != "cgroup2" || fields[3] != "/" || found {
			return p, errors.New("the cgroup mount is ambiguous or nested")
		}
		p.MountID, err = strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return p, errors.New("the cgroup mount identity is invalid")
		}
		found = true
	}
	if scanner.Err() != nil || !found {
		return p, errors.New("the root cgroup mount is unavailable")
	}
	for _, entry := range []struct {
		path          string
		device, inode *uint64
	}{{"/proc/self/ns/cgroup", &p.NamespaceDevice, &p.NamespaceInode}, {"/proc/1/ns/cgroup", &p.InitNamespaceDevice, &p.InitNamespaceInode}} {
		if unix.Stat(entry.path, &info) != nil {
			return p, errors.New("the cgroup namespace identity is unavailable")
		}
		*entry.device = uint64(info.Dev)
		*entry.inode = info.Ino
	}
	return p, p.validate()
}
func (s *Store) root() (int, error) {
	proof, err := MeasureRoot(s.config.Proof.OwnedPrefix, s.config.Proof.QualificationReceiptDigest)
	if err != nil || proof != s.config.Proof {
		return -1, errors.New("the qualified cgroup root or namespace changed")
	}
	fd, err := unix.Open(RootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, errors.New("the cgroup root cannot open")
	}
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Ino != proof.RootInode || uint64(info.Dev) != proof.Device {
		unix.Close(fd)
		return -1, errors.New("the cgroup root inode changed")
	}
	return fd, nil
}

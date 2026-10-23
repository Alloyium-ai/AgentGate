// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// HostMountRoot is the only container directory that may hold host folder
// mounts. A mount grants nothing by itself: the command's filesystem policy
// decides whether a path below it may be read, written or executed.
const HostMountRoot = "/var/lib/agentgate/mounts"

// MaxHostMounts bounds the operator-approved host folders per target.
const MaxHostMounts = 8

var hostMountName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// Host trees that may never be bound into a target, or contain a bound tree.
var protectedHostTrees = []string{
	"/proc", "/sys", "/dev", "/run", "/var/run", "/etc", "/root", "/boot",
	"/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
	"/var/lib/docker", "/var/lib/containerd",
}

// HostMount is one operator-approved bind mount of a Docker host directory.
type HostMount struct {
	Path     string `json:"path"`
	Source   string `json:"source"`
	ReadOnly bool   `json:"read_only"`
}

// HostMountMeasurement binds a mounted directory to its measured identity.
type HostMountMeasurement struct {
	Path     string `json:"path"`
	Device   uint64 `json:"device"`
	Inode    uint64 `json:"inode"`
	ReadOnly bool   `json:"read_only"`
}

func overlaps(a, b string) bool {
	if a == "/" || b == "/" {
		return true
	}
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

func validateHostMounts(t Target) error {
	if len(t.HostMounts) > MaxHostMounts {
		return fmt.Errorf("the Docker target allows at most %d host folder mounts", MaxHostMounts)
	}
	containerPaths := []string{t.Workspace}
	hostPaths := []string{t.WorkspaceSource, filepath.Dir(t.SocketPath)}
	for _, path := range []string{t.ArtifactPath, t.BridgePath} {
		if path != "" {
			containerPaths = append(containerPaths, path)
		}
	}
	for _, path := range []string{t.ArtifactSource, t.BridgeSource} {
		if path != "" {
			hostPaths = append(hostPaths, path)
		}
	}
	for _, mounted := range t.HostMounts {
		name := strings.TrimPrefix(mounted.Path, HostMountRoot+"/")
		if !absolute(mounted.Path) || !absolute(mounted.Source) || !hostMountName.MatchString(name) ||
			mounted.Path != HostMountRoot+"/"+name {
			return errors.New("a host folder mount requires a canonical source and " + HostMountRoot + "/NAME")
		}
		for _, protected := range protectedHostTrees {
			if overlaps(mounted.Source, protected) {
				return fmt.Errorf("host folder %s overlaps protected host tree %s", mounted.Source, protected)
			}
		}
		for _, other := range containerPaths {
			if overlaps(mounted.Path, other) {
				return errors.New("a host folder mount overlaps another target mount")
			}
		}
		for _, other := range hostPaths {
			if overlaps(mounted.Source, other) {
				return errors.New("a host folder source overlaps another target source")
			}
		}
		containerPaths = append(containerPaths, mounted.Path)
		hostPaths = append(hostPaths, mounted.Source)
	}
	return nil
}

// matchHostMount accepts one Docker inspect mount only when it is exactly an
// approved bind with the approved write mode. Each approval matches once.
func matchHostMount(t Target, mounted mount, used []bool) bool {
	for index, approved := range t.HostMounts {
		if !used[index] && mounted.Type == "bind" && mounted.Destination == approved.Path &&
			mounted.Source == approved.Source && mounted.RW == !approved.ReadOnly {
			used[index] = true
			return true
		}
	}
	return false
}

type mountEntry struct {
	point   string
	options []string
}

// unescapeMountinfo decodes the octal escapes the kernel uses for space, tab,
// newline and backslash in /proc/PID/mountinfo paths.
func unescapeMountinfo(value string) (string, error) {
	var out strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			out.WriteByte(value[index])
			continue
		}
		if index+4 > len(value) {
			return "", errors.New("the mountinfo escape is truncated")
		}
		code, err := strconv.ParseUint(value[index+1:index+4], 8, 8)
		if err != nil {
			return "", errors.New("the mountinfo escape is invalid")
		}
		out.WriteByte(byte(code))
		index += 3
	}
	return out.String(), nil
}

func parseMountinfo(raw []byte) ([]mountEntry, error) {
	entries := []mountEntry{}
	for _, line := range strings.Split(string(raw), "\n") {
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			return nil, errors.New("a mountinfo record is incomplete")
		}
		point, err := unescapeMountinfo(fields[4])
		if err != nil {
			return nil, err
		}
		entries = append(entries, mountEntry{point: point, options: strings.Split(fields[5], ",")})
	}
	return entries, nil
}

// checkMountinfo requires each approved path to be one top-level mount with
// the approved kernel write mode, and no further mount below it. A symlink in
// the image that redirected the mount would leave the approved path unmounted.
func checkMountinfo(entries []mountEntry, approved []HostMount) error {
	for _, item := range approved {
		var top *mountEntry
		for index := range entries {
			entry := &entries[index]
			if entry.point == item.Path {
				top = entry
			} else if strings.HasPrefix(entry.point, item.Path+"/") {
				return fmt.Errorf("a further mount exists below host folder mount %s", item.Path)
			}
		}
		if top == nil {
			return fmt.Errorf("host folder mount %s is absent from the target mount table", item.Path)
		}
		readOnly := false
		for _, option := range top.options {
			if option == "ro" {
				readOnly = true
			}
		}
		if item.ReadOnly && !readOnly {
			return fmt.Errorf("host folder mount %s is not read-only in the kernel", item.Path)
		}
	}
	return nil
}

// measureHostMounts binds each approved directory to the target's view of it.
func measureHostMounts(t Target, pid int) ([]HostMountMeasurement, error) {
	if len(t.HostMounts) == 0 {
		return nil, nil
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", pid))
	if err != nil {
		return nil, err
	}
	entries, err := parseMountinfo(raw)
	if err != nil {
		return nil, err
	}
	if err = checkMountinfo(entries, t.HostMounts); err != nil {
		return nil, err
	}
	out := []HostMountMeasurement{}
	for _, item := range t.HostMounts {
		inside, insideErr := os.Stat(fmt.Sprintf("/proc/%d/root%s", pid, item.Path))
		if insideErr != nil {
			return nil, insideErr
		}
		source, sourceErr := os.Lstat(item.Source)
		if sourceErr != nil {
			return nil, sourceErr
		}
		resolved, resolveErr := filepath.EvalSymlinks(item.Source)
		x, xok := inside.Sys().(*syscall.Stat_t)
		y, yok := source.Sys().(*syscall.Stat_t)
		if resolveErr != nil || resolved != item.Source || !xok || !yok || !inside.IsDir() || !source.IsDir() ||
			x.Dev != y.Dev || x.Ino != y.Ino {
			return nil, fmt.Errorf("host folder mount %s custody differs", item.Path)
		}
		out = append(out, HostMountMeasurement{Path: item.Path, Device: uint64(x.Dev), Inode: x.Ino, ReadOnly: item.ReadOnly})
	}
	return out, nil
}

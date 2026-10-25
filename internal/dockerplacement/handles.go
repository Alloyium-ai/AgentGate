// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Handles retain the measured namespace and root descriptors. Only the trusted
// node may hold them. A workload must never receive the Docker API socket.
type Handles struct {
	Measurement Measurement
	Mount       *os.File
	Network     *os.File
	PID         *os.File
	Root        *os.File
}

func (h *Handles) Close() error {
	var result error
	for _, file := range []*os.File{h.Mount, h.Network, h.PID, h.Root} {
		if file != nil {
			result = errors.Join(result, file.Close())
		}
	}
	h.Mount, h.Network, h.PID, h.Root = nil, nil, nil, nil
	return result
}

func namespaceHandle(pid int, kind, expected string, namespaceType int) (*os.File, error) {
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/ns/%s", pid, kind), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "measured "+kind+" namespace")
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil {
		file.Close()
		return nil, err
	}
	actualType, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.NS_GET_NSTYPE, 0)
	if errno != 0 || int(actualType) != namespaceType || expected != fmt.Sprintf("%s:[%d]", kind, stat.Ino) {
		file.Close()
		return nil, errors.New("the Docker namespace handle differs from its measured identity")
	}
	return file, nil
}

// Open remeasures the target, then retains exact namespace and root handles.
// The caller must keep them outside workload rights and recheck placement.
func Open(ctx context.Context, target Target) (out *Handles, err error) {
	measurement, err := Measure(ctx, target)
	if err != nil {
		return nil, err
	}
	h := &Handles{Measurement: measurement}
	defer func() {
		if err != nil {
			_ = h.Close()
		}
	}()
	for _, item := range []struct {
		kind   string
		typeID int
		field  **os.File
	}{
		{"mnt", unix.CLONE_NEWNS, &h.Mount},
		{"net", unix.CLONE_NEWNET, &h.Network},
		{"pid", unix.CLONE_NEWPID, &h.PID},
	} {
		*item.field, err = namespaceHandle(measurement.HostPID, item.kind, measurement.Namespaces[item.kind], item.typeID)
		if err != nil {
			return nil, err
		}
	}
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/root", measurement.HostPID), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	h.Root = os.NewFile(uintptr(fd), "measured Docker root")
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return nil, errors.New("the Docker target root descriptor differs")
	}
	var currentRoot unix.Stat_t
	if err = unix.Stat(fmt.Sprintf("/proc/%d/root", measurement.HostPID), &currentRoot); err != nil ||
		currentRoot.Dev != stat.Dev || currentRoot.Ino != stat.Ino {
		return nil, errors.New("the Docker target root changed during handle custody")
	}
	again, err := startTime(measurement.HostPID)
	if err != nil || again != measurement.StartTimeTicks {
		return nil, errors.New("the Docker target changed before handle custody")
	}
	for _, kind := range []string{"mnt", "net", "pid", "ipc", "uts"} {
		actual, readErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", measurement.HostPID, kind))
		if readErr != nil || actual != measurement.Namespaces[kind] {
			return nil, errors.New("the Docker target namespace changed before handle custody")
		}
	}
	return h, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strconv"
	"strings"
)

type LinuxDaemonMonitor struct{}

func ProcessStartTime(pid int) (uint64, error) {
	if pid <= 1 {
		return 0, errors.New("daemon PID is invalid")
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, errors.New("daemon process identity is unavailable")
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return 0, errors.New("daemon process identity is malformed")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 || fields[0] == "Z" || fields[0] == "X" {
		return 0, errors.New("daemon process is not alive")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return 0, errors.New("daemon start time is invalid")
	}
	return ticks, nil
}
func (LinuxDaemonMonitor) Alive(ctx context.Context, identity DaemonIdentity) error {
	if ctx.Err() != nil || identity.validate() != nil {
		return errors.New("daemon process identity is invalid")
	}
	fd, err := unix.PidfdOpen(identity.PID, 0)
	if err != nil {
		return errors.New("daemon process handle is unavailable")
	}
	defer unix.Close(fd)
	ticks, err := ProcessStartTime(identity.PID)
	if err != nil || ticks != identity.StartTimeTicks || unix.PidfdSendSignal(fd, 0, nil, 0) != nil {
		return errors.New("daemon process identity differs or ended")
	}
	return nil
}

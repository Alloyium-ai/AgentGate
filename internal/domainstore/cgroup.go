// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package domainstore

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

func openDomain(root int, name string) (int, uint64, error) {
	if strings.Contains(name, "/") || name == "" {
		return -1, 0, errors.New("the owned cgroup name is invalid")
	}
	fd, err := unix.Openat(root, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, 0, err
	}
	var info unix.Stat_t
	var fs unix.Statfs_t
	if unix.Fstat(fd, &info) != nil || info.Ino == 0 || info.Uid != 0 || info.Mode&0022 != 0 || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		unix.Close(fd)
		return -1, 0, errors.New("the owned cgroup custody is invalid")
	}
	return fd, info.Ino, nil
}
func readControl(fd int, name string) ([]byte, error) {
	opened, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("the cgroup readback cannot open")
	}
	file := os.NewFile(uintptr(opened), name)
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(raw) > 65536 {
		return nil, errors.New("the cgroup readback exceeds its bound")
	}
	return raw, nil
}
func writeControl(fd int, name, value string) error {
	opened, err := unix.Openat(fd, name, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("the cgroup control cannot open")
	}
	file := os.NewFile(uintptr(opened), name)
	defer file.Close()
	count, err := file.WriteString(value)
	if err != nil || count != len(value) {
		return errors.New("the cgroup control write failed")
	}
	return nil
}
func domainEmpty(fd int) (bool, []byte, error) {
	raw, err := readControl(fd, "cgroup.events")
	if err != nil {
		return false, nil, err
	}
	seen := false
	empty := false
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "populated" {
			if seen || (fields[1] != "0" && fields[1] != "1") {
				return false, nil, errors.New("the cgroup population readback is invalid")
			}
			seen = true
			empty = fields[1] == "0"
		}
	}
	if !seen {
		return false, nil, errors.New("the cgroup population readback is missing")
	}
	return empty, raw, nil
}
func stopDomain(ctx context.Context, fd int) (string, error) {
	digest, _, _, err := stopDomainRaw(ctx, fd)
	return digest, err
}
func stopDomainRaw(ctx context.Context, fd int) (string, []byte, uint64, error) {
	if err := writeControl(fd, "cgroup.kill", "1"); err != nil {
		return "", nil, 0, err
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		empty, raw, err := domainEmpty(fd)
		if err != nil {
			return "", nil, 0, err
		}
		if empty {
			mono, err := (lifecycle.MonotonicClock{}).NowNS()
			if err != nil {
				return "", nil, 0, err
			}
			sum := sha256.Sum256(append([]byte("agentgate-domain-empty-v1\n"), raw...))
			return hex.EncodeToString(sum[:]), raw, mono, nil
		}
		select {
		case <-ctx.Done():
			return "", nil, 0, errors.New("the whole owned cgroup remains populated")
		case <-ticker.C:
		}
	}
}
func stoppedProcess(process lifecycle.HeldProcess) error {
	if process.PID <= 1 || process.StartTimeTicks == 0 || !identifier.MatchString(process.BarrierID) {
		return errors.New("the held process identity is invalid")
	}
	ticks, err := lifecycle.ProcessStartTime(process.PID)
	if err != nil || ticks != process.StartTimeTicks {
		return errors.New("the held process start time differs")
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", process.PID))
	if err != nil {
		return errors.New("the held process state is unavailable")
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return errors.New("the held process state is invalid")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 || (fields[0] != "T" && fields[0] != "t") {
		return errors.New("the helper must remain stopped during placement")
	}
	tasks, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", process.PID))
	if err != nil || len(tasks) != 1 {
		return errors.New("the held helper must contain exactly one thread")
	}
	children, err := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", process.PID, process.PID))
	if err != nil || len(strings.TrimSpace(string(children))) != 0 {
		return errors.New("the held helper already has descendants")
	}
	return nil
}
func (s *Store) PlaceHeld(ctx context.Context, b lifecycle.Binding, process lifecycle.HeldProcess) (Placement, error) {
	if s.config.BarrierVerifier == nil || stoppedProcess(process) != nil {
		return Placement{}, errors.New("a measured stopped helper barrier is required")
	}
	root, err := s.root()
	if err != nil {
		return Placement{}, err
	}
	defer unix.Close(root)
	unlock, err := s.lock(ctx)
	if err != nil {
		return Placement{}, err
	}
	defer unlock()
	r, fd, err := s.exact(root, b)
	if err != nil {
		return Placement{}, err
	}
	defer unix.Close(fd)
	if r.Proof != s.config.Proof || r.State != "created" || r.Process != nil {
		return Placement{}, errors.New("the held domain placement already occurred")
	}
	if empty, _, emptyErr := domainEmpty(fd); emptyErr != nil || !empty {
		return Placement{}, errors.New("the held domain is not empty")
	}
	pidfd, err := unix.PidfdOpen(process.PID, 0)
	if err != nil {
		return Placement{}, errors.New("the held process handle is unavailable")
	}
	defer unix.Close(pidfd)
	if s.config.BarrierVerifier.VerifyHeld(ctx, b, process) != nil || stoppedProcess(process) != nil || unix.PidfdSendSignal(pidfd, 0, nil, 0) != nil {
		return Placement{}, errors.New("the measured helper barrier differs")
	}
	// Persist custody before the PID moves. Failure never grants execution.
	r.Process = &process
	if err = s.save(&r); err != nil {
		return Placement{}, err
	}
	if err = writeControl(fd, "cgroup.procs", strconv.Itoa(process.PID)); err != nil {
		return Placement{}, err
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", process.PID))
	if err != nil || strings.TrimSpace(string(raw)) != "0::/"+r.Name || stoppedProcess(process) != nil || s.config.BarrierVerifier.VerifyHeld(ctx, b, process) != nil || unix.PidfdSendSignal(pidfd, 0, nil, 0) != nil {
		return Placement{}, errors.New("the held process placement readback differs")
	}
	r.State = "placed"
	if err = s.save(&r); err != nil {
		return Placement{}, err
	}
	placement := Placement{Binding: copyValue(b), Process: process}
	bytes, _ := json.Marshal(placement)
	sum := sha256.Sum256(bytes)
	placement.ReadbackDigest = hex.EncodeToString(sum[:])
	return placement, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"golang.org/x/sys/unix"
)

func waitBootstrapReady(ctx context.Context, pid int, path, hash string) (processSnapshot, error) {
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if err := ctx.Err(); err != nil {
			return processSnapshot{}, err
		}
		s, err := inspectProcess(pid, path, hash)
		if err != nil {
			return s, err
		}
		fields := processFields(s.Status)
		if validateProcess(s, false, "2") == nil && fields["Seccomp_filters"] == "1" && strings.HasPrefix(fields["State"], "R") && len(s.Descriptors) == 0 {
			return s, nil
		}
		time.Sleep(time.Millisecond)
	}
	return processSnapshot{}, errors.New("the measured worker did not close its bootstrap descriptors")
}

func processFields(raw string) map[string]string {
	fields := map[string]string{}
	for _, line := range strings.Split(raw, "\n") {
		if key, value, ok := strings.Cut(line, ":"); ok {
			fields[key] = strings.TrimSpace(value)
		}
	}
	return fields
}
func validateProcess(s processSnapshot, stopped bool, seccomp string) error {
	f := processFields(s.Status)
	if s.PID <= 1 || s.StartTimeTicks == 0 || s.MonoNS == 0 || len(s.Tasks) != 1 || s.Tasks[0] != strconv.Itoa(s.PID) || strings.TrimSpace(s.Children) != "" {
		return errors.New("qualification actor identity or descendants differ")
	}
	for _, key := range []string{"Uid", "Gid"} {
		if strings.Join(strings.Fields(f[key]), " ") != "65534 65534 65534 65534" {
			return fmt.Errorf("qualification actor %s differs", key)
		}
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapAmb"} {
		value, err := strconv.ParseUint(f[key], 16, 64)
		if err != nil || value != 0 {
			return errors.New("qualification actor retains a capability")
		}
	}
	if f["Groups"] != "" || f["NoNewPrivs"] != "1" || f["Threads"] != "1" || f["Seccomp"] != seccomp {
		return errors.New("qualification actor profile readback differs")
	}
	if stopped && !strings.HasPrefix(f["State"], "T") && !strings.HasPrefix(f["State"], "t") {
		return errors.New("qualification actor is not held")
	}
	return nil
}
func inspectProcess(pid int, path, hash string) (processSnapshot, error) {
	s := processSnapshot{PID: pid, Executable: path, ExecutableSHA256: hash}
	var err error
	if err = jobartifacts.VerifyExecutable(path, hash); err != nil {
		return s, err
	}
	actual, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil || actual != path {
		return s, errors.New("the qualification actor executable differs")
	}
	if s.StartTimeTicks, err = lifecycle.ProcessStartTime(pid); err != nil {
		return s, err
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return s, err
	}
	s.Status = string(raw)
	raw, err = os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return s, err
	}
	s.Cgroup = string(raw)
	raw, err = os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", pid, pid))
	if err != nil {
		return s, err
	}
	s.Children = string(raw)
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		return s, err
	}
	for _, entry := range entries {
		s.Tasks = append(s.Tasks, entry.Name())
	}
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		return s, err
	}
	for _, fd := range fds {
		path := fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())
		target, e := os.Readlink(path)
		if e != nil {
			return s, e
		}
		var st unix.Stat_t
		if e = unix.Stat(path, &st); e != nil {
			return s, e
		}
		s.Descriptors = append(s.Descriptors, descriptorSnapshot{Number: fd.Name(), Target: target, Device: uint64(st.Dev), Inode: st.Ino, Mode: st.Mode, UID: st.Uid, GID: st.Gid, Links: st.Nlink})
	}
	s.MonoNS, err = kernel.MonotonicNS()
	return s, err
}
func waitHeld(pid int, path, hash string) (processSnapshot, error) {
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		s, err := inspectProcess(pid, path, hash)
		if err != nil {
			return s, err
		}
		if validateProcess(s, true, "2") == nil && processFields(s.Status)["Seccomp_filters"] == "1" && len(s.Descriptors) == 0 {
			return s, nil
		}
		time.Sleep(time.Millisecond)
	}
	return processSnapshot{}, errors.New("the qualification actor did not enter its measured hold")
}
func memberSnapshot(s processSnapshot, domain string) bool {
	return strings.TrimSpace(s.Cgroup) == "0::/"+filepath.Base(domain)
}

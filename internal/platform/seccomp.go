// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package platform

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ScalarFilter is a diagnostic filter. Its default allowance is never a job policy.
func ScalarFilter() []unix.SockFilter {
	return []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.AUDIT_ARCH_X86_64, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x40000000, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_GETPPID, Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
}

func scalarFixture() error {
	marker, err := os.ReadFile("/etc/alloyium-disposable-vm")
	if err != nil || os.Geteuid() != 0 || runtime.GOARCH != "amd64" || !strings.HasPrefix(strings.TrimSpace(string(marker)), "kernel-poc-agentgate-g0-") {
		return errors.New("seccomp probe requires the owned disposable G0 fixture")
	}
	return nil
}

// ProbeScalarChild installs its filter across every existing Go runtime thread.
// It proves one scalar syscall decision, not a full runtime or notification broker.
func ProbeScalarChild() (SeccompProbe, error) {
	result := SeccompProbe{Available: true}
	if err := scalarFixture(); err != nil {
		return result, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return result, err
	}
	filter := ScalarFilter()
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	value, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	if errno != 0 {
		return result, errno
	}
	if value != 0 {
		return result, errors.New("the seccomp filter did not synchronize every runtime thread")
	}
	result.FilterInstalled = true
	_, _, errno = unix.Syscall(unix.SYS_GETPPID, 0, 0, 0)
	if errno != unix.EPERM {
		return result, errors.New("the scalar getppid denial did not return EPERM")
	}
	pid, _, errno := unix.Syscall(unix.SYS_GETPID, 0, 0, 0)
	if errno != 0 || pid != uintptr(os.Getpid()) {
		return result, errors.New("the scalar filter changed an allowed syscall")
	}
	result.DecisionVerified = true
	return result, nil
}

func probeScalarProcess(executable string) SeccompProbe {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, executable, "--seccomp-scalar-child").Output()
	if err != nil {
		return SeccompProbe{Error: err.Error()}
	}
	var result SeccompProbe
	if err = json.Unmarshal(output, &result); err != nil {
		return SeccompProbe{Error: err.Error()}
	}
	return result
}

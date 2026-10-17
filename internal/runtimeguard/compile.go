// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package runtimeguard compiles explicit syscall rights. Resource hooks remain mandatory.
package runtimeguard

import (
	"alloyium.local/kernel-poc/internal/policy"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"golang.org/x/sys/unix"
)

const Purpose = "agentgate.explicit-seccomp-component.v1"
const deny = unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)

type Plan struct {
	filters []unix.SockFilter
	names   []string
	digest  string
	notify  bool
}

func (p Plan) Filters() []unix.SockFilter             { return append([]unix.SockFilter{}, p.filters...) }
func (p Plan) Names() []string                        { return append([]string{}, p.names...) }
func (p Plan) Digest() string                         { return p.digest }
func (p Plan) RequiresExecListener() bool             { return p.notify }
func statement(code uint16, k uint32) unix.SockFilter { return unix.SockFilter{Code: code, K: k} }
func jump(code uint16, k uint32, t, f uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, K: k, Jt: t, Jf: f}
}
func load(offset uint32) unix.SockFilter {
	return statement(unix.BPF_LD|unix.BPF_W|unix.BPF_ABS, offset)
}
func ret(value uint32) unix.SockFilter { return statement(unix.BPF_RET|unix.BPF_K, value) }
func arg(index uint32) uint32          { return 16 + index*8 }
func zeroHigh(index uint32) []unix.SockFilter {
	return []unix.SockFilter{load(arg(index) + 4), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 1, 0), ret(deny)}
}
func restrictedBits(index, allowed uint32) []unix.SockFilter {
	p := zeroHigh(index)
	return append(p, load(arg(index)), jump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, ^allowed, 0, 1), ret(deny))
}
func equalsAny(index uint32, values ...uint32) []unix.SockFilter {
	p := zeroHigh(index)
	p = append(p, load(arg(index)))
	for _, v := range values {
		p = append(p, jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, v, 0, 1), ret(unix.SECCOMP_RET_ALLOW))
	}
	return append(p, ret(deny))
}

// Compile grants exactly the requested supported calls and scalar subsets.
// It rejects pointer-based clone3 flags. Exec calls require a held notification broker.
func Compile(runtime policy.Runtime) (Plan, error) {
	var p Plan
	if err := policy.ValidateRuntimeSection(runtime); err != nil {
		return p, err
	}
	p.names = append([]string{}, runtime.Seccomp.AllowSyscalls...)
	sort.Strings(p.names)
	p.filters = []unix.SockFilter{load(4), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AUDIT_ARCH_X86_64, 1, 0), ret(unix.SECCOMP_RET_KILL_PROCESS), load(0), jump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, 0x40000000, 0, 1), ret(unix.SECCOMP_RET_KILL_PROCESS)}
	// clone3 stays denied. ENOSYS permits libc to try an independently allowed
	// scalar clone; the pointer-based clone3 arguments never authorize execution.
	p.filters = append(p.filters, load(0), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_CLONE3, 0, 1), ret(unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS)))
	for _, name := range p.names {
		if name == "eventfd2" && !eventFDOperation(runtime, "create") {
			return Plan{}, errors.New("eventfd2 requires an explicit eventfd creation allowance")
		}
		if name == "mremap" && !anonymousOperation(runtime, "map") {
			return Plan{}, errors.New("mremap requires an explicit anonymous mapping allowance")
		}
		if name == "brk" && (runtime.Memory == nil || runtime.Memory.Heap != "allow") {
			return Plan{}, errors.New("brk requires an explicit heap memory allowance")
		}
		if name == "pipe2" {
			create := false
			if runtime.IPC != nil {
				for _, op := range runtime.IPC.Pipes {
					create = create || op == "create"
				}
			}
			if !create {
				return Plan{}, errors.New("pipe2 requires an explicit anonymous pipe creation allowance")
			}
		}
		if (name == "kill" || name == "tkill" || name == "tgkill") && (runtime.Signals == nil || len(*runtime.Signals) == 0) {
			return Plan{}, errors.New("signal syscalls require explicit same-job signal permissions and a qualified task guard")
		}
		nr, ok := numbers[name]
		if !ok {
			return Plan{}, fmt.Errorf("syscall %s lacks a supported target compiler", name)
		}
		body, notify, err := callBody(name)
		if err != nil {
			return Plan{}, err
		}
		p.notify = p.notify || notify
		if len(body) > 255 {
			return Plan{}, errors.New("seccomp branch exceeds its checked jump bound")
		}
		p.filters = append(p.filters, load(0), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, nr, 0, uint8(len(body))))
		p.filters = append(p.filters, body...)
	}
	p.filters = append(p.filters, ret(deny))
	if len(p.filters) > 4096 {
		return Plan{}, errors.New("seccomp instruction limit exceeded")
	}
	raw, err := json.Marshal(runtime)
	if err != nil {
		return Plan{}, err
	}
	h := sha256.New()
	h.Write([]byte(Purpose + "\n" + policy.SchemaDigest() + "\n"))
	h.Write(raw)
	for _, f := range p.filters {
		_ = binary.Write(h, binary.LittleEndian, f)
	}
	p.digest = hex.EncodeToString(h.Sum(nil))
	return p, nil
}
func anonymousOperation(runtime policy.Runtime, operation string) bool {
	if runtime.Memory != nil {
		for _, allowed := range runtime.Memory.Anonymous {
			if allowed == operation {
				return true
			}
		}
	}
	return false
}
func eventFDOperation(runtime policy.Runtime, operation string) bool {
	if runtime.IPC != nil && runtime.IPC.EventFDs != nil {
		for _, allowed := range *runtime.IPC.EventFDs {
			if allowed == operation {
				return true
			}
		}
	}
	return false
}
func callBody(name string) ([]unix.SockFilter, bool, error) {
	var p []unix.SockFilter
	switch name {
	case "readlink", "readlinkat":
		return nil, false, fmt.Errorf("%s requires a qualified pathname guard; admission rejects this allowance", name)
	case "clone3":
		return nil, false, errors.New("clone3 pointer flags require a qualified broker; admission rejects this allowance")
	case "brk":
		// The broker checks the live heap bit, installed generation and cutoff.
		return []unix.SockFilter{ret(unix.SECCOMP_RET_USER_NOTIF)}, true, nil
	case "execve", "execveat":
		if name == "execveat" {
			p = restrictedBits(4, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW)
		}
		return append(p, ret(unix.SECCOMP_RET_USER_NOTIF)), true, nil
	case "clone":
		allowed := uint32(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_SIGHAND | unix.CLONE_THREAD | unix.CLONE_SYSVSEM | unix.CLONE_SETTLS | unix.CLONE_PARENT_SETTID | unix.CLONE_CHILD_CLEARTID | unix.CLONE_CHILD_SETTID | unix.CLONE_VFORK | 0xff)
		p = restrictedBits(0, allowed)
	case "openat":
		p = zeroHigh(2)
		p = append(p, load(arg(2)), jump(unix.BPF_JMP|unix.BPF_JSET|unix.BPF_K, unix.O_PATH, 0, 1), ret(deny))
	case "mmap":
		p = restrictedBits(2, unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC)
		p = append(p, restrictedBits(3, unix.MAP_SHARED|unix.MAP_PRIVATE|unix.MAP_FIXED|unix.MAP_ANON|unix.MAP_DENYWRITE|unix.MAP_EXECUTABLE|unix.MAP_NORESERVE|unix.MAP_POPULATE|unix.MAP_STACK|unix.MAP_FIXED_NOREPLACE)...)
	case "mprotect":
		p = restrictedBits(2, unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC)
	case "arch_prctl":
		return equalsAny(0, 0x1002, 0x1003, 0x1001, 0x1004), false, nil
	case "fcntl":
		return fcntlBody(), false, nil
	case "epoll_create1":
		p = restrictedBits(0, unix.EPOLL_CLOEXEC)
	case "epoll_ctl":
		return equalsAny(1, unix.EPOLL_CTL_ADD, unix.EPOLL_CTL_DEL, unix.EPOLL_CTL_MOD), false, nil
	case "eventfd2":
		p = restrictedBits(1, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK|unix.EFD_SEMAPHORE)
	case "mremap":
		p = restrictedBits(3, unix.MREMAP_MAYMOVE|unix.MREMAP_FIXED|unix.MREMAP_DONTUNMAP)
	case "madvise":
		return equalsAny(2, unix.MADV_NORMAL, unix.MADV_RANDOM, unix.MADV_SEQUENTIAL, unix.MADV_WILLNEED, unix.MADV_DONTNEED, unix.MADV_FREE, unix.MADV_DONTFORK, unix.MADV_DOFORK, unix.MADV_HUGEPAGE, unix.MADV_NOHUGEPAGE, unix.MADV_DONTDUMP, unix.MADV_COLD, unix.MADV_PAGEOUT, unix.MADV_WIPEONFORK, unix.MADV_KEEPONFORK), false, nil
	case "sched_getaffinity":
		return equalsAny(0, 0), false, nil
	case "getrusage":
		return equalsAny(0, unix.RUSAGE_SELF, unix.RUSAGE_THREAD), false, nil
	case "statx":
		p = restrictedBits(2, unix.AT_SYMLINK_NOFOLLOW|unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT|unix.AT_STATX_FORCE_SYNC|unix.AT_STATX_DONT_SYNC)
	case "prlimit64":
		for _, offset := range []uint32{arg(0), arg(0) + 4, arg(2), arg(2) + 4} {
			p = append(p, load(offset), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 1, 0), ret(deny))
		}
	case "socket":
		p = zeroHigh(0)
		p = append(p, load(arg(0)), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AF_INET, 2, 0), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.AF_INET6, 1, 0), ret(deny))
		p = append(p, zeroHigh(1)...)
		p = append(p, load(arg(1)), statement(unix.BPF_ALU|unix.BPF_AND|unix.BPF_K, ^(uint32(unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK))), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SOCK_STREAM, 2, 0), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SOCK_DGRAM, 1, 0), ret(deny))
	}
	return append(p, ret(unix.SECCOMP_RET_ALLOW)), false, nil
}

func fcntlBody() []unix.SockFilter {
	p := zeroHigh(1)
	for _, command := range []uint32{unix.F_GETFD, unix.F_GETFL, unix.F_DUPFD, unix.F_DUPFD_CLOEXEC, unix.F_SETFD, unix.F_SETFL} {
		body := []unix.SockFilter{}
		if command == unix.F_SETFD {
			body = restrictedBits(2, unix.FD_CLOEXEC)
		}
		if command == unix.F_SETFL {
			body = restrictedBits(2, unix.O_APPEND|unix.O_NONBLOCK|unix.O_ACCMODE|unix.O_LARGEFILE)
		}
		body = append(body, ret(unix.SECCOMP_RET_ALLOW))
		p = append(p, load(arg(1)), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, command, 0, uint8(len(body))))
		p = append(p, body...)
	}
	return append(p, ret(deny))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package runtimeguard

import (
	"alloyium.local/kernel-poc/internal/policy"
	"golang.org/x/sys/unix"
	"testing"
)

func TestNativeScalarBoundaries(t *testing.T) {
	r := runtimePolicy("fcntl", "epoll_create1", "epoll_ctl", "eventfd2", "mremap", "madvise", "sched_getaffinity", "statx")
	r.Memory = &policy.MemoryPolicy{Default: "deny", Anonymous: []string{"map", "read", "write"}, Heap: "deny"}
	eventfds := []string{"create"}
	r.IPC = &policy.IPCPolicy{Default: "deny", Pipes: []string{}, EventFDs: &eventfds}
	p, err := Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		nr    uint32
		args  [6]uint64
		allow bool
	}{{unix.SYS_FCNTL, [6]uint64{3, unix.F_SETFD, unix.FD_CLOEXEC}, true}, {unix.SYS_FCNTL, [6]uint64{3, unix.F_SETFD, 2}, false}, {unix.SYS_FCNTL, [6]uint64{3, unix.F_SETFL, unix.O_NONBLOCK | unix.O_RDWR}, true}, {unix.SYS_FCNTL, [6]uint64{3, unix.F_SETFL, unix.O_ASYNC}, false}, {unix.SYS_FCNTL, [6]uint64{3, unix.F_SETOWN, 42}, false}, {unix.SYS_EPOLL_CREATE1, [6]uint64{unix.EPOLL_CLOEXEC}, true}, {unix.SYS_EPOLL_CREATE1, [6]uint64{1}, false}, {unix.SYS_EPOLL_CTL, [6]uint64{3, unix.EPOLL_CTL_ADD}, true}, {unix.SYS_EPOLL_CTL, [6]uint64{3, 4}, false}, {unix.SYS_EVENTFD2, [6]uint64{0, unix.EFD_NONBLOCK | unix.EFD_CLOEXEC}, true}, {unix.SYS_EVENTFD2, [6]uint64{0, 1 << 15}, false}, {unix.SYS_MREMAP, [6]uint64{0, 4096, 8192, unix.MREMAP_MAYMOVE}, true}, {unix.SYS_MREMAP, [6]uint64{0, 4096, 8192, 1 << 31}, false}, {unix.SYS_MADVISE, [6]uint64{0, 4096, unix.MADV_DONTDUMP}, true}, {unix.SYS_MADVISE, [6]uint64{0, 4096, unix.MADV_HWPOISON}, false}, {unix.SYS_SCHED_GETAFFINITY, [6]uint64{}, true}, {unix.SYS_SCHED_GETAFFINITY, [6]uint64{42}, false}, {unix.SYS_STATX, [6]uint64{0, 0, unix.AT_SYMLINK_NOFOLLOW}, true}, {unix.SYS_STATX, [6]uint64{0, 0, 1 << 31}, false}} {
		want := uint32(deny)
		if test.allow {
			want = unix.SECCOMP_RET_ALLOW
		}
		if got := decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, test.nr, test.args); got != want {
			t.Fatalf("call%d args%v got%x want%x", test.nr, test.args, got, want)
		}
	}
}
func TestEventFDCreationNeedsItsSeparateExplicitRight(t *testing.T) {
	for _, ops := range [][]string{nil, {}, {"read"}, {"write"}} {
		r := runtimePolicy("eventfd2")
		r.IPC = &policy.IPCPolicy{Default: "deny", Pipes: []string{}}
		if ops != nil {
			r.IPC.EventFDs = &ops
		}
		if _, err := Compile(r); err == nil {
			t.Fatal("eventfd creation gained an implicit right")
		}
	}
	ops := []string{"create"}
	r := runtimePolicy("eventfd2")
	r.IPC = &policy.IPCPolicy{Default: "deny", Pipes: []string{}, EventFDs: &ops}
	p, err := Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	if decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, unix.SYS_EVENTFD2, [6]uint64{}) != unix.SECCOMP_RET_ALLOW {
		t.Fatal("the explicit create right disappeared")
	}
}
func TestRemapRequiresAnExplicitMemoryMappingRight(t *testing.T) {
	for _, memory := range []*policy.MemoryPolicy{nil, {Default: "deny", Anonymous: []string{}, Heap: "deny"}, {Default: "deny", Anonymous: []string{"read", "write"}, Heap: "deny"}} {
		r := runtimePolicy("mremap")
		r.Memory = memory
		if _, err := Compile(r); err == nil {
			t.Fatal("mremap gained an implicit mapping right")
		}
	}
}
func TestClone3DenialAllowsOnlyAnExplicitCloneFallback(t *testing.T) {
	for _, names := range [][]string{{}, {"clone"}} {
		p, err := Compile(runtimePolicy(names...))
		if err != nil {
			t.Fatal(err)
		}
		if got := decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, unix.SYS_CLONE3, [6]uint64{1, 1}); got != unix.SECCOMP_RET_ERRNO|uint32(unix.ENOSYS) {
			t.Fatal("clone3 was not denied with ENOSYS")
		}
		want := uint32(deny)
		if len(names) > 0 {
			want = unix.SECCOMP_RET_ALLOW
		}
		if got := decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, unix.SYS_CLONE, [6]uint64{}); got != want {
			t.Fatal("clone fallback gained an implicit right")
		}
	}
}
func TestPollingAndQueriesNeedExplicitNames(t *testing.T) {
	names := []string{"readv", "writev", "pread64", "pwrite64", "epoll_wait", "epoll_pwait", "epoll_pwait2", "poll", "ppoll", "uname", "sched_yield", "gettid", "getppid", "getrlimit", "getdents64", "getsockname", "getpeername"}
	empty, err := Compile(runtimePolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		p, err := Compile(runtimePolicy(name))
		if err != nil {
			t.Fatal(name, err)
		}
		nr := numbers[name]
		if decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, nr, [6]uint64{}) != unix.SECCOMP_RET_ALLOW || decide(t, empty.Filters(), unix.AUDIT_ARCH_X86_64, nr, [6]uint64{}) != deny {
			t.Fatal("the named call was implicit or unsupported", name)
		}
	}
}

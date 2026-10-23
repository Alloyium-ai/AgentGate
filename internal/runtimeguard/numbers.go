// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package runtimeguard

import "golang.org/x/sys/unix"

// The schema is the public call catalog. An absent compiler entry rejects admission.
var numbers = map[string]uint32{
	"readlink": unix.SYS_READLINK,
	"readv":    unix.SYS_READV, "writev": unix.SYS_WRITEV, "pread64": unix.SYS_PREAD64, "pwrite64": unix.SYS_PWRITE64,
	"epoll_create1": unix.SYS_EPOLL_CREATE1, "epoll_ctl": unix.SYS_EPOLL_CTL, "epoll_wait": unix.SYS_EPOLL_WAIT, "epoll_pwait": unix.SYS_EPOLL_PWAIT, "epoll_pwait2": unix.SYS_EPOLL_PWAIT2,
	"eventfd2": unix.SYS_EVENTFD2, "poll": unix.SYS_POLL, "ppoll": unix.SYS_PPOLL, "madvise": unix.SYS_MADVISE, "mremap": unix.SYS_MREMAP,
	"uname": unix.SYS_UNAME, "sched_yield": unix.SYS_SCHED_YIELD, "sched_getaffinity": unix.SYS_SCHED_GETAFFINITY, "gettid": unix.SYS_GETTID, "getppid": unix.SYS_GETPPID,
	"getrlimit": unix.SYS_GETRLIMIT, "getrusage": unix.SYS_GETRUSAGE, "getdents64": unix.SYS_GETDENTS64, "statx": unix.SYS_STATX,
	"getsockname": unix.SYS_GETSOCKNAME, "getpeername": unix.SYS_GETPEERNAME,
	"kill": unix.SYS_KILL, "tkill": unix.SYS_TKILL, "tgkill": unix.SYS_TGKILL,
	"read": unix.SYS_READ, "write": unix.SYS_WRITE, "close": unix.SYS_CLOSE, "openat": unix.SYS_OPENAT,
	"newfstatat": unix.SYS_NEWFSTATAT, "fstat": unix.SYS_FSTAT, "lseek": unix.SYS_LSEEK,
	"mmap": unix.SYS_MMAP, "mprotect": unix.SYS_MPROTECT, "munmap": unix.SYS_MUNMAP, "brk": unix.SYS_BRK,
	"rt_sigaction": unix.SYS_RT_SIGACTION, "rt_sigprocmask": unix.SYS_RT_SIGPROCMASK, "rt_sigreturn": unix.SYS_RT_SIGRETURN,
	"arch_prctl": unix.SYS_ARCH_PRCTL, "set_tid_address": unix.SYS_SET_TID_ADDRESS, "set_robust_list": unix.SYS_SET_ROBUST_LIST,
	"rseq": unix.SYS_RSEQ, "futex": unix.SYS_FUTEX, "getrandom": unix.SYS_GETRANDOM,
	"getpid": unix.SYS_GETPID, "getuid": unix.SYS_GETUID, "geteuid": unix.SYS_GETEUID, "getgid": unix.SYS_GETGID, "getegid": unix.SYS_GETEGID,
	"clock_gettime": unix.SYS_CLOCK_GETTIME, "exit": unix.SYS_EXIT, "exit_group": unix.SYS_EXIT_GROUP,
	"execve": unix.SYS_EXECVE, "execveat": unix.SYS_EXECVEAT, "clone": unix.SYS_CLONE, "clone3": unix.SYS_CLONE3, "wait4": unix.SYS_WAIT4,
	"socket": unix.SYS_SOCKET, "connect": unix.SYS_CONNECT, "bind": unix.SYS_BIND, "listen": unix.SYS_LISTEN, "accept": unix.SYS_ACCEPT, "accept4": unix.SYS_ACCEPT4,
	"sendto": unix.SYS_SENDTO, "recvfrom": unix.SYS_RECVFROM, "sendmsg": unix.SYS_SENDMSG, "recvmsg": unix.SYS_RECVMSG,
	"sendmmsg": unix.SYS_SENDMMSG, "recvmmsg": unix.SYS_RECVMMSG, "getsockopt": unix.SYS_GETSOCKOPT, "setsockopt": unix.SYS_SETSOCKOPT, "shutdown": unix.SYS_SHUTDOWN,
	"pipe2": unix.SYS_PIPE2, "dup": unix.SYS_DUP, "dup2": unix.SYS_DUP2, "dup3": unix.SYS_DUP3, "fcntl": unix.SYS_FCNTL,
	"readlinkat": unix.SYS_READLINKAT, "getcwd": unix.SYS_GETCWD, "chdir": unix.SYS_CHDIR, "prlimit64": unix.SYS_PRLIMIT64,
}

// Number returns the same target syscall number used by the policy compiler.
// Qualification uses this lookup to match a permitted call to raw kernel evidence.
func Number(name string) (uint32, bool) {
	number, ok := numbers[name]
	return number, ok
}

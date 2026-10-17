// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package runtimeguard

import (
	"alloyium.local/kernel-poc/internal/policy"
	"encoding/binary"
	"golang.org/x/sys/unix"
	"testing"
)

func runtimePolicy(names ...string) policy.Runtime {
	return policy.Runtime{Profile: "managed-unprivileged.v1", UID: 65534, GID: 65534, SupplementaryGroups: []int{}, Capabilities: []string{}, NoNewPrivileges: true, Seccomp: policy.Seccomp{Profile: "explicit-allowlist-notify.v2", Architecture: "x86_64", Default: "deny", AllowSyscalls: append([]string{}, names...)}}
}

// Interpret the emitted Linux cBPF instruction set against an independent seccomp_data layout.
func decide(t *testing.T, filters []unix.SockFilter, arch, nr uint32, args [6]uint64) uint32 {
	t.Helper()
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data, nr)
	binary.LittleEndian.PutUint32(data[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(data[16+i*8:], a)
	}
	var a uint32
	for pc := 0; pc < len(filters); pc++ {
		f := filters[pc]
		switch f.Code {
		case unix.BPF_LD | unix.BPF_W | unix.BPF_ABS:
			if f.K > 60 {
				t.Fatal("out of range data load")
			}
			a = binary.LittleEndian.Uint32(data[f.K:])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == f.K {
				pc += int(f.Jt)
			} else {
				pc += int(f.Jf)
			}
		case unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K:
			if a&f.K != 0 {
				pc += int(f.Jt)
			} else {
				pc += int(f.Jf)
			}
		case unix.BPF_ALU | unix.BPF_AND | unix.BPF_K:
			a &= f.K
		case unix.BPF_RET | unix.BPF_K:
			return f.K
		default:
			t.Fatalf("unknown cBPF opcode %x", f.Code)
		}
	}
	t.Fatal("filter did not return")
	return 0
}
func TestDefaultDeniesEveryUndeclaredCall(t *testing.T) {
	p, err := Compile(runtimePolicy("getpid"))
	if err != nil {
		t.Fatal(err)
	}
	for nr := uint32(0); nr < 1024; nr++ {
		want := uint32(deny)
		if nr == unix.SYS_GETPID {
			want = unix.SECCOMP_RET_ALLOW
		}
		if nr == unix.SYS_CLONE3 {
			want = unix.SECCOMP_RET_ERRNO | uint32(unix.ENOSYS)
		}
		if got := decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, nr, [6]uint64{}); got != want {
			t.Fatalf("syscall %d=%x want%x", nr, got, want)
		}
	}
	for _, arch := range []uint32{unix.AUDIT_ARCH_I386, unix.AUDIT_ARCH_AARCH64, 0} {
		if got := decide(t, p.Filters(), arch, unix.SYS_GETPID, [6]uint64{}); got != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatalf("alternate architecture allowed: %x", got)
		}
	}
	if got := decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, 0x40000000|unix.SYS_GETPID, [6]uint64{}); got != unix.SECCOMP_RET_KILL_PROCESS {
		t.Fatal("x32 survived")
	}
}
func TestScalarBoundaryAndExecListener(t *testing.T) {
	p, err := Compile(runtimePolicy("openat", "clone", "fcntl", "mmap", "mprotect", "prlimit64", "socket", "execve", "execveat"))
	if err != nil {
		t.Fatal(err)
	}
	if !p.RequiresExecListener() {
		t.Fatal("exec listener requirement missing")
	}
	tests := []struct {
		name string
		nr   uint32
		args [6]uint64
		want uint32
	}{
		{"ordinary open", unix.SYS_OPENAT, [6]uint64{}, unix.SECCOMP_RET_ALLOW},
		{"O_PATH", unix.SYS_OPENAT, [6]uint64{0, 0, unix.O_PATH}, deny},
		{"high open flags", unix.SYS_OPENAT, [6]uint64{0, 0, 1 << 32}, deny},
		{"normal clone", unix.SYS_CLONE, [6]uint64{unix.CLONE_VM | unix.CLONE_THREAD | unix.CLONE_SIGHAND}, unix.SECCOMP_RET_ALLOW},
		{"namespace clone", unix.SYS_CLONE, [6]uint64{unix.CLONE_NEWUSER}, deny},
		{"high clone flags", unix.SYS_CLONE, [6]uint64{1 << 32}, deny},
		{"fcntl get", unix.SYS_FCNTL, [6]uint64{3, unix.F_GETFD}, unix.SECCOMP_RET_ALLOW},
		{"fcntl async owner", unix.SYS_FCNTL, [6]uint64{3, unix.F_SETOWN}, deny},
		{"normal map", unix.SYS_MMAP, [6]uint64{0, 4096, unix.PROT_READ | unix.PROT_WRITE, unix.MAP_PRIVATE | unix.MAP_ANON}, unix.SECCOMP_RET_ALLOW},
		{"locked map", unix.SYS_MMAP, [6]uint64{0, 4096, unix.PROT_READ, unix.MAP_PRIVATE | unix.MAP_LOCKED}, deny},
		{"unknown protect", unix.SYS_MPROTECT, [6]uint64{0, 4096, 1 << 7}, deny},
		{"own limits read", unix.SYS_PRLIMIT64, [6]uint64{}, unix.SECCOMP_RET_ALLOW},
		{"foreign limits", unix.SYS_PRLIMIT64, [6]uint64{1}, deny},
		{"limits write", unix.SYS_PRLIMIT64, [6]uint64{0, 0, 1}, deny},
		{"IPv4 TCP", unix.SYS_SOCKET, [6]uint64{unix.AF_INET, unix.SOCK_STREAM | unix.SOCK_CLOEXEC}, unix.SECCOMP_RET_ALLOW},
		{"UNIX family", unix.SYS_SOCKET, [6]uint64{unix.AF_UNIX, unix.SOCK_STREAM}, deny},
		{"raw socket", unix.SYS_SOCKET, [6]uint64{unix.AF_INET, unix.SOCK_RAW}, deny},
		{"exec notification", unix.SYS_EXECVE, [6]uint64{}, unix.SECCOMP_RET_USER_NOTIF},
		{"fd exec notification", unix.SYS_EXECVEAT, [6]uint64{0, 0, 0, 0, unix.AT_EMPTY_PATH}, unix.SECCOMP_RET_USER_NOTIF},
		{"unknown exec flags", unix.SYS_EXECVEAT, [6]uint64{0, 0, 0, 0, 1 << 20}, deny},
	}
	for _, x := range tests {
		t.Run(x.name, func(t *testing.T) {
			if got := decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, x.nr, x.args); got != x.want {
				t.Fatalf("got%x want%x", got, x.want)
			}
		})
	}
}
func TestRejectsUnsupportedAndProtectsCompiledBytes(t *testing.T) {
	for _, r := range []policy.Runtime{runtimePolicy("clone3"), runtimePolicy("readlinkat"), runtimePolicy("readlink"), runtimePolicy("bpf"), runtimePolicy("getpid", "getpid")} {
		if _, e := Compile(r); e == nil {
			t.Fatal("unsupported or invalid runtime accepted")
		}
	}
	p, err := Compile(runtimePolicy("read", "exit_group"))
	if err != nil {
		t.Fatal(err)
	}
	q, err := Compile(runtimePolicy("exit_group", "read"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Digest() == "" || q.Digest() == "" {
		t.Fatal("digest missing")
	}
	f := p.Filters()
	f[len(f)-1].K = unix.SECCOMP_RET_ALLOW
	n := p.Names()
	n[0] = "bpf"
	if decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, unix.SYS_GETPPID, [6]uint64{}) != deny || p.Names()[0] == "bpf" {
		t.Fatal("caller changed immutable plan")
	}
}

func TestHeapPermissionDoesNotGrantBrkImplicitly(t *testing.T) {
	r := runtimePolicy("brk")
	if _, err := Compile(r); err == nil {
		t.Fatal("brk without explicit heap policy accepted")
	}
	r.Memory = &policy.MemoryPolicy{Default: "deny", Anonymous: []string{}, Heap: "allow"}
	p, err := Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	if decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, unix.SYS_BRK, [6]uint64{}) != unix.SECCOMP_RET_USER_NOTIF || !p.RequiresExecListener() {
		t.Fatal("explicit heap rights require a live notification broker")
	}
	r.Seccomp.AllowSyscalls = []string{}
	p, err = Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	if decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, unix.SYS_BRK, [6]uint64{}) != deny {
		t.Fatal("heap policy granted undeclared syscall")
	}
}

func TestPipeCreationRequiresBothExplicitPolicies(t *testing.T) {
	r := runtimePolicy("pipe2")
	if _, err := Compile(r); err == nil {
		t.Fatal("pipe creation allowance missing")
	}
	r.IPC = &policy.IPCPolicy{Default: "deny", Pipes: []string{"create"}}
	p, err := Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	if decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, unix.SYS_PIPE2, [6]uint64{}) != unix.SECCOMP_RET_ALLOW {
		t.Fatal("explicit pipe creation denied")
	}
	r.Seccomp.AllowSyscalls = []string{}
	p, err = Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	if decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, unix.SYS_PIPE2, [6]uint64{}) != deny {
		t.Fatal("pipe policy granted an undeclared syscall")
	}
}

func TestSignalCallsRequireExplicitSameJobRights(t *testing.T) {
	r := runtimePolicy("tgkill")
	if _, err := Compile(r); err == nil {
		t.Fatal("implicit signal rights accepted")
	}
	signals := []int{10}
	r.Signals = &signals
	p, err := Compile(r)
	if err != nil {
		t.Fatal(err)
	}
	if decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, unix.SYS_TGKILL, [6]uint64{}) != unix.SECCOMP_RET_ALLOW {
		t.Fatal("explicit signal call denied before task guard")
	}
	signals = []int{0}
	if _, err = Compile(r); err == nil {
		t.Fatal("unsupported signal zero accepted")
	}
}

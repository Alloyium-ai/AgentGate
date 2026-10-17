// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package runtimeguard

import (
	"golang.org/x/sys/unix"
	"testing"
)

func combinedAction(a, b uint32) uint32 {
	if int32(a&unix.SECCOMP_RET_ACTION_FULL) < int32(b&unix.SECCOMP_RET_ACTION_FULL) {
		return a
	}
	return b
}
func TestBootstrapFinalFilterRemovesEveryTemporaryRight(t *testing.T) {
	p, err := Compile(runtimePolicy("read", "close", "execve"))
	if err != nil {
		t.Fatal(err)
	}
	first, last, err := p.BootstrapFilters(7)
	if err != nil {
		t.Fatal(err)
	}
	for nr := uint32(0); nr < 1024; nr++ {
		for _, args := range [][6]uint64{{}, {7}, {8}, {1<<32 | 7}} {
			a := decide(t, first, unix.AUDIT_ARCH_X86_64, nr, args)
			b := decide(t, last, unix.AUDIT_ARCH_X86_64, nr, args)
			want := decide(t, p.Filters(), unix.AUDIT_ARCH_X86_64, nr, args)
			if combinedAction(a, b) != want {
				t.Fatalf("combined action widened syscall%d args%v", nr, args)
			}
		}
	}
	if decide(t, first, unix.AUDIT_ARCH_X86_64, unix.SYS_SENDMSG, [6]uint64{7}) != unix.SECCOMP_RET_ALLOW {
		t.Fatal("listener transfer transport unavailable")
	}
	if decide(t, first, unix.AUDIT_ARCH_X86_64, unix.SYS_SENDMSG, [6]uint64{8}) != deny {
		t.Fatal("bootstrap transport permits another descriptor")
	}
	if decide(t, last, unix.AUDIT_ARCH_X86_64, unix.SYS_SENDMSG, [6]uint64{7}) != deny {
		t.Fatal("final filter retains bootstrap send right")
	}
	if decide(t, first, unix.AUDIT_ARCH_X86_64, unix.SYS_EXECVE, [6]uint64{}) != unix.SECCOMP_RET_USER_NOTIF || decide(t, last, unix.AUDIT_ARCH_X86_64, unix.SYS_EXECVE, [6]uint64{}) != unix.SECCOMP_RET_ALLOW {
		t.Fatal("final filter replaced the listener")
	}
	for _, arch := range []uint32{unix.AUDIT_ARCH_I386, 0} {
		if decide(t, first, arch, unix.SYS_SENDMSG, [6]uint64{7}) != unix.SECCOMP_RET_KILL_PROCESS {
			t.Fatal("bootstrap bypassed architecture check")
		}
	}
	if _, _, err = p.BootstrapFilters(2); err == nil {
		t.Fatal("unsafe bootstrap descriptor accepted")
	}
}

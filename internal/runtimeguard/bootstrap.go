// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package runtimeguard

import (
	"errors"
	"golang.org/x/sys/unix"
)

// BootstrapFilters adds temporary transport rights before the trusted held barrier.
// The final filter removes those rights. Its ALLOW for notifications preserves
// the first filter's listener, whose stricter notification action still applies.
func (p Plan) BootstrapFilters(controlFD uint32) (setup, final []unix.SockFilter, err error) {
	if !p.notify || p.digest == "" || len(p.filters) < 6 || controlFD < 3 || controlFD > 255 {
		return nil, nil, errors.New("a measured exec listener and bounded control descriptor are required")
	}
	temporary := []unix.SockFilter{
		load(0), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_SENDMSG, 0, 5),
		load(arg(0) + 4), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, 0, 0, 3),
		load(arg(0)), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, controlFD, 0, 1), ret(unix.SECCOMP_RET_ALLOW),
		load(0), jump(unix.BPF_JMP|unix.BPF_JEQ|unix.BPF_K, unix.SYS_SECCOMP, 0, 1), ret(unix.SECCOMP_RET_ALLOW),
	}
	setup = append(setup, p.filters[:6]...)
	setup = append(setup, temporary...)
	setup = append(setup, p.filters[6:]...)
	final = p.Filters()
	for i, f := range final {
		if f.Code == unix.BPF_RET|unix.BPF_K && f.K == unix.SECCOMP_RET_USER_NOTIF {
			final[i].K = unix.SECCOMP_RET_ALLOW
		}
	}
	if len(setup) > 4096 {
		return nil, nil, errors.New("bootstrap filter exceeds the instruction bound")
	}
	return setup, final, nil
}

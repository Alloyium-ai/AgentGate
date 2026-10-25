//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// HardenProcess disables core dumps and ptrace-style access from same-uid
// processes and sets no_new_privs. Call it before reading any secret. It
// reports what it achieved; the caller decides whether a gap is fatal.
func HardenProcess() Hardening {
	var h Hardening
	// PR_SET_DUMPABLE=0 stops core dumps and makes /proc/self/mem, environ
	// and ptrace attach unavailable to other processes of the same uid.
	if unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) == nil {
		if v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0); err == nil && v == 0 {
			h.NotDumpable = true
		}
	}
	zero := unix.Rlimit{Cur: 0, Max: 0}
	if unix.Setrlimit(unix.RLIMIT_CORE, &zero) == nil {
		var got unix.Rlimit
		if unix.Getrlimit(unix.RLIMIT_CORE, &got) == nil && got.Cur == 0 && got.Max == 0 {
			h.CoreLimitZero = true
		}
	}
	// no_new_privs is per thread; AllThreadsSyscall applies it to every
	// runtime thread when cgo is disabled, as in the release build.
	// With cgo (for example a -race build) AllThreadsSyscall is unavailable;
	// the flag is then set on this thread only and not reported as achieved.
	if _, _, errno := syscall.AllThreadsSyscall(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); errno == 0 {
		if v, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0); err == nil && v == 1 {
			h.NoNewPrivs = true
		}
	} else {
		_ = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	}
	h.UID, h.GID = os.Geteuid(), os.Getegid()
	h.NoCapabilities = effectiveCapabilitiesZero()
	return h
}

// ErrIdentity is returned when the broker cannot serve as its configured
// unprivileged identity.
var ErrIdentity = errors.New("broker cannot assume its unprivileged identity")

var errIdentity = ErrIdentity

// DropPrivileges switches every thread to uid:gid with no supplementary groups
// and verifies the change cannot be undone. When the process is not root it
// only verifies that it already runs as the configured identity. It never lets
// the broker serve as root.
func DropPrivileges(id *Identity) error {
	if os.Geteuid() == 0 {
		if id == nil {
			return errIdentity
		}
		// Clear the capability bounding set while CAP_SETPCAP is still held.
		for c := 0; c <= unix.CAP_LAST_CAP; c++ {
			_ = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0)
		}
		if syscall.Setgroups(nil) != nil || syscall.Setresgid(id.GID, id.GID, id.GID) != nil ||
			syscall.Setresuid(id.UID, id.UID, id.UID) != nil {
			return errIdentity
		}
	}
	ru, eu, su := unix.Getresuid()
	rg, eg, sg := unix.Getresgid()
	if ru == 0 || eu == 0 || su == 0 {
		return errIdentity
	}
	if id != nil && (ru != id.UID || eu != id.UID || su != id.UID || rg != id.GID || eg != id.GID || sg != id.GID) {
		return errIdentity
	}
	if groups, err := syscall.Getgroups(); err != nil || (id != nil && len(groups) > 0 && !(len(groups) == 1 && groups[0] == id.GID)) {
		return errIdentity
	}
	if syscall.Setresuid(0, 0, 0) == nil {
		return errIdentity
	}
	if !effectiveCapabilitiesZero() {
		return errIdentity
	}
	return nil
}

// effectiveCapabilitiesZero reads CapEff and CapPrm from /proc/self/status.
func effectiveCapabilitiesZero() bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	seen := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		for _, key := range []string{"CapEff:", "CapPrm:"} {
			if strings.HasPrefix(line, key) {
				seen++
				if strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, key)), "0") != "" {
					return false
				}
			}
		}
	}
	return seen == 2
}

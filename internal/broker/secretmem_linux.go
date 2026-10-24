//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"os"

	"golang.org/x/sys/unix"
)

// secretArena holds a credential and its derived forms outside the Go heap: an
// anonymous private mapping, excluded from core dumps and locked against swap
// where RLIMIT_MEMLOCK allows. The garbage collector never copies or scans it.
// destroy zeroes it; the mapping is never unmapped, because a string built over
// it may still be referenced by a request that is being torn down.
type secretArena struct {
	mem    []byte
	used   int
	locked bool
}

func newSecretArena(size int) (*secretArena, error) {
	page := os.Getpagesize()
	size = (size + page - 1) / page * page
	mem, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return nil, err
	}
	_ = unix.Madvise(mem, unix.MADV_DONTDUMP)
	_ = unix.Madvise(mem, unix.MADV_WIPEONFORK)
	return &secretArena{mem: mem, locked: unix.Mlock(mem) == nil}, nil
}

func (a *secretArena) alloc(n int) []byte {
	if n < 0 || a.used+n > len(a.mem) {
		return nil
	}
	b := a.mem[a.used : a.used+n : a.used+n]
	a.used += n
	return b
}

// release zeroes and unmaps an arena that nothing references any more.
func (a *secretArena) release() {
	a.destroy()
	_ = unix.Munmap(a.mem)
	a.mem = nil
}

func (a *secretArena) destroy() {
	clear(a.mem)
	if a.locked {
		_ = unix.Munlock(a.mem)
		a.locked = false
	}
}

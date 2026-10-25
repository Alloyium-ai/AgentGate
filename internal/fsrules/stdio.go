// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package fsrules

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

// A plan marked InheritedStdio lets the job use a pipe made outside every
// managed domain only when the launcher recorded that pipe's inode for the
// domain, before the command joined, and only in the recorded direction. The
// rights are the kernel's file_permission mask bits.
const (
	StdioWrite uint32 = 2 // MAY_WRITE: stdout and stderr
	StdioRead  uint32 = 4 // MAY_READ: stdin
)

// MaxStdioPipes bounds the recorded pipes: stdin, stdout and stderr.
const MaxStdioPipes = 3

// StdioKey is the stdio map key in bpf/fs_access.bpf.c.
type StdioKey struct{ Domain, Inode uint64 }

// StdioPipe is one recorded launcher pipe.
type StdioPipe struct {
	Inode  uint64
	Rights uint32
}

// ValidateStdio requires one to three distinct pipes, each with exactly one
// direction. Nothing else can ever be recorded.
func ValidateStdio(pipes []StdioPipe) error {
	if len(pipes) == 0 || len(pipes) > MaxStdioPipes {
		return fmt.Errorf("between 1 and %d stdio pipes are recorded", MaxStdioPipes)
	}
	seen := map[uint64]bool{}
	for _, pipe := range pipes {
		if pipe.Inode == 0 || seen[pipe.Inode] {
			return errors.New("each recorded stdio pipe has its own nonzero inode")
		}
		if pipe.Rights != StdioRead && pipe.Rights != StdioWrite {
			return errors.New("a recorded stdio pipe is either read or written, never both")
		}
		seen[pipe.Inode] = true
	}
	return nil
}

// RecordStdio writes the launcher's stdio pipes for domain into the file
// component's stdio map, once: the map must be empty, every entry is created
// exclusively, and the whole map must read back as exactly these entries. The
// caller proves the domain is still empty, so no task of the job can use a
// pipe before it is recorded, and none is recorded after the job runs.
func RecordStdio(m *ebpf.Map, domain uint64, pipes []StdioPipe) error {
	if domain == 0 {
		return errors.New("the stdio grant needs a domain")
	}
	if err := ValidateStdio(pipes); err != nil {
		return err
	}
	if m == nil || m.Type() != ebpf.Hash || m.KeySize() != 16 || m.ValueSize() != 4 || m.MaxEntries() < MaxStdioPipes {
		return errors.New("the file component's stdio map differs")
	}
	if entries, err := readStdio(m); err != nil || len(entries) != 0 {
		return errors.Join(err, errors.New("stdio pipes are recorded once per domain, before the job joins"))
	}
	for _, pipe := range pipes {
		if err := m.Update(StdioKey{domain, pipe.Inode}, pipe.Rights, ebpf.UpdateNoExist); err != nil {
			return fmt.Errorf("record stdio pipe %d: %w", pipe.Inode, err)
		}
	}
	entries, err := readStdio(m)
	if err != nil {
		return err
	}
	if len(entries) != len(pipes) {
		return errors.New("the stdio map readback differs")
	}
	for _, pipe := range pipes {
		if entries[StdioKey{domain, pipe.Inode}] != pipe.Rights {
			return errors.New("the stdio map readback differs")
		}
	}
	return nil
}

func readStdio(m *ebpf.Map) (map[StdioKey]uint32, error) {
	out := map[StdioKey]uint32{}
	var key StdioKey
	var value uint32
	iterator := m.Iterate()
	for iterator.Next(&key, &value) {
		if len(out) > MaxStdioPipes {
			return nil, errors.New("the stdio map holds more than its bound")
		}
		out[key] = value
	}
	return out, iterator.Err()
}

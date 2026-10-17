// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package syscallrules

import "errors"

const (
	TraceOrigin uint32 = 1
	EntryOrigin uint32 = 2
)

func validateOrigin(e Event) error {
	if e.Version == 0 {
		if e.OriginalID != 0 || e.EntryMonoNS != 0 || e.OriginFlags != 0 {
			return errors.New("a legacy observation acquired origin fields")
		}
		return nil
	}
	if e.Version != 2 || e.OriginFlags & ^uint32(TraceOrigin|EntryOrigin) != 0 {
		return errors.New("the syscall origin version or flags differ")
	}
	if e.Type == TaskExit {
		if e.OriginalID != -1 || e.EntryMonoNS != 0 || e.OriginFlags != 0 {
			return errors.New("a task exit acquired a syscall origin")
		}
		return nil
	}
	switch e.OriginFlags {
	case TraceOrigin:
		if e.SyscallID < 0 || e.OriginalID != e.SyscallID || e.EntryMonoNS != 0 {
			return errors.New("the direct syscall origin differs")
		}
	case EntryOrigin:
		if e.SyscallID != -1 || e.OriginalID < 0 || e.EntryMonoNS == 0 || e.EntryMonoNS > e.MonoNS {
			return errors.New("the correlated syscall origin differs")
		}
	case 0:
		if e.SyscallID >= 0 || e.OriginalID != -1 || e.EntryMonoNS != 0 {
			return errors.New("an unavailable origin acquired an original number")
		}
	default:
		return errors.New("the syscall origin is ambiguous")
	}
	return nil
}

// OriginalNumber preserves the raw SyscallID. It uses only a validated kernel
// trace origin or the kernel's exact task-bound entry correlation.
func (e Event) OriginalNumber() (int64, bool) {
	if e.Type != Result || e.Flags & ^UnknownSyscallID != 0 || (e.SyscallID < 0) != (e.Flags&UnknownSyscallID != 0) || validateOrigin(e) != nil {
		return -1, false
	}
	if e.Version == 0 {
		return e.SyscallID, e.SyscallID >= 0 && e.Flags&UnknownSyscallID == 0
	}
	if e.OriginFlags == TraceOrigin || e.OriginFlags == EntryOrigin {
		return e.OriginalID, true
	}
	return -1, false
}

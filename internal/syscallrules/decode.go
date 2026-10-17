// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package syscallrules

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

func Decode(raw []byte) (Event, error) {
	var event Event
	if len(raw) != 104 && len(raw) != 128 {
		return event, fmt.Errorf("unsupported syscall audit event length: %d", len(raw))
	}
	frame := raw
	if len(raw) == 104 {
		frame = append(append([]byte{}, raw...), make([]byte, 24)...)
	}
	if err := binary.Read(bytes.NewReader(frame), binary.LittleEndian, &event); err != nil {
		return event, err
	}
	if len(raw) == 128 && event.Version != 2 {
		return event, errors.New("unsupported syscall audit event version")
	}
	return event, Validate(event)
}
func Validate(event Event) error {
	if event.Sequence == 0 || event.Domain == 0 || event.Cgroup == 0 || event.MonoNS == 0 || event.TaskStartBootNS == 0 || event.TGID == 0 || event.TID == 0 || event.BindingState > Invalid || event.Flags & ^UnknownSyscallID != 0 {
		return errors.New("invalid syscall audit identity or flags")
	}
	if event.BindingState == Live && event.Generation == 0 {
		return errors.New("live syscall audit event lacks its generation")
	}
	if event.BindingState == Missing && event.Generation != 0 {
		return errors.New("missing audit binding acquired a generation")
	}
	switch event.Type {
	case Result:
		if event.ExitCode != 0 || (event.SyscallID < 0) != (event.Flags&UnknownSyscallID != 0) {
			return errors.New("syscall result identity or flags differ")
		}
	case TaskExit:
		if event.SyscallID != -1 || event.Result != 0 || event.Flags != 0 {
			return errors.New("task exit contains an invented syscall result")
		}
	default:
		return errors.New("unknown syscall audit record type")
	}
	return validateOrigin(event)
}

// Complete checks observation integrity. It does not authorize VALID_COMPLETE.
func Complete(events []Event, stats Counters) error {
	if stats.Lost != 0 || stats.Records == 0 || stats.Records != uint64(len(events)) {
		return errors.New("syscall audit loss or counter mismatch requires a whole-domain stop")
	}
	sequences := map[uint64]bool{}
	for _, event := range events {
		if err := Validate(event); err != nil {
			return err
		}
		if event.Sequence > stats.Records || sequences[event.Sequence] {
			return errors.New("syscall audit sequence gap or duplicate")
		}
		sequences[event.Sequence] = true
		if event.Type == Result {
			if _, known := event.OriginalNumber(); !known {
				return errors.New("raw syscall number is unavailable; original-number qualification failed")
			}
		}
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package nodeaudit decodes exact raw kernel facts. It invents no policy decision.
package nodeaudit

import (
	"encoding/binary"
	"errors"
	"fmt"

	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/syscallrules"
)

func Registry() jobaudit.Registry {
	return jobaudit.Registry{
		"files/files216.v1":       files,
		"peers/peers96.v2":        peers,
		"sockets/sockets112.v1":   sockets,
		"custody/custody64.v1":    custody,
		"process/process80.v1":    process,
		"syscalls/syscalls104.v1": legacySyscalls,
		"syscalls/syscalls128.v2": currentSyscalls,
	}
}
func u32(raw []byte, offset int) uint32 { return binary.LittleEndian.Uint32(raw[offset:]) }
func u64(raw []byte, offset int) uint64 { return binary.LittleEndian.Uint64(raw[offset:]) }
func header(raw []byte, size, domain, generation, mono int) (jobaudit.Observation, error) {
	var out jobaudit.Observation
	if len(raw) != size {
		return out, fmt.Errorf("raw event size %d differs from %d", len(raw), size)
	}
	out.CgroupID = u64(raw, domain)
	out.Generation = u64(raw, generation)
	out.Sequence = u64(raw, 0)
	out.TimestampNS = u64(raw, mono)
	if out.CgroupID == 0 || out.Sequence == 0 || out.TimestampNS == 0 {
		return out, errors.New("raw event lacks a domain, sequence or time")
	}
	return out, nil
}
func decision(out jobaudit.Observation, effect uint32) (jobaudit.Observation, error) {
	if effect > 1 {
		return out, errors.New("raw resource decision is outside its binary domain")
	}
	value := effect == 1
	if value && out.Generation == 0 {
		return out, errors.New("a raw resource grant lacks a generation")
	}
	out.Decision = &value
	return out, nil
}
func files(raw []byte) (jobaudit.Observation, error) {
	out, err := header(raw, 216, 16, 8, 24)
	if err != nil {
		return out, err
	}
	if u32(raw, 40) > 23 || u32(raw, 40) >= 22 && u32(raw, 44) != 0 {
		return out, errors.New("unknown file operation")
	}
	return decision(out, u32(raw, 44))
}
func peers(raw []byte) (jobaudit.Observation, error) {
	out, err := header(raw, 96, 16, 8, 32)
	if err != nil {
		return out, err
	}
	if u32(raw, 88) != 2 || u64(raw, 24) == 0 || u32(raw, 48) < 1 || u32(raw, 48) > 6 {
		return out, errors.New("unknown endpoint version, cgroup or hook")
	}
	out.DNSLeaseRevision = uint64(u32(raw, 92))
	if u32(raw, 52) == 1 {
		family, protocol, port := u32(raw, 60), u32(raw, 64), u32(raw, 68)
		if (family != 4 && family != 6) || (protocol != 6 && protocol != 17) || port == 0 || port > 65535 || u32(raw, 56) == 0 {
			return out, errors.New("invalid allowed endpoint fields")
		}
	}
	return decision(out, u32(raw, 52))
}
func sockets(raw []byte) (jobaudit.Observation, error) {
	out, err := header(raw, 112, 16, 8, 32)
	if err != nil {
		return out, err
	}
	operation, source := u32(raw, 56), u32(raw, 88)
	if u64(raw, 24) == 0 || operation == 0 || operation > 1024 || operation&(operation-1) != 0 || source < 1 || source > 5 {
		return out, errors.New("unknown socket cgroup, operation or source")
	}
	if source == 3 && operation != 32 || source == 4 && operation != 16 || source == 5 && operation != 1 {
		return out, errors.New("socket packet or creation source differs")
	}
	if u32(raw, 60) == 1 {
		family, protocol := u32(raw, 68), u32(raw, 72)
		if (family != 2 && family != 10) || (protocol != 6 && protocol != 17) || u32(raw, 64) == 0 {
			return out, errors.New("invalid allowed socket fields")
		}
		if source == 5 && u64(raw, 40) != out.CgroupID {
			return out, errors.New("socket creation owner differs")
		}
	}
	out.DNSLeaseRevision = uint64(u32(raw, 92))
	return decision(out, u32(raw, 60))
}
func custody(raw []byte) (jobaudit.Observation, error) {
	out, err := header(raw, 64, 8, 32, 40)
	if err != nil {
		return out, err
	}
	if u64(raw, 24) == 0 || u32(raw, 56) < 1 || u32(raw, 56) > 2 {
		return out, errors.New("unknown socket custody cgroup or hook")
	}
	if u32(raw, 60) == 1 && u64(raw, 16) != out.CgroupID {
		return out, errors.New("socket custody owner differs")
	}
	return decision(out, u32(raw, 60))
}
func process(raw []byte) (jobaudit.Observation, error) {
	out, err := header(raw, 80, 8, 32, 40)
	if err != nil {
		return out, err
	}
	hook, mode, effect, reason := u32(raw, 56), u32(raw, 64), u32(raw, 68), u32(raw, 72)
	if u64(raw, 24) == 0 || hook < 1 || hook > 3 || reason > 11 {
		return out, errors.New("unknown process cgroup, hook or reason")
	}
	if effect == 1 {
		signal := int32(u32(raw, 60))
		valid := hook == 1 && signal >= 1 && signal <= 64 || hook == 2 && mode&2 == 0 && mode&1 != 0 && mode & ^uint32(1|4|8|16) == 0
		if !valid || reason != 0 || u64(raw, 16) != out.CgroupID {
			return out, errors.New("process grant has unsupported ownership or mode")
		}
	}
	return decision(out, effect)
}
func syscalls(raw []byte) (jobaudit.Observation, error) {
	var out jobaudit.Observation
	event, err := syscallrules.Decode(raw)
	if err != nil {
		return out, err
	}
	if event.Type == syscallrules.Result {
		if _, known := event.OriginalNumber(); !known {
			return out, errors.New("unknown original syscall number prevents complete audit")
		}
	}
	out.CgroupID = event.Domain
	out.Generation = event.Generation
	out.Sequence = event.Sequence
	out.TimestampNS = event.MonoNS
	out.BindingState = event.BindingState
	// The observer's signed return value is not a resource policy decision.
	return out, nil
}

func legacySyscalls(raw []byte) (jobaudit.Observation, error) {
	if len(raw) != 104 {
		return jobaudit.Observation{}, errors.New("the legacy syscall stream ABI differs")
	}
	return syscalls(raw)
}
func currentSyscalls(raw []byte) (jobaudit.Observation, error) {
	if len(raw) != 128 {
		return jobaudit.Observation{}, errors.New("the current syscall stream ABI differs")
	}
	return syscalls(raw)
}

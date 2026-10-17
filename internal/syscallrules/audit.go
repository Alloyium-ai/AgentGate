// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package syscallrules defines an outcome observer. It grants no syscall rights.
package syscallrules

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const Purpose = "agentgate.syscall-result-audit.v1"
const LegacyFormat = "syscalls104.v1"
const Format = "syscalls128.v2"
const (
	Result   uint32 = 1
	TaskExit uint32 = 2
)
const (
	Live uint32 = iota
	Missing
	Expired
	Invalid
)
const UnknownSyscallID uint32 = 1

// Event records a kernel outcome, never an inferred policy effect.
type Event struct {
	Sequence          uint64 `json:"sequence,string"`
	Domain            uint64 `json:"domain,string"`
	Cgroup            uint64 `json:"cgroup,string"`
	Generation        uint64 `json:"generation,string"`
	MonoNS            uint64 `json:"mono_ns,string"`
	TaskStartBootNS   uint64 `json:"task_start_boot_ns,string"`
	SyscallID         int64  `json:"syscall_id,string"`
	Result            int64  `json:"result,string"`
	TGID              uint32 `json:"tgid"`
	TID               uint32 `json:"tid"`
	UID               uint32 `json:"uid"`
	Type              uint32 `json:"type"`
	ExitCode          int32  `json:"exit_code"`
	BindingState      uint32 `json:"binding_state"`
	ParentTGID        uint32 `json:"parent_tgid"`
	Flags             uint32 `json:"flags"`
	ParentStartBootNS uint64 `json:"parent_start_boot_ns,string"`
	OriginalID        int64  `json:"original_id,string,omitempty"`
	EntryMonoNS       uint64 `json:"entry_mono_ns,string,omitempty"`
	Version           uint32 `json:"version,omitempty"`
	OriginFlags       uint32 `json:"origin_flags,omitempty"`
}
type Binding struct{ Generation, ExpiresNS uint64 }

// Records counts attempted observations. Records equals emitted events plus Lost.
type Counters struct {
	Records uint64 `json:"records,string"`
	Lost    uint64 `json:"lost,string"`
}
type Plan struct {
	domain  uint64
	binding Binding
	digest  string
}

func Compile(domain, generation, now, deadline uint64) (Plan, error) {
	if domain == 0 || generation == 0 || deadline <= now {
		return Plan{}, errors.New("an audit binding requires a live immutable root, generation, and deadline")
	}
	p := Plan{domain: domain, binding: Binding{generation, deadline}}
	raw := make([]byte, 24)
	binary.LittleEndian.PutUint64(raw, domain)
	binary.LittleEndian.PutUint64(raw[8:], generation)
	binary.LittleEndian.PutUint64(raw[16:], deadline)
	sum := sha256.Sum256(append([]byte(Purpose+"\n"+Format+"\n"), raw...))
	p.digest = hex.EncodeToString(sum[:])
	return p, nil
}
func (p Plan) Domain() uint64   { return p.domain }
func (p Plan) Binding() Binding { return p.binding }
func (p Plan) Digest() string   { return p.digest }
func (p Plan) Check(domain, now uint64) error {
	actual, err := Compile(p.domain, p.binding.Generation, now, p.binding.ExpiresNS)
	if err != nil || domain != p.domain || p.digest == "" || actual.digest != p.digest {
		return errors.New("the audit binding changed or expired")
	}
	return nil
}

type Tracepoint struct{ Program, Group, Name string }
type TraceProfile struct {
	Programs                                        []Tracepoint
	ManagedMap, BindingsMap, EventsMap, CountersMap string
}

func Programs() []Tracepoint {
	return []Tracepoint{{"audit_sys_enter", "raw_syscalls", "sys_enter"}, {"audit_sys_exit", "raw_syscalls", "sys_exit"}, {"audit_task_exit", "sched", "sched_process_exit"}}
}

// Profile is a standalone descriptor until the common loader supports tracepoints.
func Profile() TraceProfile {
	return TraceProfile{Programs: Programs(), ManagedMap: "audit_managed", BindingsMap: "audit_bindings", EventsMap: "audit_events", CountersMap: "audit_stats"}
}

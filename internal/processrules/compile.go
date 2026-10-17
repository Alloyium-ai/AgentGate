// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package processrules compiles explicit same-job signals and process isolation.
package processrules

import (
	"alloyium.local/kernel-poc/internal/policy"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

const Purpose = "agentgate.explicit-process-component.v1"

type State struct {
	Generation uint64 `json:"generation,string"`
	ExpiresNS  uint64 `json:"expires_ns,string"`
	Signals    uint64 `json:"signals,string"`
}
type Counters struct {
	Decisions uint64 `json:"decisions,string"`
	Lost      uint64 `json:"lost,string"`
}
type Event struct {
	Sequence     uint64 `json:"sequence,string"`
	Domain       uint64 `json:"domain,string"`
	TargetDomain uint64 `json:"target_domain,string"`
	Cgroup       uint64 `json:"cgroup,string"`
	Generation   uint64 `json:"generation,string"`
	MonoNS       uint64 `json:"mono_ns,string"`
	PID          uint32 `json:"pid"`
	UID          uint32 `json:"uid"`
	Hook         uint32 `json:"hook"`
	Signal       int32  `json:"signal"`
	Mode         uint32 `json:"mode"`
	Allowed      uint32 `json:"allowed"`
	Reason       uint32 `json:"reason"`
	TargetPID    uint32 `json:"target_pid"`
}

const (
	SignalHook uint32 = 1 + iota
	PtraceHook
	TracemeHook
)
const (
	Allowed uint32 = iota
	MissingPolicy
	ExpiredPolicy
	UnsupportedSignal
	UnlistedSignal
	ForeignTarget
	UnownedTarget
	TracingDenied
	UnsupportedPtraceMode
	InvalidManaged
	UnknownTarget
	PriorDenial
)

type Plan struct {
	domain uint64
	state  State
	digest string
}

func (p Plan) State() State   { return p.state }
func (p Plan) Domain() uint64 { return p.domain }
func (p Plan) Digest() string { return p.digest }
func planDigest(p Plan) string {
	hash := sha256.New()
	hash.Write([]byte(Purpose + "\n" + policy.SchemaDigest() + "\n"))
	_ = binary.Write(hash, binary.LittleEndian, p.domain)
	_ = binary.Write(hash, binary.LittleEndian, p.state)
	return hex.EncodeToString(hash.Sum(nil))
}

// Compile grants no syscall. The explicit seccomp compiler remains mandatory.
func Compile(runtime policy.Runtime, domain, generation, deadline uint64) (Plan, error) {
	if err := policy.ValidateRuntimeSection(runtime); err != nil {
		return Plan{}, err
	}
	if domain == 0 || generation == 0 || deadline == 0 {
		return Plan{}, errors.New("process rights require a resolved root, generation and deadline")
	}
	p := Plan{domain: domain, state: State{Generation: generation, ExpiresNS: deadline}}
	if runtime.Signals != nil {
		for _, signal := range *runtime.Signals {
			if signal < 1 || signal > 64 {
				return Plan{}, errors.New("only explicit Linux signals1 through64 are supported")
			}
			p.state.Signals |= uint64(1) << uint(signal-1)
		}
	}
	p.digest = planDigest(p)
	return p, nil
}

// Decide is the scalar ownership restriction. It grants no file or syscall right.
func Decide(state State, source, target uint64, sourceManaged, targetManaged *uint32, hook uint32, signal int32, mode uint32, now uint64) (bool, uint32) {
	if sourceManaged == nil {
		return true, Allowed
	}
	if *sourceManaged != 1 {
		return false, InvalidManaged
	}
	if state.Generation == 0 {
		return false, MissingPolicy
	}
	if now >= state.ExpiresNS {
		return false, ExpiredPolicy
	}
	if hook == TracemeHook {
		return false, TracingDenied
	}
	if target == 0 {
		return false, UnknownTarget
	}
	if targetManaged == nil || *targetManaged != 1 {
		return false, UnownedTarget
	}
	if source == 0 || source != target {
		return false, ForeignTarget
	}
	switch hook {
	case SignalHook:
		if signal < 1 || signal > 64 {
			return false, UnsupportedSignal
		}
		if state.Signals&(uint64(1)<<uint(signal-1)) == 0 {
			return false, UnlistedSignal
		}
	case PtraceHook:
		if mode&2 != 0 {
			return false, TracingDenied
		}
		if mode&1 == 0 || mode&^uint32(1|4|8|16) != 0 {
			return false, UnsupportedPtraceMode
		}
	default:
		return false, TracingDenied
	}
	return true, Allowed
}

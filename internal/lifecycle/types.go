// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package lifecycle coordinates a held workload and its kernel enforcement domain.
package lifecycle

import (
	"context"
	"encoding/json"
)

type Binding struct {
	AgentID         string            `json:"agent_id"`
	AgentKey        string            `json:"agent_key"`
	JobDigest       string            `json:"job_digest"`
	GrantID         string            `json:"grant_id"`
	RunID           string            `json:"run_id"`
	NodeID          string            `json:"node_id"`
	BootID          string            `json:"boot_id"`
	PolicyDigest    string            `json:"policy_digest"`
	SchemaDigest    string            `json:"schema_digest"`
	CompilerDigest  string            `json:"compiler_digest"`
	ArtifactDigests map[string]string `json:"artifact_digests"`
	CgroupID        uint64            `json:"cgroup_id,string"`
	Generation      uint64            `json:"generation,string"`
	DeadlineNS      uint64            `json:"deadline_ns,string"`
}

type Authorization struct {
	Binding              Binding         `json:"binding"`
	Grant                string          `json:"grant"`
	Document             json.RawMessage `json:"document"`
	RequiredCapabilities []string        `json:"required_capabilities"`
}

type HeldProcess struct {
	PID            int    `json:"pid"`
	StartTimeTicks uint64 `json:"start_time_ticks,string"`
	BarrierID      string `json:"barrier_id"`
}

type Capability struct {
	State          string   `json:"state"`
	Mechanisms     []string `json:"mechanisms"`
	EvidenceDigest string   `json:"evidence_digest"`
}

type Evidence struct {
	FixturePurpose      string                `json:"fixture_purpose,omitempty"`
	Binding             Binding               `json:"binding"`
	EffectiveDeadlineNS uint64                `json:"effective_deadline_ns,string,omitempty"`
	Phase               string                `json:"phase"`
	Quarantined         bool                  `json:"quarantined"`
	Released            bool                  `json:"released"`
	Terminated          bool                  `json:"terminated"`
	ReadbackDigest      string                `json:"readback_digest"`
	MandatoryHooks      bool                  `json:"mandatory_hooks"`
	Capabilities        map[string]Capability `json:"capabilities"`
	Process             *HeldProcess          `json:"process,omitempty"`
	Empty               bool                  `json:"empty"`
	NoDomain            bool                  `json:"no_domain,omitempty"`
	CountersAvailable   bool                  `json:"counters_available,omitempty"`
	RightsRemoved       bool                  `json:"rights_removed"`
	Decisions           uint64                `json:"decisions,string"`
	Lost                uint64                `json:"lost,string"`
	Digest              string                `json:"digest"`
}

type Record struct {
	Binding               Binding        `json:"binding"`
	PreparationDeadlineNS uint64         `json:"preparation_deadline_ns,string"`
	Authorization         *Authorization `json:"authorization,omitempty"`
	Process               *HeldProcess   `json:"process,omitempty"`
	Watchdog              *WatchdogAck   `json:"watchdog,omitempty"`
	State                 string         `json:"state"`
	Revision              uint64         `json:"revision,string"`
	Evidence              []Evidence     `json:"evidence"`
	LastError             string         `json:"last_error,omitempty"`
	StopReason            string         `json:"stop_reason,omitempty"`
}

// Backend owns all process and kernel operations. It must retain deny enforcement
// on every failed operation. Stop removes rights only after whole-domain termination.
type Backend interface {
	ListDomains(context.Context) ([]Binding, error)
	Prepare(context.Context, Binding) (Evidence, error)
	Place(context.Context, Binding, HeldProcess) (Evidence, error)
	Install(context.Context, Authorization) (Evidence, error)
	Release(context.Context, Binding) (Evidence, error)
	Stop(context.Context, Binding, string) (Evidence, error)
	Recover(context.Context, Record) (Evidence, error)
}

// Verifier checks signatures, immutable policy content, current qualification,
// enrollment and exact target binding. An unverified caller flag is insufficient.
type Verifier interface {
	Verify(context.Context, Authorization) error
}

type StopCause string

const (
	GrantExpired StopCause = "grant-expired"
	GrantRevoked StopCause = "revoked"
)

// LifecycleStopReason identifies a verified grant outcome. The manager accepts
// only GrantExpired and GrantRevoked; other failures retain the generic abort.
type LifecycleStopReason interface {
	error
	LifecycleStopReason() StopCause
}

// Journal must atomically retain records before the manager changes kernel state.
// Save checks the expected prior revision to reject another manager's stale write.
type Journal interface {
	Save(context.Context, Record, uint64) error
	SaveOrphan(context.Context, Evidence) error
	Load(context.Context) ([]Record, error)
	Lookup(context.Context, string) (Record, error)
}

type Clock interface{ NowNS() (uint64, error) }

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package activity defines future collector and ingest boundaries.
// It does not collect events, authorize a viewer, or enable a live stream.
package activity

import (
	"context"
	"errors"
	"fmt"
	"regexp"
)

const SchemaVersion = "agentgate.activity.v1"

var hash64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Process struct {
	PID     uint32 `json:"pid"`
	StartNS uint64 `json:"start_ns"`
}
type Correlation struct {
	Agent         string   `json:"agent"`
	Job           string   `json:"job"`
	GrantDigest   string   `json:"grant_digest"`
	PolicyVersion string   `json:"policy_version"`
	PolicyDigest  string   `json:"policy_digest"`
	Process       Process  `json:"process"`
	Parent        *Process `json:"parent,omitempty"`
}
type Event struct {
	SchemaVersion   string      `json:"schema_version"`
	Node            string      `json:"node"`
	Boot            string      `json:"boot"`
	Sequence        uint64      `json:"sequence"`
	MonotonicNS     uint64      `json:"monotonic_ns"`
	Correlation     Correlation `json:"correlation"`
	Kind            string      `json:"kind"`
	AttemptSequence uint64      `json:"attempt_sequence,omitempty"`
	Operation       string      `json:"operation"`
	Rule            string      `json:"rule,omitempty"`
	ResourceID      string      `json:"resource_id"`
	Decision        string      `json:"decision,omitempty"`
	Outcome         string      `json:"outcome,omitempty"`
	Redacted        bool        `json:"redacted"`
}

// ID uses length prefixes so separators in an enrolled identity cannot collide.
func (e Event) ID() string {
	return fmt.Sprintf("%d:%s%d:%s:%d", len(e.Node), e.Node, len(e.Boot), e.Boot, e.Sequence)
}

func (e Event) Validate() error {
	if e.SchemaVersion != SchemaVersion || len(e.Node) == 0 || len(e.Node) > 100 || len(e.Boot) == 0 || len(e.Boot) > 100 || e.Sequence == 0 {
		return errors.New("activity identity or schema differs")
	}
	if e.Correlation.Agent == "" || e.Correlation.Job == "" || e.Correlation.Process.PID == 0 || e.Correlation.Process.StartNS == 0 {
		return errors.New("activity requires an agent, job, and stable process identity")
	}
	if !hash64.MatchString(e.Correlation.GrantDigest) || !hash64.MatchString(e.Correlation.PolicyDigest) || e.Correlation.PolicyVersion == "" {
		return errors.New("activity requires immutable grant and policy bindings")
	}
	if e.Operation == "" || len(e.Operation) > 100 || !hash64.MatchString(e.ResourceID) || len(e.Rule) > 100 {
		return errors.New("activity requires a bounded operation and opaque resource identity")
	}
	if e.Kind == "decision" && (e.Decision == "allow" || e.Decision == "deny" || e.Decision == "held") && e.Outcome == "" && e.AttemptSequence == 0 {
		return nil
	}
	if e.Kind == "outcome" && (e.Outcome == "succeeded" || e.Outcome == "failed" || e.Outcome == "unknown") && e.Decision == "" && e.AttemptSequence > 0 && e.AttemptSequence < e.Sequence {
		return nil
	}
	return errors.New("activity must separate an attempt decision from an outcome")
}

type Gap struct {
	From   uint64 `json:"from"`
	To     uint64 `json:"to"`
	Reason string `json:"reason"`
}
type Batch struct {
	SchemaVersion        string  `json:"schema_version"`
	Node                 string  `json:"node"`
	Boot                 string  `json:"boot"`
	First                uint64  `json:"first"`
	Last                 uint64  `json:"last"`
	Events               []Event `json:"events"`
	Gaps                 []Gap   `json:"gaps"`
	EvidenceState        string  `json:"evidence_state"`
	SignedEvidenceDigest string  `json:"signed_evidence_digest,omitempty"`
}
type Cursor string
type Ack struct {
	Cursor  Cursor
	Digest  string
	Durable bool
}

// Collectors use bounded batches. Kernel decisions cannot wait for these calls.
type Collector interface {
	Drain(context.Context, int) (Batch, error)
}

// Journals append before ingest and retain unacknowledged records for replay.
type Journal interface {
	Append(context.Context, Batch) (Cursor, error)
	Read(context.Context, Cursor, int) (Batch, error)
}

// Ingest acknowledges only committed bytes. Viewer delivery uses a separate path.
type Ingest interface {
	Commit(context.Context, Batch) (Ack, error)
}

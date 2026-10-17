// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package jobaudit records separate resource and node control evidence streams.
package jobaudit

import (
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"crypto/ed25519"
)

const HeaderProtocol = "agentgate.full-job-audit.v1"
const HeaderDomain = "AGENTGATE_JOB_AUDIT_HEADER_V1\n"

type Stream struct {
	Name           string `json:"name"`
	Kind           string `json:"kind"` // resource, observation or control
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifact_digest"`
}
type Header struct {
	FixturePurpose       string            `json:"fixture_purpose,omitempty"`
	Protocol             string            `json:"protocol"`
	Binding              lifecycle.Binding `json:"binding"`
	DocumentDigest       string            `json:"document_digest"`
	QualificationDigest  string            `json:"qualification_digest"`
	RequiredCapabilities []string          `json:"required_capabilities"`
	RequiredStreams      []Stream          `json:"required_streams"`
	CreatedMonoNS        uint64            `json:"created_mono_ns,string"`
}
type Observation struct {
	GrantExpiry      *GrantExpiry `json:"grant_expiry,omitempty"`
	ControlPhase     string       `json:"-"`
	Decision         *bool        `json:"decision,omitempty"`
	BindingState     uint32       `json:"binding_state"`
	CgroupID         uint64       `json:"cgroup_id,string"`
	Generation       uint64       `json:"generation,string"`
	Sequence         uint64       `json:"sequence,string"`
	TimestampNS      uint64       `json:"timestamp_ns,string"`
	DNSLeaseRevision uint64       `json:"dns_lease_revision,string"`
}

// Decoders validate exact versioned raw bytes. They must reject unknown layouts.
type Decoder func([]byte) (Observation, error)
type Registry map[string]Decoder // stream name + "/" + version

type Event struct {
	Index          uint64      `json:"index,string"`
	Stream         string      `json:"stream"`
	Kind           string      `json:"kind"`
	Version        string      `json:"version"`
	Observation    Observation `json:"observation"`
	Raw            []byte      `json:"raw"`
	PreviousDigest string      `json:"previous_digest"`
	Digest         string      `json:"digest"`
}
type FinalCounters struct {
	Sequence  uint64 `json:"sequence,string"`
	Decisions uint64 `json:"decisions,string"`
	Lost      uint64 `json:"lost,string"`
	Available bool   `json:"available"`
}
type Terminal struct {
	State             string `json:"state"`
	ExitCode          int    `json:"exit_code"`
	Empty             bool   `json:"empty"`
	RightsRemoved     bool   `json:"rights_removed"`
	OutputDigest      string `json:"output_digest"`
	CountersAvailable bool   `json:"counters_available"`
}
type NodeSeal struct {
	Protocol       string   `json:"protocol"`
	NodeID         string   `json:"node_id"`
	KeyID          string   `json:"key_id"`
	HeaderDigest   string   `json:"header_digest"`
	GrantDigest    string   `json:"grant_digest"`
	EventsDigest   string   `json:"events_digest"`
	CountersDigest string   `json:"counters_digest"`
	Terminal       Terminal `json:"terminal"`
	SealedMonoNS   uint64   `json:"sealed_mono_ns,string"`
	Signature      string   `json:"signature"`
}
type AuthorityReceipt struct {
	Protocol       string            `json:"protocol"`
	AuthorityID    string            `json:"authority_id"`
	KeyID          string            `json:"key_id"`
	Binding        lifecycle.Binding `json:"binding"`
	NodeSealDigest string            `json:"node_seal_digest"`
	IssuedAt       int64             `json:"issued_at"`
	Accepted       bool              `json:"accepted"`
	Signature      string            `json:"signature"`
}
type Bundle struct {
	Header    Header                   `json:"header"`
	Grant     *jobgrant.Envelope       `json:"grant,omitempty"`
	Events    []Event                  `json:"events"`
	Counters  map[string]FinalCounters `json:"counters"`
	Seal      *NodeSeal                `json:"node_seal,omitempty"`
	Authority *AuthorityReceipt        `json:"authority_receipt,omitempty"`
}
type Signer interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}
type Config struct {
	Path          string
	Header        Header
	Registry      Registry
	Clock         lifecycle.Clock
	Document      policy.Document
	AuthorityKeys map[string]ed25519.PublicKey
	NodeKeys      map[string]ed25519.PublicKey // NodeID/KeyID
	MaxRecords    int
	MaxBytes      int64
}
type Trust struct {
	NodeKeys      map[string]ed25519.PublicKey
	AuthorityKeys map[string]ed25519.PublicKey
	Registry      Registry
	Document      policy.Document
}
type Verdict struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

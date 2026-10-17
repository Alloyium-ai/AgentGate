// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package qualification produces policy-scoped reports from trusted behavior adapters.
package qualification

import (
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"encoding/json"
)

const Version = "agentgate.qualification.v1"
const ContractVersion = "agentgate.qualification.contract.v1"

// Binding names the exact target, source, policy and measured implementation.
// A result from another binding cannot supply coverage for this request.
type Binding struct {
	NodeID             string            `json:"node_id"`
	BootID             string            `json:"boot_id"`
	Challenge          string            `json:"challenge"`
	SourceRevision     string            `json:"source_revision"`
	PolicyDigest       string            `json:"policy_digest"`
	SchemaDigest       string            `json:"schema_digest"`
	Kernel             string            `json:"kernel"`
	Architecture       string            `json:"architecture"`
	BTFSHA256          string            `json:"btf_sha256"`
	KernelConfigSHA256 string            `json:"kernel_config_sha256"`
	InventorySHA256    string            `json:"inventory_sha256"`
	ArtifactDigests    map[string]string `json:"artifact_digests"`
}

type Contract struct {
	CapabilityID  string   `json:"capability_id"`
	Version       string   `json:"version"`
	Cases         []string `json:"cases"`
	Mechanisms    []string `json:"mechanisms"`
	ArtifactNames []string `json:"artifact_names"`
}

type Request struct {
	Binding   Binding         `json:"binding"`
	Document  policy.Document `json:"document"`
	Contracts []Contract      `json:"contracts"`
}

// Result retains raw, bounded evidence. It has no enforced or passed field.
type Result struct {
	Binding        Binding         `json:"binding"`
	StartedMonoNS  uint64          `json:"started_mono_ns,string"`
	FinishedMonoNS uint64          `json:"finished_mono_ns,string"`
	Raw            json.RawMessage `json:"raw"`
}

// Coverage is returned only by a compiled adapter's raw evidence verifier.
// The producer checks it against the complete fixed contract and receipt hash.
type Coverage struct {
	CapabilityID    string   `json:"capability_id"`
	ContractVersion string   `json:"contract_version"`
	Cases           []string `json:"cases"`
	ReceiptSHA256   string   `json:"receipt_sha256"`
}

// Adapter implementations are trusted source, pinned with the report producer.
// Verify must validate raw outcomes, decisions, loss counters, custody and cleanup.
// Caller-provided result summaries cannot replace these checks.
type Adapter interface {
	ID() string
	Run(context.Context, Request) (Result, error)
	Verify(Request, Result) ([]Coverage, error)
}

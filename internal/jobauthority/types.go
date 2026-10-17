// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package jobauthority owns the full-job signer and durable request custody.
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"crypto/ed25519"
	"time"
)

const IssueProtocol = "agentgate.full-job-issue.v1"
const RevokeProtocol = "agentgate.full-job-revoke.v1"
const IssuedProtocol = "agentgate.full-job-issued.v1"
const StateProtocol = "agentgate.full-job-state.v1"
const ReceiptProtocol = "agentgate.full-job-receipt.v1"

type IssueRequest struct {
	Protocol string                    `json:"protocol"`
	Manifest lifecycle.Manifest        `json:"manifest"`
	Prepared lifecycle.PrepareResponse `json:"prepared"`
	Document policy.Document           `json:"document"`
}
type RevokeRequest struct {
	Protocol string `json:"protocol"`
	GrantID  string `json:"grant_id"`
}
type IssueResponse struct {
	Protocol      string                  `json:"protocol"`
	Authorization lifecycle.Authorization `json:"authorization"`
}
type StateResponse struct {
	Protocol string `json:"protocol"`
	GrantID  string `json:"grant_id"`
	Known    bool   `json:"known"`
	Revoked  bool   `json:"revoked"`
}
type ReceiptResponse struct {
	Protocol string                    `json:"protocol"`
	Receipt  jobaudit.AuthorityReceipt `json:"receipt"`
}

// Enrollment pins the agent key, node boot, target artifacts and agent runtime.
type Enrollment interface {
	jobgrant.EnrollmentResolver
	VerifyManifest(context.Context, lifecycle.Binding, lifecycle.Manifest) error
}
type ApprovedDocuments interface {
	Resolve(context.Context, string) (policy.Document, error)
}

// NodeTime comes only from a verified, fresh node preparation signature/readback.
// MonoNS belongs to Binding.BootID. It never uses the authority host epoch.
type NodeTime struct {
	Wall   time.Time
	MonoNS uint64
}
type Preparations interface {
	Verify(context.Context, lifecycle.PrepareResponse) (NodeTime, error)
}
type ProofSubject struct {
	Role string
	Key  ed25519.PublicKey
}
type Config struct {
	AuthorityID    string
	KeyID          string
	SigningKey     ed25519.PrivateKey
	Subjects       map[string]ProofSubject      // exact agent/node subject; roles cannot overlap
	NodeKeys       map[string]ed25519.PublicKey // NodeID/KeyID
	Enrollment     Enrollment
	Documents      ApprovedDocuments
	Qualification  jobgrant.QualificationProvider
	Preparations   Preparations
	Clock          jobgrant.Clock // only the wall component is used by this authority
	Store          *Store
	Registry       func(lifecycle.Binding) jobaudit.Registry
	MaxLifetime    time.Duration
	RequestTimeout time.Duration
}

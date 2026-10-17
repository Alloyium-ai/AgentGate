// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package jobgrant signs full job grants. The node retains only public authority keys.
package jobgrant

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"crypto/ed25519"
	"time"
)

const Protocol = "agentgate.full-job-grant.v1"

type Claims struct {
	Binding              lifecycle.Binding `json:"binding"`
	DocumentDigest       string            `json:"document_digest"`
	RequiredCapabilities []string          `json:"required_capabilities"`
	QualificationDigest  string            `json:"qualification_digest"`
	AuditHeaderDigest    string            `json:"audit_header_digest"`
	IssuedAt             int64             `json:"issued_at"`
	NotBefore            int64             `json:"not_before"`
	ExpiresAt            int64             `json:"expires_at"`
	IssuedMonoNS         uint64            `json:"issued_mono_ns,string"`
	DeadlineNS           uint64            `json:"deadline_ns,string"`
}
type Envelope struct {
	Protocol    string `json:"protocol"`
	AuthorityID string `json:"authority_id"`
	KeyID       string `json:"key_id"`
	Claims      Claims `json:"claims"`
	Signature   string `json:"signature"`
}
type Snapshot struct {
	Target          policy.VerifiedTarget
	CompilerDigest  string
	ArtifactDigests map[string]string
}
type QualificationProvider interface {
	Current(context.Context, lifecycle.Binding) (Snapshot, error)
}
type EnrollmentResolver interface {
	VerifyEnrollment(context.Context, lifecycle.Binding) error
}
type RevocationState struct{ Known, Revoked bool }
type RevocationProvider interface {
	State(context.Context, string) (RevocationState, error)
}
type Clock interface {
	Now() (time.Time, uint64, error)
}
type Config struct {
	Authorities   map[string]ed25519.PublicKey // AuthorityID/KeyID
	Enrollment    EnrollmentResolver
	Qualification QualificationProvider
	Revocation    RevocationProvider
	Clock         Clock
	MaxLifetime   time.Duration
}
type Verifier struct {
	config  Config
	fixture *lifecycle.QualificationFixturePermit
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/credentialstage"
	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/execbroker"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodedns"
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"crypto/ed25519"
	"sync"
)

type Documents interface {
	Resolve(context.Context, string) (policy.Document, error)
}
type ReceiptAuthority interface {
	Countersign(context.Context, jobaudit.Bundle) (jobaudit.AuthorityReceipt, error)
}
type RuntimeVerifier interface {
	VerifyRuntime(context.Context, lifecycle.Binding, lifecycle.Manifest) error
}
type Config struct {
	Domain                  domainstore.Config
	Artifacts               enforcement.Artifacts
	ObservationObject       string
	ObservationProfile      kernel.Profile
	Helper, Broker          string
	ArtifactDigests         map[string]string
	CompilerDigest          string
	ArtifactRoot, AuditRoot string
	OutputLimit             int64
	MaxRuns                 int
	Limits                  Limits
	Resolver                dnslease.Resolver
	Documents               Documents
	Qualification           jobgrant.QualificationProvider
	Verifier                lifecycle.Verifier
	Clock                   lifecycle.Clock
	Signer                  jobaudit.Signer
	NodeKeys, AuthorityKeys map[string]ed25519.PublicKey
	Authority               ReceiptAuthority
	Registry                jobaudit.Registry
	Runtimes                RuntimeVerifier
	Credentials             *CredentialConfig
}

type run struct {
	mu                            sync.Mutex
	binding                       lifecycle.Binding
	reservation                   domainstore.Reservation
	document                      policy.Document
	qualification                 jobgrant.Snapshot
	group                         *enforcement.Group
	observation                   *kernel.Runtime
	plan                          enforcement.Plan
	child                         *enforcement.Child
	broker                        *execbroker.Process
	writer                        *jobaudit.Writer
	header                        jobaudit.Header
	headerBytes                   []byte
	headerDigest                  string
	streams                       jobartifacts.Streams
	manifest                      lifecycle.Manifest
	authorization                 *lifecycle.Authorization
	phase                         string
	collectors                    *collectors
	collectCancel                 context.CancelFunc
	brokerAudit, brokerDiagnostic string
	exitCode                      int
	kernelDeadline                uint64
	stopped                       *lifecycle.Evidence
	terminal                      *lifecycle.Terminal
	dns                           *nodedns.Coordinator
	dnsInitial                    dnslease.Snapshot
	dnsCancel                     context.CancelFunc
	dnsDone                       chan error
	dnsConsumed                   bool
	dnsResult                     error
	controlCount                  uint64
	controlMu                     sync.Mutex
	credentials                   *credentialstage.Stage
}
type Backend struct {
	fixture   *lifecycle.QualificationFixturePermit
	config    Config
	domains   *domainstore.Store
	pins      *PinReader
	artifacts *jobartifacts.Store
	mu        sync.RWMutex
	runs      map[string]*run
}

func (b *Backend) get(id string) (*run, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	r := b.runs[id]
	if r == nil {
		return nil, errUnknownRun
	}
	return r, nil
}
func copyValue[T any](value T) T { return cloneJSON(value) }

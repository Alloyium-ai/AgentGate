// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package nodeapi exposes only the private, authenticated node execution protocol.
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"context"
	"time"
)

type RuntimeArtifact struct {
	Files             []runtimeclosure.File `json:"files"`
	FilesDigest       string                `json:"files_digest"`
	Version           string
	Executable        string
	ExecutableDigest  string
	ImageDigest       string
	ArgumentsPrefix   []string
	EntryScript       string
	EntryScriptDigest string
	PackageRoot       string
	PackageDigest     string
}
type Enrollment struct {
	AgentID  string
	AgentKey string
	PeerUID  uint32
	PeerGID  uint32
	Enabled  bool
	Runtimes map[string]RuntimeArtifact
}
type EnrollmentResolver interface {
	Resolve(context.Context, string) (Enrollment, error)
}
type ProofConsumer interface {
	ConsumeProof(context.Context, string, string, int64) error
}

// NodeOperations owns held helpers, policy verification, kernel state and evidence.
// Target must return a current target verified against pinned enrollment trust.
type NodeOperations interface {
	Target(context.Context) (policy.VerifiedTarget, error)
	Prepare(context.Context, lifecycle.PrepareRequest) (lifecycle.PrepareResponse, error)
	Run(context.Context, lifecycle.RunRequest) (lifecycle.Terminal, error)
	Status(context.Context, string, string) (lifecycle.JobStatus, error)
	Stop(context.Context, lifecycle.StopRequest) (lifecycle.StopResponse, error)
}
type Config struct {
	Identity          lifecycle.Identity
	SocketPath        string
	SocketGID         uint32
	ReadHeaderTimeout time.Duration
	RequestTimeout    time.Duration
	ShutdownTimeout   time.Duration
	Clock             lifecycle.Clock
}

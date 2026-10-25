// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package noderuntime supplies protected configuration for the disposable node.
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/dockerplacement"
	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/nodebackend"
	"bytes"
	"errors"
	"regexp"
	"time"
)

const ConfigProtocol = "agentgate.node-config.v1"

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var hash64 = regexp.MustCompile(`^[a-f0-9]{64}$`)

type QualificationConfig struct {
	ReportFile     string `json:"report_file"`
	PublicKey      string `json:"public_key"`
	Challenge      string `json:"challenge"`
	SourceRevision string `json:"source_revision"`
}
type AuthorityConfig struct {
	SocketPath  string `json:"socket_path"`
	AuthorityID string `json:"authority_id"`
	Epoch       string `json:"epoch"`
	PeerUID     uint32 `json:"peer_uid"`
	TimeoutMS   int    `json:"timeout_ms"`
}
type ResolverConfig struct {
	Address         string `json:"address"`
	ServerName      string `json:"server_name"`
	RootsFile       string `json:"roots_file"`
	RootsFileSHA256 string `json:"roots_file_sha256"`
	TimeoutMS       int    `json:"timeout_ms"`
}
type Config struct {
	Protocol                string                        `json:"protocol"`
	NodeID                  string                        `json:"node_id"`
	InstanceID              string                        `json:"instance_id"`
	NodeKeyID               string                        `json:"node_key_id"`
	NodeKeyFile             string                        `json:"node_key_file"`
	NodeKeys                map[string]string             `json:"node_keys"`
	AuthorityKeys           map[string]string             `json:"authority_keys"`
	SocketPath              string                        `json:"socket_path"`
	SocketGID               uint32                        `json:"socket_gid"`
	WatchdogSocket          string                        `json:"watchdog_socket"`
	WatchdogPublicKey       string                        `json:"watchdog_public_key"`
	WatchdogKeyFile         string                        `json:"watchdog_key_file,omitempty"`
	WatchdogStore           string                        `json:"watchdog_store"`
	OwnedPrefix             string                        `json:"owned_prefix"`
	RootQualificationDigest string                        `json:"root_qualification_digest"`
	DomainState             string                        `json:"domain_state"`
	Journal                 string                        `json:"journal"`
	AuditRoot               string                        `json:"audit_root"`
	ArtifactRoot            string                        `json:"artifact_root"`
	Artifacts               enforcement.Artifacts         `json:"artifacts"`
	ObservationObject       string                        `json:"observation_object"`
	Helper                  string                        `json:"helper"`
	Broker                  string                        `json:"broker"`
	ArtifactDigests         map[string]string             `json:"artifact_digests"`
	Limits                  nodebackend.Limits            `json:"limits"`
	OutputLimit             int64                         `json:"output_limit"`
	MaxRuns                 int                           `json:"max_runs"`
	PreparationLeaseMS      int                           `json:"preparation_lease_ms"`
	StopTimeoutMS           int                           `json:"stop_timeout_ms"`
	RequestTimeoutMS        int                           `json:"request_timeout_ms"`
	Documents               map[string]string             `json:"documents"`
	Enrollments             []nodeapi.Enrollment          `json:"enrollments"`
	Qualification           QualificationConfig           `json:"qualification"`
	Authority               AuthorityConfig               `json:"authority"`
	Resolver                *ResolverConfig               `json:"resolver,omitempty"`
	Credentials             *nodebackend.CredentialConfig `json:"credentials,omitempty"`
	PilotTarget             *dockerplacement.Target       `json:"pilot_target,omitempty"`
}

func ReadConfig(path string) (Config, error) {
	var c Config
	raw, err := readOwned(path, 2<<20, true)
	if err != nil {
		return c, err
	}
	if err = lifecycle.DecodeTransport(bytes.NewReader(raw), &c); err != nil {
		return c, err
	}
	if c.Protocol != ConfigProtocol || !identifier.MatchString(c.NodeID) || !identifier.MatchString(c.InstanceID) || !identifier.MatchString(c.NodeKeyID) || !hash64.MatchString(c.RootQualificationDigest) || c.PreparationLeaseMS <= 0 || c.PreparationLeaseMS > 30000 || c.StopTimeoutMS < 1000 || c.StopTimeoutMS > 30000 || c.RequestTimeoutMS <= 0 || c.RequestTimeoutMS > int((24*time.Hour)/time.Millisecond) || c.OutputLimit <= 0 || c.OutputLimit > lifecycle.MaxInputBytes {
		return c, errors.New("the bounded node configuration is invalid")
	}
	for _, path := range []string{c.SocketPath, c.WatchdogSocket, c.DomainState, c.Journal, c.AuditRoot, c.ArtifactRoot, c.WatchdogStore} {
		if !canonical(path) {
			return c, errors.New("the node configuration has an invalid protected path")
		}
	}
	if c.PilotTarget != nil {
		if err := c.PilotTarget.Validate(); err != nil {
			return c, err
		}
	}
	return c, nil
}

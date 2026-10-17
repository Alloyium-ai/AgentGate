// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/buildinfo"
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodebackend"
	"alloyium.local/kernel-poc/internal/watchdogapi"
	"bytes"
	"context"
	"errors"
	"reflect"
	"time"
)

type WatchdogConfig struct {
	Protocol                string `json:"protocol"`
	NodeID                  string `json:"node_id"`
	InstanceID              string `json:"instance_id"`
	SocketPath              string `json:"socket_path"`
	StatePath               string `json:"state_path"`
	DomainState             string `json:"domain_state"`
	OwnedPrefix             string `json:"owned_prefix"`
	RootQualificationDigest string `json:"root_qualification_digest"`
	KeyFile                 string `json:"key_file"`
	PublicKey               string `json:"public_key"`
	ArtifactDigest          string `json:"artifact_digest"`
	SourceRevision          string `json:"source_revision"`
	StopTimeoutMS           int    `json:"stop_timeout_ms"`
	HeartbeatTimeoutMS      int    `json:"heartbeat_timeout_ms"`
}

func ReadWatchdogConfig(path string) (WatchdogConfig, error) {
	var c WatchdogConfig
	raw, err := readOwned(path, 2<<20, true)
	if err != nil {
		return c, err
	}
	if err = lifecycle.DecodeTransport(bytes.NewReader(raw), &c); err != nil {
		return c, err
	}
	if c.Protocol != "agentgate.watchdog-config.v1" || !identifier.MatchString(c.NodeID) || !identifier.MatchString(c.InstanceID) || !hash64.MatchString(c.RootQualificationDigest) || !hash64.MatchString(c.ArtifactDigest) || c.SourceRevision == "" || c.SourceRevision != buildinfo.SourceRevision || c.StopTimeoutMS < 1000 || c.StopTimeoutMS > 30000 || c.HeartbeatTimeoutMS < 100 || c.HeartbeatTimeoutMS > 2000 {
		return c, errors.New("the watchdog configuration is invalid or differs from CI")
	}
	for _, p := range []string{c.SocketPath, c.StatePath, c.DomainState, c.KeyFile} {
		if !canonical(p) {
			return c, errors.New("a protected watchdog path is invalid")
		}
	}
	return c, nil
}
func ServeWatchdog(ctx context.Context, c WatchdogConfig) error {
	if err := kernel.Preflight(); err != nil {
		return err
	}
	if err := jobartifacts.VerifyRunningExecutable(c.ArtifactDigest); err != nil {
		return err
	}
	owner, err := acquireOwner(c.StatePath + ".owner")
	if err != nil {
		return err
	}
	defer owner.Close()
	proof, err := domainstore.MeasureRoot(c.OwnedPrefix, c.RootQualificationDigest)
	if err != nil {
		return err
	}
	key, err := privateKey(c.KeyFile)
	if err != nil {
		return err
	}
	public, err := publicKey(c.PublicKey)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(public, key.Public()) {
		return errors.New("the watchdog private key differs from its pinned key")
	}
	pins, err := nodebackend.NewPinReader(c.NodeID, proof)
	if err != nil {
		return err
	}
	stop := time.Duration(c.StopTimeoutMS) * time.Millisecond
	domains, err := domainstore.New(domainstore.Config{NodeID: c.NodeID, StateDir: c.DomainState, Proof: proof, StopTimeout: stop, CounterReader: pins, RightsVerifier: pins})
	if err != nil {
		return err
	}
	defer domains.Close()
	store, err := lifecycle.OpenWatchdogStore(c.StatePath)
	if err != nil {
		return err
	}
	defer store.Close()
	core, err := lifecycle.NewIndependentWatchdog(lifecycle.WatchdogConfig{Identity: lifecycle.Identity{NodeID: c.NodeID, BootID: proof.BootID}, InstanceID: c.InstanceID, ArtifactDigest: c.ArtifactDigest, HeartbeatTimeout: time.Duration(c.HeartbeatTimeoutMS) * time.Millisecond, StopTimeout: stop}, key, store, domains, lifecycle.LinuxDaemonMonitor{}, Clock{})
	if err != nil {
		return err
	}
	server := watchdogapi.Server{SocketPath: c.SocketPath, Core: core, RequestTimeout: time.Second, StopTimeout: stop}
	return server.Serve(ctx)
}

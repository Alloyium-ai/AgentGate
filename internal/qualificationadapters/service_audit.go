// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"

	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeaudit"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
)

// VerifyServiceAudit verifies the actual audit emitted by an owned service run.
// The caller supplies keys from its pinned service configuration, never from the
// receipt. It must retain the exact bytes inside its own Adapter.Result.Raw.
// This function supplies no forced-loss or missing-stream execution witness.
func VerifyServiceAudit(request qualification.Request, expected lifecycle.Binding, raw []byte, nodes, authorities map[string]ed25519.PublicKey) ([]qualification.Coverage, error) {
	return VerifyServiceFixtureAudit(request, request.Document, expected, raw, nodes, authorities)
}

// VerifyServiceFixtureAudit supports a fixed, compiled fixture recipe for shared
// audit mechanisms. The enclosing adapter must record both policy digests and
// the actual map readbacks. Fixture rights supply no candidate allowance proof.
func VerifyServiceFixtureAudit(request qualification.Request, executed policy.Document, expected lifecycle.Binding, raw []byte, nodes, authorities map[string]ed25519.PublicKey) ([]qualification.Coverage, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	executedDigest, err := executed.Digest()
	if err != nil {
		return nil, err
	}
	if expected.Validate(false) != nil || expected.NodeID != request.Binding.NodeID || expected.BootID != request.Binding.BootID || expected.PolicyDigest != executedDigest || expected.SchemaDigest != request.Binding.SchemaDigest || !reflect.DeepEqual(expected.ArtifactDigests, request.Binding.ArtifactDigests) {
		return nil, errors.New("the service audit target or candidate binding differs")
	}
	if len(raw) == 0 || len(raw) > 8<<20 || uniqueJSON(raw) != nil {
		return nil, errors.New("the service audit encoding differs")
	}
	bundle, err := jobauthority.DecodeAuditBundle(raw)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(bundle.Header.Binding, expected) || !reflect.DeepEqual(bundle.Header.RequiredCapabilities, executed.RequiredCapabilities) || bundle.Header.DocumentDigest != executedDigest {
		return nil, errors.New("the service audit signed job binding differs")
	}
	if err := verifyServiceStreams(bundle, expected); err != nil {
		return nil, err
	}
	trust := jobaudit.Trust{NodeKeys: nodes, AuthorityKeys: authorities, Registry: nodecontrol.Registry(nodeaudit.Registry(), expected), Document: executed}
	verdict := jobaudit.VerifyOffline(bundle, trust)
	if verdict.State != "VALID_COMPLETE" {
		return nil, fmt.Errorf("the service audit is %s: %s", verdict.State, verdict.Reason)
	}
	// VerifyOffline checks both signatures, exact raw decoders and origins,
	// contiguous counters, loss, terminal cleanup, and control proof ordering.
	cases := []string{"seven-required-streams", "exact-raw-decisions-and-origins", "contiguous-counter-readback", "zero-loss-complete", "node-authority-signatures-distinct", "offline-signature-and-binding-check", "expiry-cutoff-proof-before-activity", "runtime-files-proof-before-activity"}
	return []qualification.Coverage{{CapabilityID: "audit.batch.v1", ContractVersion: qualification.ContractVersion, Cases: cases, ReceiptSHA256: digestBytes(raw)}}, nil
}

func verifyServiceStreams(bundle jobaudit.Bundle, expected lifecycle.Binding) error {
	if len(bundle.Header.RequiredStreams) != 7 || len(bundle.Counters) != 7 {
		return errors.New("the service audit requires seven exact streams")
	}
	streams := map[string]jobaudit.Stream{}
	for name, format := range jobaudit.ResourceFormats() {
		streams[name] = jobaudit.Stream{Name: name, Kind: "resource", Version: format.Version, ArtifactDigest: expected.ArtifactDigests[name]}
	}
	for name, format := range jobaudit.ObservationFormats() {
		streams[name] = jobaudit.Stream{Name: name, Kind: "observation", Version: format.Version, ArtifactDigest: expected.ArtifactDigests[name]}
	}
	streams[nodecontrol.Stream] = jobaudit.Stream{Name: nodecontrol.Stream, Kind: "control", Version: nodecontrol.Version, ArtifactDigest: expected.ArtifactDigests["node"]}
	for _, stream := range bundle.Header.RequiredStreams {
		want, ok := streams[stream.Name]
		counters, present := bundle.Counters[stream.Name]
		if !ok || !reflect.DeepEqual(stream, want) || !present || !counters.Available || counters.Lost != 0 {
			return errors.New("the service audit stream, artifact or loss readback differs")
		}
		delete(streams, stream.Name)
	}
	if len(streams) != 0 {
		return errors.New("a mandatory service audit stream is absent")
	}
	return nil
}

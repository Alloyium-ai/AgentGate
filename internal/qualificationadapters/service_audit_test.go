// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"testing"

	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
)

func TestServiceAuditRejectsMissingRawAndDifferentTarget(t *testing.T) {
	request := adapterRequest(t)
	binding := lifecycle.Binding{}
	for _, raw := range [][]byte{nil, []byte("{}"), []byte(`{"header":{},"header":{}}`)} {
		if coverage, err := VerifyServiceAudit(request, binding, raw, nil, nil); err == nil || len(coverage) != 0 {
			t.Fatal("an absent actual audit supplied coverage")
		}
	}
}
func TestServiceAuditStreamReadbackRejectsLossAndArtifactSubstitution(t *testing.T) {
	binding := lifecycle.Binding{ArtifactDigests: map[string]string{}}
	bundle := jobaudit.Bundle{Counters: map[string]jobaudit.FinalCounters{}}
	for name, format := range jobaudit.ResourceFormats() {
		binding.ArtifactDigests[name] = digestJSON(name)
		bundle.Header.RequiredStreams = append(bundle.Header.RequiredStreams, jobaudit.Stream{Name: name, Kind: "resource", Version: format.Version, ArtifactDigest: binding.ArtifactDigests[name]})
		bundle.Counters[name] = jobaudit.FinalCounters{Available: true}
	}
	for name, format := range jobaudit.ObservationFormats() {
		binding.ArtifactDigests[name] = digestJSON(name)
		bundle.Header.RequiredStreams = append(bundle.Header.RequiredStreams, jobaudit.Stream{Name: name, Kind: "observation", Version: format.Version, ArtifactDigest: binding.ArtifactDigests[name]})
		bundle.Counters[name] = jobaudit.FinalCounters{Available: true}
	}
	binding.ArtifactDigests["node"] = digestJSON("node")
	bundle.Header.RequiredStreams = append(bundle.Header.RequiredStreams, jobaudit.Stream{Name: nodecontrol.Stream, Kind: "control", Version: nodecontrol.Version, ArtifactDigest: binding.ArtifactDigests["node"]})
	bundle.Counters["node"] = jobaudit.FinalCounters{Available: true}
	if err := verifyServiceStreams(bundle, binding); err != nil {
		t.Fatal(err)
	}
	counters := bundle.Counters["files"]
	counters.Lost = 1
	bundle.Counters["files"] = counters
	if err := verifyServiceStreams(bundle, binding); err == nil {
		t.Fatal("lost records supplied zero-loss proof")
	}
	counters.Lost = 0
	bundle.Counters["files"] = counters
	bundle.Header.RequiredStreams[0].ArtifactDigest = digestJSON("other")
	if err := verifyServiceStreams(bundle, binding); err == nil {
		t.Fatal("a different stream artifact supplied proof")
	}
}

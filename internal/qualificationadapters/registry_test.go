// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"os"
	"testing"

	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/testpolicy"
)

func adapterRequest(t *testing.T) qualification.Request {
	t.Helper()
	d := testpolicy.Deny()
	digest, err := d.Digest()
	if err != nil {
		t.Fatal(err)
	}
	contracts, err := qualification.Contracts(d)
	if err != nil {
		t.Fatal(err)
	}
	return qualification.Request{Binding: qualification.Binding{PolicyDigest: digest, SchemaDigest: policy.SchemaDigest(), ArtifactDigests: map[string]string{}}, Document: d, Contracts: contracts}
}
func TestRegistryHasNoCallerSelectedCommandOrClaim(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the protected registry test requires the root test container")
	}
	root := os.Getenv("AGENTGATE_TEST_SCRATCH")
	if root == "" {
		t.Skip("the protected registry scratch is required")
	}
	adapters, err := New(Config{ScratchRoot: root, Artifacts: map[string]string{}})
	if err != nil || len(adapters) != 1 {
		t.Fatal(adapters, err)
	}
	request := adapterRequest(t)
	if _, err = adapters[0].Run(context.Background(), request); err == nil {
		t.Fatal("a missing measured worker produced evidence")
	}
	if coverage, err := adapters[0].Verify(request, qualification.Result{}); err == nil || len(coverage) != 0 {
		t.Fatal("empty raw evidence produced coverage")
	}
}
func TestAdapterRejectsChangedPolicyAndCallerContract(t *testing.T) {
	r := adapterRequest(t)
	r.Binding.PolicyDigest = policy.SchemaDigest()
	if err := validateRequest(r); err == nil {
		t.Fatal("a different policy binding passed")
	}
	r = adapterRequest(t)
	r.Contracts[0].Cases = []string{"caller-says-pass"}
	if err := validateRequest(r); err == nil {
		t.Fatal("a caller-selected contract passed")
	}
}

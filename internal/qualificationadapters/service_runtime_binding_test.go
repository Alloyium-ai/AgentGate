// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"reflect"
	"testing"

	"alloyium.local/kernel-poc/internal/runtimeclosure"
)

func TestIdentityRuntimeKeepsTheCompleteCandidateArtifactMap(t *testing.T) {
	request := adapterRequest(t)
	request.Binding.NodeID = "unit-identity-node"
	request.Binding.BootID = "unit-identity-boot"
	request.Binding.ArtifactDigests["qualification"] = digestJSON("unit-qualifier")
	request.Binding.ArtifactDigests["node"] = digestJSON("unit-node")
	closure, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil {
		t.Fatal(err)
	}
	request.Binding.ArtifactDigests["runtime.codex.files"] = closure.Digest()
	before := serviceJSON(request.Binding.ArtifactDigests)
	input, _, err := serviceRuntimeInput(request, "/var/lib/unit-runtime-fixture", make([]byte, 32))
	if err != nil || !reflect.DeepEqual(input.Binding.ArtifactDigests, request.Binding.ArtifactDigests) || !reflect.DeepEqual(before, serviceJSON(request.Binding.ArtifactDigests)) {
		t.Fatal("the identity runtime changed a candidate artifact", err)
	}
	for _, value := range []string{"", digestJSON("nonempty-candidate-closure")} {
		request.Binding.ArtifactDigests["runtime.codex.files"] = value
		if _, _, err = serviceRuntimeInput(request, "/var/lib/unit-runtime-fixture", make([]byte, 32)); err == nil {
			t.Fatal("the fixed identity actor replaced an existing candidate closure")
		}
	}
}

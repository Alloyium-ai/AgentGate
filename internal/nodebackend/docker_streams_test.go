// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/childwire"
	"alloyium.local/kernel-poc/internal/dockerplacement"
	"testing"
)

func TestDockerStreamsResolveOnlyInsideMeasuredBind(t *testing.T) {
	target := dockerplacement.Target{ArtifactSource: "/var/lib/agentgate/streams", ArtifactPath: "/run/agentgate/streams"}
	host := childwire.IOPaths{
		Input: "/var/lib/agentgate/streams/job-opaque/input", Output: "/var/lib/agentgate/streams/job-opaque/output", Error: "/var/lib/agentgate/streams/job-opaque/error",
	}
	got, err := dockerStreamPaths(host, target)
	if err != nil || got != (childwire.IOPaths{
		Input: "/run/agentgate/streams/job-opaque/input", Output: "/run/agentgate/streams/job-opaque/output", Error: "/run/agentgate/streams/job-opaque/error",
	}) {
		t.Fatal("the Docker child did not receive target-local stream paths", err)
	}
	host.Error = "/var/lib/agentgate/streams-foreign/error"
	if _, err := dockerStreamPaths(host, target); err == nil {
		t.Fatal("a foreign host stream entered the target")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/dockerplacement"
	"testing"
)

func TestPreparedPilotTargetRejectsRestartAndBridgeReplacement(t *testing.T) {
	before := dockerplacement.Measurement{
		ContainerID: "target", ImageDigest: "sha256:target", HostPID: 123,
		StartTimeTicks: "456", Namespaces: map[string]string{"mnt": "mnt:[1]", "net": "net:[2]", "pid": "pid:[3]"},
		WorkspaceDevice: 4, WorkspaceInode: 5, BridgeContainerID: "bridge",
		BridgeDevice: 6, BridgeInode: 7, BridgeTokenIsolated: true,
	}
	if err := matchPreparedPilotTarget(&before, before); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*dockerplacement.Measurement){
		"restart-pid":       func(v *dockerplacement.Measurement) { v.HostPID++ },
		"restart-starttime": func(v *dockerplacement.Measurement) { v.StartTimeTicks = "457" },
		"new-namespace":     func(v *dockerplacement.Measurement) { v.Namespaces = map[string]string{"mnt": "mnt:[8]"} },
		"new-workspace":     func(v *dockerplacement.Measurement) { v.WorkspaceInode++ },
		"new-bridge":        func(v *dockerplacement.Measurement) { v.BridgeContainerID = "other" },
		"new-socket":        func(v *dockerplacement.Measurement) { v.BridgeInode++ },
	} {
		t.Run(name, func(t *testing.T) {
			after := before
			change(&after)
			if err := matchPreparedPilotTarget(&before, after); err == nil {
				t.Fatal("a replacement target passed the prepared measurement")
			}
		})
	}
	if err := matchPreparedPilotTarget(nil, before); err == nil {
		t.Fatal("a missing prepared target passed")
	}
}

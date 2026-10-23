// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"strings"
	"testing"
)

func trustedBridgeFixture() (Target, inspect) {
	t, _ := testTarget()
	t.ArtifactPath = "/run/agentgate/streams"
	t.ArtifactSource = "/owned/streams"
	t.BridgePath = "/run/agentgate/taskboard"
	t.BridgeSource = "/var/lib/docker/volumes/owned-bridge/_data"
	t.BridgeVolume = "owned-bridge"
	t.BridgeTaskID = 42
	t.BridgeContainerID = strings.Repeat("e", 64)
	t.BridgeImageDigest = "sha256:" + strings.Repeat("f", 64)
	t.BridgeNetworkName = "owned-bridge-net"
	t.BridgeUpstreamURL = "http://10.77.0.2:18080/"
	d := inspect{ID: t.BridgeContainerID, Image: t.BridgeImageDigest}
	d.State.Running, d.State.PID = true, 12345
	d.Config.Image, d.Config.User = t.BridgeImageDigest, "root"
	d.Config.Entrypoint = []string{"/usr/local/bin/bun", "/opt/agentgate/taskboard_bridge.mts"}
	d.Config.Env = []string{
		"AGENTGATE_TASKBOARD_SOCKET=/run/agentgate/taskboard/taskboard.sock",
		"AGENTGATE_TASKBOARD_SOCKET_GID=65534",
		"AGENTGATE_TASKBOARD_URL=http://10.77.0.2:18080/",
		"AGENTGATE_TASKBOARD_TASK_ID=42",
		"AGENTGATE_TASKBOARD_TOKEN_FILE=/run/secrets/taskboard-token",
		"AGENTGATE_TASKBOARD_SNAPSHOT=/run/agentgate/taskboard/task.json",
	}
	d.HostConfig.ReadonlyRoot, d.HostConfig.NetworkMode = true, t.BridgeNetworkName
	d.HostConfig.CapDrop, d.HostConfig.CapAdd = []string{"ALL"}, []string{"CHOWN"}
	d.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	d.HostConfig.PidsLimit, d.HostConfig.Memory = 32, 256<<20
	d.NetworkSettings.Networks = map[string]networkAttachment{t.BridgeNetworkName: {NetworkID: strings.Repeat("d", 64)}}
	d.Mounts = []mount{
		{Type: "volume", Name: t.BridgeVolume, Source: t.BridgeSource, Destination: t.BridgePath, RW: true},
		{Type: "bind", Source: "/owned/secrets/taskboard.token", Destination: "/run/secrets/taskboard-token", RW: false},
	}
	return t, d
}

func TestTrustedBridgeRequiresPinnedSeparateImageAndExactUpstream(t *testing.T) {
	target, bridge := trustedBridgeFixture()
	if err := target.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := validateBridgeInspect(target, bridge); err != nil {
		t.Fatal(err)
	}
	bridge.HostConfig.CapAdd = []string{"CAP_CHOWN"}
	if err := validateBridgeInspect(target, bridge); err != nil {
		t.Fatalf("Docker-normalized CHOWN was rejected: %v", err)
	}
	if !target.MatchesPilot(42, "10.77.0.2", 18080) || target.MatchesPilot(42, "10.77.0.3", 18080) || target.MatchesPilot(43, "10.77.0.2", 18080) {
		t.Fatal("the trusted bridge upstream lost its signed pilot binding")
	}
	for name, change := range map[string]func(*inspect){
		"entrypoint":    func(d *inspect) { d.Config.Entrypoint[1] = "/bin/sh" },
		"task":          func(d *inspect) { d.Config.Env[3] = "AGENTGATE_TASKBOARD_TASK_ID=43" },
		"upstream":      func(d *inspect) { d.Config.Env[2] = "AGENTGATE_TASKBOARD_URL=http://10.77.0.3:18080/" },
		"duplicate env": func(d *inspect) { d.Config.Env = append(d.Config.Env, d.Config.Env[3]) },
		"host network":  func(d *inspect) { d.HostConfig.NetworkMode = "host" },
		"privileged":    func(d *inspect) { d.HostConfig.Privileged = true },
		"extra capability": func(d *inspect) { d.HostConfig.CapAdd = []string{"CAP_CHOWN", "CAP_NET_ADMIN"} },
		"wrong capability": func(d *inspect) { d.HostConfig.CapAdd = []string{"CAP_NET_ADMIN"} },
		"extra mount": func(d *inspect) {
			d.Mounts = append(d.Mounts, mount{Type: "bind", Destination: "/var/run/docker.sock"})
		},
		"token writable":            func(d *inspect) { d.Mounts[1].RW = true },
		"token in workspace":        func(d *inspect) { d.Mounts[1].Source = target.WorkspaceSource },
		"token below workspace":     func(d *inspect) { d.Mounts[1].Source = target.WorkspaceSource + "/token" },
		"token below bridge volume": func(d *inspect) { d.Mounts[1].Source = target.BridgeSource + "/token" },
		"token below stream mount":  func(d *inspect) { d.Mounts[1].Source = target.ArtifactSource + "/token" },
		"socket readonly":           func(d *inspect) { d.Mounts[0].RW = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := bridge
			candidate.Config.Entrypoint = append([]string{}, bridge.Config.Entrypoint...)
			candidate.Config.Env = append([]string{}, bridge.Config.Env...)
			candidate.Mounts = append([]mount{}, bridge.Mounts...)
			change(&candidate)
			if err := validateBridgeInspect(target, candidate); err == nil {
				t.Fatal("an untrusted bridge configuration was accepted")
			}
		})
	}
	for _, upstream := range []string{"http://taskboard.example:18080/", "http://10.77.0.2:18080/else", "http://10.77.0.2:18080/?q=1", "http://1.1.1.1:18080/"} {
		bad := target
		bad.BridgeUpstreamURL = upstream
		if err := bad.Validate(); err == nil {
			t.Fatalf("nonprivate or broad bridge upstream passed: %s", upstream)
		}
	}
}

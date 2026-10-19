// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerReadbackUsesSupportedAPIVersion(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.44/version" {
			http.Error(w, "client API version unavailable", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"supported"}`))
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	var result struct {
		Version string `json:"version"`
	}
	if err := readJSON(context.Background(), Target{SocketPath: socket}, "version", &result); err != nil || result.Version != "supported" {
		t.Fatal("Docker readback did not use the supported API version", err, result)
	}
}

func testTarget() (Target, inspect) {
	t := Target{SocketPath: "/run/docker.sock", ContainerID: strings.Repeat("a", 64),
		ImageDigest: "sha256:" + strings.Repeat("b", 64), NetworkName: "owned-net",
		Workspace: "/work", WorkspaceVolume: "owned", WorkspaceSource: "/var/lib/docker/volumes/owned/_data"}
	d := inspect{ID: t.ContainerID, Image: t.ImageDigest}
	d.State.Running, d.State.PID = true, 1234
	d.Config.Image, d.Config.User = "registry.invalid/owned@sha256:"+strings.Repeat("c", 64), "65534:65534"
	t.ImageReference = d.Config.Image
	d.HostConfig.ReadonlyRoot, d.HostConfig.NetworkMode = true, t.NetworkName
	d.HostConfig.CapDrop = []string{"ALL"}
	d.HostConfig.SecurityOpt = []string{"no-new-privileges:true"}
	d.HostConfig.PidsLimit, d.HostConfig.Memory = 64, 512<<20
	d.NetworkSettings.Networks = map[string]networkAttachment{t.NetworkName: {NetworkID: strings.Repeat("d", 64)}}
	d.Mounts = []mount{{Type: "volume", Name: t.WorkspaceVolume, Source: t.WorkspaceSource, Destination: t.Workspace, RW: true}}
	return t, d
}

func TestTargetRequiresPinnedRestrictedContainer(t *testing.T) {
	target, good := testTarget()
	if err := target.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := validateInspect(target, good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*inspect){
		"wrong ID":         func(d *inspect) { d.ID = strings.Repeat("0", 64) },
		"stopped":          func(d *inspect) { d.State.Running = false },
		"tagged image":     func(d *inspect) { d.Config.Image = "registry.invalid/owned:latest" },
		"privileged":       func(d *inspect) { d.HostConfig.Privileged = true },
		"writable root":    func(d *inspect) { d.HostConfig.ReadonlyRoot = false },
		"host pid":         func(d *inspect) { d.HostConfig.PIDMode = "host" },
		"host net":         func(d *inspect) { d.HostConfig.NetworkMode = "host" },
		"shared IPC":       func(d *inspect) { d.HostConfig.IPCMode = "container:foreign" },
		"shared cgroup":    func(d *inspect) { d.HostConfig.CgroupnsMode = "host" },
		"user remap":       func(d *inspect) { d.HostConfig.UsernsMode = "host" },
		"foreign tmpfs":    func(d *inspect) { d.HostConfig.Tmpfs = map[string]string{"/run": "mode=0777"} },
		"device request":   func(d *inspect) { d.HostConfig.DeviceRequests = []json.RawMessage{json.RawMessage(`{}`)} },
		"extra cap":        func(d *inspect) { d.HostConfig.CapAdd = []string{"SYS_ADMIN"} },
		"unbounded pid":    func(d *inspect) { d.HostConfig.PidsLimit = 0 },
		"unbounded memory": func(d *inspect) { d.HostConfig.Memory = 0 },
		"extra network": func(d *inspect) {
			d.NetworkSettings.Networks["foreign"] = networkAttachment{NetworkID: strings.Repeat("e", 64)}
		},
		"Docker socket mount": func(d *inspect) {
			d.Mounts = append(d.Mounts, d.Mounts[0])
			d.Mounts[1].Destination = "/var/run/docker.sock"
		},
		"foreign workspace":   func(d *inspect) { d.Mounts[0].Source = "/other" },
		"foreign volume":      func(d *inspect) { d.Mounts[0].Name = "other" },
		"host bind":           func(d *inspect) { d.Mounts[0].Type = "bind" },
		"read-only workspace": func(d *inspect) { d.Mounts[0].RW = false },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := good
			candidate.Mounts = append([]mount{}, good.Mounts...)
			candidate.NetworkSettings.Networks = map[string]networkAttachment{target.NetworkName: {NetworkID: strings.Repeat("d", 64)}}
			mutate(&candidate)
			if err := validateInspect(target, candidate); err == nil {
				t.Fatal("unsafe target accepted")
			}
		})
	}
}

func TestTargetPinsTheInspectedImageContent(t *testing.T) {
	target, container := testTarget()
	good := image{ID: container.Image, RepoDigests: []string{container.Config.Image}}
	good.Config.Labels = map[string]string{"org.opencontainers.image.revision": strings.Repeat("f", 40)}
	if err := validateImage(target, container, good); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*image){
		"different image ID": func(i *image) { i.ID = "sha256:" + strings.Repeat("d", 64) },
		"missing digest":     func(i *image) { i.RepoDigests = nil },
		"other manifest":     func(i *image) { i.RepoDigests = []string{"registry.invalid/owned@sha256:" + strings.Repeat("e", 64)} },
		"missing revision":   func(i *image) { i.Config.Labels = nil },
		"invalid revision":   func(i *image) { i.Config.Labels = map[string]string{"org.opencontainers.image.revision": "unbuilt"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := good
			mutate(&candidate)
			if err := validateImage(target, container, candidate); err == nil {
				t.Fatal("an image without the signed manifest digest passed")
			}
		})
	}
	local := container
	local.Config.Image = container.Image
	localTarget := target
	localTarget.ImageDigest = container.Image
	localTarget.ImageReference = ""
	if err := validateInspect(localTarget, local); err != nil {
		t.Fatal(err)
	}
	localImage := image{ID: local.Image}
	localImage.Config.Labels = good.Config.Labels
	if err := validateImage(localTarget, local, localImage); err != nil {
		t.Fatal(err)
	}
	local.Config.Image = "sha256:" + strings.Repeat("0", 64)
	if err := validateInspect(localTarget, local); err == nil {
		t.Fatal("a local image alias with different content passed")
	}
}

func TestPilotAdmissionRequiresExactRegistryReferences(t *testing.T) {
	target, container := testTarget()
	target.BridgeImageDigest = "sha256:" + strings.Repeat("e", 64)
	target.ImageReference = ""
	if target.RegistryReady() == nil {
		t.Fatal("a local diagnostic image opened normal admission")
	}
	target.ImageReference = container.Config.Image
	target.BridgeImageReference = "registry.invalid/agentgate/bridge@sha256:" + strings.Repeat("a", 64)
	if err := target.RegistryReady(); err != nil {
		t.Fatal(err)
	}
	image := image{ID: container.Image, RepoDigests: []string{container.Config.Image}}
	image.Config.Labels = map[string]string{"org.opencontainers.image.revision": strings.Repeat("f", 40)}
	if err := validateImage(target, container, image); err != nil {
		t.Fatal(err)
	}
	// A registry manifest digest and the local Docker config digest are distinct.
	// Both readbacks must match their own configured value.
	if target.ImageDigest == strings.TrimPrefix(container.Config.Image, "registry.invalid/owned@") {
		t.Fatal("the fixture failed to distinguish Docker's two digests")
	}
	wrongContent := image
	wrongContent.ID = "sha256:" + strings.Repeat("c", 64)
	wrongContainer := container
	wrongContainer.Image = wrongContent.ID
	if validateImage(target, wrongContainer, wrongContent) == nil {
		t.Fatal("a correct registry manifest with another local config digest passed")
	}
	for name, change := range map[string]func(*Target){
		"missing target":      func(t *Target) { t.ImageReference = "" },
		"missing bridge":      func(t *Target) { t.BridgeImageReference = "" },
		"tagged target":       func(t *Target) { t.ImageReference = "registry.invalid/owned:latest" },
		"wrong bridge digest": func(t *Target) { t.BridgeImageReference += "0" },
		"unscoped registry":   func(t *Target) { t.ImageReference = "owned@" + t.ImageDigest },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := target
			change(&candidate)
			if candidate.RegistryReady() == nil {
				t.Fatal("an unpinned image reference opened normal admission")
			}
		})
	}
	changed := container
	changed.Config.Image = "other.invalid/owned@" + target.ImageDigest
	if validateInspect(target, changed) == nil {
		t.Fatal("an image from another registry passed target custody")
	}
	image.RepoDigests = []string{"other.invalid/owned@" + target.ImageDigest}
	if validateImage(target, container, image) == nil {
		t.Fatal("the expected registry digest is absent")
	}
}

func TestTargetRejectsForeignAndDriverBackedVolumes(t *testing.T) {
	target, _ := testTarget()
	good := volume{Name: target.WorkspaceVolume, Driver: "local", Scope: "local", Mountpoint: target.WorkspaceSource}
	if err := validateVolume(target, good); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []volume{
		{Name: "other", Driver: "local", Scope: "local", Mountpoint: target.WorkspaceSource},
		{Name: good.Name, Driver: "remote", Scope: "local", Mountpoint: good.Mountpoint},
		{Name: good.Name, Driver: "local", Scope: "global", Mountpoint: good.Mountpoint},
		{Name: good.Name, Driver: "local", Scope: "local", Mountpoint: "/other"},
		{Name: good.Name, Driver: "local", Scope: "local", Mountpoint: good.Mountpoint, Options: map[string]string{"type": "nfs"}},
	} {
		if err := validateVolume(target, candidate); err == nil {
			t.Fatalf("unsafe volume accepted: %+v", candidate)
		}
	}
}

func TestTargetRejectsDockerPathInjection(t *testing.T) {
	target, _ := testTarget()
	for _, unsafe := range []string{"", "../other", "owned?next=other", "owned#fragment", "owned/name"} {
		candidate := target
		candidate.WorkspaceVolume = unsafe
		if err := candidate.Validate(); err == nil {
			t.Fatalf("unsafe Docker volume name %q accepted", unsafe)
		}
	}
}

func TestTargetRequiresOnlyTheExactStreamMount(t *testing.T) {
	target, docker := testTarget()
	target.ArtifactPath, target.ArtifactSource = "/run/agentgate/streams", "/var/lib/agentgate/streams"
	if err := target.Validate(); err != nil {
		t.Fatal(err)
	}
	docker.Mounts = append(docker.Mounts, mount{Type: "bind", Source: target.ArtifactSource, Destination: target.ArtifactPath, RW: true})
	if err := validateInspect(target, docker); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*inspect){
		func(d *inspect) { d.Mounts[1].Source = "/etc" },
		func(d *inspect) { d.Mounts[1].Destination = "/run/docker.sock" },
		func(d *inspect) { d.Mounts[1].RW = false },
		func(d *inspect) {
			d.Mounts = append(d.Mounts, mount{Type: "bind", Source: "/", Destination: "/host", RW: true})
		},
	} {
		candidate := docker
		candidate.Mounts = append([]mount{}, docker.Mounts...)
		change(&candidate)
		if err := validateInspect(target, candidate); err == nil {
			t.Fatal("an unsafe target stream mount passed")
		}
	}
}

func TestTargetRequiresReadOnlyScopedBridgeVolume(t *testing.T) {
	target, docker := testTarget()
	target.BridgePath = "/run/agentgate/taskboard"
	target.BridgeVolume = "owned-bridge"
	target.BridgeSource = "/var/lib/docker/volumes/owned-bridge/_data"
	target.BridgeTaskID = 42
	target.BridgeContainerID = strings.Repeat("e", 64)
	target.BridgeImageDigest = "sha256:" + strings.Repeat("f", 64)
	target.BridgeNetworkName = "owned-bridge-net"
	target.BridgeUpstreamURL = "http://10.77.0.2:18080/"
	if err := target.Validate(); err != nil {
		t.Fatal(err)
	}
	docker.Mounts = append(docker.Mounts, mount{Type: "volume", Name: target.BridgeVolume, Source: target.BridgeSource, Destination: target.BridgePath, RW: false})
	if err := validateInspect(target, docker); err != nil {
		t.Fatal(err)
	}
	if err := validateBridgeVolume(target, volume{Name: target.BridgeVolume, Driver: "local", Scope: "local", Mountpoint: target.BridgeSource}); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*inspect){
		func(d *inspect) { d.Mounts[1].RW = true },
		func(d *inspect) { d.Mounts[1].Source = "/other" },
		func(d *inspect) { d.Mounts[1].Name = "foreign" },
		func(d *inspect) { d.Mounts[1].Type = "bind" },
	} {
		candidate := docker
		candidate.Mounts = append([]mount{}, docker.Mounts...)
		change(&candidate)
		if err := validateInspect(target, candidate); err == nil {
			t.Fatal("an unsafe taskboard bridge mount passed")
		}
	}
	bad := target
	bad.BridgeVolume = ""
	if err := bad.Validate(); err == nil {
		t.Fatal("a partial bridge identity passed")
	}
}

func TestTargetRequiresItsDedicatedLocalBridge(t *testing.T) {
	target, container := testTarget()
	bridge := network{ID: strings.Repeat("d", 64), Name: target.NetworkName, Driver: "bridge", Scope: "local"}
	if err := validateNetwork(target, container, bridge); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*network){
		func(n *network) { n.ID = strings.Repeat("e", 64) },
		func(n *network) { n.Driver = "macvlan" },
		func(n *network) { n.Scope = "swarm" },
		func(n *network) { n.Internal = true },
		func(n *network) { n.Ingress = true },
		func(n *network) { n.Attachable = true },
	} {
		candidate := bridge
		mutate(&candidate)
		if err := validateNetwork(target, container, candidate); err == nil {
			t.Fatal("a foreign or shared network passed")
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package dockerplacement measures a dedicated Docker target before placement.
// A measurement does not authorize a workload or grant access to Docker.
package dockerplacement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var identifier = regexp.MustCompile(`^[a-f0-9]{64}$`)
var revision = regexp.MustCompile(`^[a-f0-9]{40}$`)
var dockerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type Target struct {
	SocketPath           string `json:"socket_path"`
	ContainerID          string `json:"container_id"`
	ImageDigest          string `json:"image_digest"`
	ImageReference       string `json:"image_reference,omitempty"`
	NetworkName          string `json:"network_name"`
	Workspace            string `json:"workspace"`
	WorkspaceVolume      string `json:"workspace_volume"`
	WorkspaceSource      string `json:"workspace_source"`
	ArtifactPath         string `json:"artifact_path,omitempty"`
	ArtifactSource       string `json:"artifact_source,omitempty"`
	BridgePath           string `json:"bridge_path,omitempty"`
	BridgeSource         string `json:"bridge_source,omitempty"`
	BridgeVolume         string `json:"bridge_volume,omitempty"`
	BridgeTaskID         int    `json:"bridge_task_id,omitempty"`
	BridgeContainerID    string `json:"bridge_container_id,omitempty"`
	BridgeImageDigest    string `json:"bridge_image_digest,omitempty"`
	BridgeImageReference string `json:"bridge_image_reference,omitempty"`
	BridgeNetworkName    string `json:"bridge_network_name,omitempty"`
	BridgeUpstreamURL    string `json:"bridge_upstream_url,omitempty"`
	// HostMounts lists the only approved host folder binds. Absent means none.
	HostMounts []HostMount `json:"host_mounts,omitempty"`
}

// RegistryReady is required for normal pilot admission. An empty reference
// remains available to fixed local-image diagnostics, which cannot admit work.
func (t Target) RegistryReady() error {
	if !registryReference(t.ImageReference) || !registryReference(t.BridgeImageReference) {
		return errors.New("the SSH pilot requires pinned target and bridge registry references")
	}
	return nil
}

func registryReference(reference string) bool {
	name, got, ok := strings.Cut(reference, "@")
	if !ok || !strings.HasPrefix(got, "sha256:") ||
		!identifier.MatchString(strings.TrimPrefix(got, "sha256:")) ||
		strings.Contains(name, "@") || strings.ContainsAny(name, " \t\n\r?#") {
		return false
	}
	registry, path, ok := strings.Cut(name, "/")
	if !ok || registry == "" || path == "" ||
		(!strings.Contains(registry, ".") && !strings.Contains(registry, ":") && registry != "localhost") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

type Measurement struct {
	ContainerID               string                 `json:"container_id"`
	ImageDigest               string                 `json:"image_digest"`
	ImageSourceRevision       string                 `json:"image_source_revision"`
	HostPID                   int                    `json:"host_pid"`
	StartTimeTicks            string                 `json:"start_time_ticks"`
	Namespaces                map[string]string      `json:"namespaces"`
	WorkspaceDevice           uint64                 `json:"workspace_device"`
	WorkspaceInode            uint64                 `json:"workspace_inode"`
	ArtifactDevice            uint64                 `json:"artifact_device,omitempty"`
	ArtifactInode             uint64                 `json:"artifact_inode,omitempty"`
	BridgeDevice              uint64                 `json:"bridge_device,omitempty"`
	BridgeInode               uint64                 `json:"bridge_inode,omitempty"`
	BridgeTaskID              int                    `json:"bridge_task_id,omitempty"`
	BridgeContainerID         string                 `json:"bridge_container_id,omitempty"`
	BridgeImageDigest         string                 `json:"bridge_image_digest,omitempty"`
	BridgeImageSourceRevision string                 `json:"bridge_image_source_revision,omitempty"`
	BridgeTokenIsolated       bool                   `json:"bridge_token_isolated,omitempty"`
	HostMounts                []HostMountMeasurement `json:"host_mounts,omitempty"`
}

type mount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

type networkAttachment struct {
	NetworkID string `json:"NetworkID"`
}

type inspect struct {
	ID    string `json:"Id"`
	Image string `json:"Image"`
	State struct {
		PID     int  `json:"Pid"`
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		Image      string   `json:"Image"`
		User       string   `json:"User"`
		Entrypoint []string `json:"Entrypoint"`
		Cmd        []string `json:"Cmd"`
		Env        []string `json:"Env"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool              `json:"Privileged"`
		ReadonlyRoot   bool              `json:"ReadonlyRootfs"`
		PIDMode        string            `json:"PidMode"`
		IPCMode        string            `json:"IpcMode"`
		UTSMode        string            `json:"UTSMode"`
		UsernsMode     string            `json:"UsernsMode"`
		CgroupnsMode   string            `json:"CgroupnsMode"`
		NetworkMode    string            `json:"NetworkMode"`
		Tmpfs          map[string]string `json:"Tmpfs"`
		Devices        []json.RawMessage `json:"Devices"`
		DeviceRequests []json.RawMessage `json:"DeviceRequests"`
		CapAdd         []string          `json:"CapAdd"`
		CapDrop        []string          `json:"CapDrop"`
		SecurityOpt    []string          `json:"SecurityOpt"`
		PidsLimit      int64             `json:"PidsLimit"`
		Memory         int64             `json:"Memory"`
	} `json:"HostConfig"`
	Mounts          []mount `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]networkAttachment `json:"Networks"`
	} `json:"NetworkSettings"`
}

type network struct {
	ID         string `json:"Id"`
	Name       string `json:"Name"`
	Driver     string `json:"Driver"`
	Scope      string `json:"Scope"`
	Internal   bool   `json:"Internal"`
	Ingress    bool   `json:"Ingress"`
	Attachable bool   `json:"Attachable"`
}

type volume struct {
	Name       string            `json:"Name"`
	Driver     string            `json:"Driver"`
	Mountpoint string            `json:"Mountpoint"`
	Options    map[string]string `json:"Options"`
	Scope      string            `json:"Scope"`
}

type image struct {
	ID          string   `json:"Id"`
	RepoDigests []string `json:"RepoDigests"`
	Config      struct {
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
}

func (t Target) Validate() error {
	if !identifier.MatchString(t.ContainerID) || !strings.HasPrefix(t.ImageDigest, "sha256:") ||
		!identifier.MatchString(strings.TrimPrefix(t.ImageDigest, "sha256:")) ||
		!absolute(t.SocketPath) || !absolute(t.Workspace) || !absolute(t.WorkspaceSource) ||
		!dockerName.MatchString(t.NetworkName) || !dockerName.MatchString(t.WorkspaceVolume) ||
		t.NetworkName == "host" || t.NetworkName == "none" || t.NetworkName == "bridge" {
		return errors.New("the Docker target configuration is incomplete")
	}
	if t.ImageReference != "" && !registryReference(t.ImageReference) ||
		t.BridgeImageReference != "" && !registryReference(t.BridgeImageReference) {
		return errors.New("the Docker image registry reference is invalid")
	}
	if (t.ArtifactPath == "") != (t.ArtifactSource == "") ||
		(t.ArtifactPath != "" && (!absolute(t.ArtifactPath) || !absolute(t.ArtifactSource) ||
			t.ArtifactPath == t.Workspace || t.ArtifactSource == t.WorkspaceSource ||
			strings.HasPrefix(t.ArtifactPath, t.Workspace+"/") || strings.HasPrefix(t.Workspace, t.ArtifactPath+"/") ||
			strings.HasPrefix(t.ArtifactSource, t.WorkspaceSource+"/"))) {
		return errors.New("the Docker target artifact mount configuration differs")
	}
	if (t.BridgePath == "") != (t.BridgeSource == "") || (t.BridgePath == "") != (t.BridgeVolume == "") ||
		(t.BridgePath == "") != (t.BridgeTaskID == 0) ||
		(t.BridgePath == "") != (t.BridgeContainerID == "") ||
		(t.BridgePath == "") != (t.BridgeImageDigest == "") ||
		(t.BridgePath == "") != (t.BridgeNetworkName == "") ||
		(t.BridgePath == "") != (t.BridgeUpstreamURL == "") ||
		(t.BridgePath != "" && (!absolute(t.BridgePath) || !absolute(t.BridgeSource) || !dockerName.MatchString(t.BridgeVolume) ||
			!identifier.MatchString(t.BridgeContainerID) || t.BridgeContainerID == t.ContainerID || !strings.HasPrefix(t.BridgeImageDigest, "sha256:") ||
			!identifier.MatchString(strings.TrimPrefix(t.BridgeImageDigest, "sha256:")) ||
			!dockerName.MatchString(t.BridgeNetworkName) || t.BridgeNetworkName == t.NetworkName ||
			!validBridgeUpstream(t.BridgeUpstreamURL) ||
			t.BridgeVolume == t.WorkspaceVolume || t.BridgeTaskID < 1 ||
			t.BridgePath == t.Workspace || t.BridgePath == t.ArtifactPath || t.BridgeSource == t.WorkspaceSource ||
			t.BridgeSource == t.ArtifactSource || strings.HasPrefix(t.BridgePath, t.Workspace+"/") ||
			(t.ArtifactPath != "" && (strings.HasPrefix(t.BridgePath, t.ArtifactPath+"/") || strings.HasPrefix(t.ArtifactPath, t.BridgePath+"/"))) ||
			strings.HasPrefix(t.Workspace, t.BridgePath+"/"))) {
		return errors.New("the Docker target taskboard bridge mount differs")
	}
	return validateHostMounts(t)
}

func absolute(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && !strings.ContainsRune(path, 0)
}

func readJSON(ctx context.Context, t Target, path string, out any) error {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("the Docker inspect redirect is forbidden")
	}, Transport: &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", t.SocketPath)
		},
	}}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.44/"+path, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > 1<<20 {
		return errors.New("the Docker inspect response is unavailable or oversized")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return errors.New("the Docker inspect response exceeds its bound")
	}
	if err = json.Unmarshal(raw, out); err != nil {
		return errors.New("the Docker inspect response is invalid")
	}
	return nil
}

func readInspect(ctx context.Context, t Target) (inspect, error) {
	var out inspect
	err := readJSON(ctx, t, "containers/"+t.ContainerID+"/json", &out)
	return out, err
}

func readImage(ctx context.Context, t Target, id string) (image, error) {
	var out image
	if !strings.HasPrefix(id, "sha256:") || !identifier.MatchString(strings.TrimPrefix(id, "sha256:")) {
		return out, errors.New("the Docker image ID is invalid")
	}
	err := readJSON(ctx, t, "images/"+id+"/json", &out)
	return out, err
}

func readVolume(ctx context.Context, t Target) (volume, error) {
	var out volume
	err := readJSON(ctx, t, "volumes/"+t.WorkspaceVolume, &out)
	return out, err
}

func readBridgeVolume(ctx context.Context, t Target) (volume, error) {
	var out volume
	err := readJSON(ctx, t, "volumes/"+t.BridgeVolume, &out)
	return out, err
}

func readNetwork(ctx context.Context, t Target) (network, error) {
	var out network
	err := readJSON(ctx, t, "networks/"+t.NetworkName, &out)
	return out, err
}

func validateInspect(t Target, d inspect) error {
	if d.ID != t.ContainerID || !d.State.Running || d.State.PID <= 1 ||
		!pinnedImageReference(t, d) || d.Config.User != "65534:65534" ||
		!strings.HasPrefix(d.Image, "sha256:") || !identifier.MatchString(strings.TrimPrefix(d.Image, "sha256:")) {
		return errors.New("the running Docker target identity differs")
	}
	h := d.HostConfig
	if h.Privileged || !h.ReadonlyRoot || h.PIDMode != "" || (h.IPCMode != "" && h.IPCMode != "private") || h.UTSMode != "" ||
		h.UsernsMode != "" || (h.CgroupnsMode != "" && h.CgroupnsMode != "private") || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 ||
		h.NetworkMode != t.NetworkName || len(h.CapAdd) != 0 || h.PidsLimit < 2 || h.PidsLimit > 128 ||
		h.Memory < 64<<20 || h.Memory > 2<<30 || !contains(h.CapDrop, "ALL") ||
		(!contains(h.SecurityOpt, "no-new-privileges:true") && !contains(h.SecurityOpt, "no-new-privileges")) {
		return errors.New("the Docker target isolation settings differ")
	}
	if len(h.Tmpfs) > 1 || (len(h.Tmpfs) == 1 && h.Tmpfs["/tmp"] != "mode=0700,size=64m" && h.Tmpfs["/tmp"] != "size=64m,mode=0700") {
		return errors.New("the Docker target tmpfs settings differ")
	}
	if len(d.NetworkSettings.Networks) != 1 || !identifier.MatchString(d.NetworkSettings.Networks[t.NetworkName].NetworkID) {
		return errors.New("the Docker target network differs")
	}
	wantMounts := 1
	if t.ArtifactPath != "" {
		wantMounts++
	}
	if t.BridgePath != "" {
		wantMounts++
	}
	wantMounts += len(t.HostMounts)
	if len(d.Mounts) != wantMounts {
		return errors.New("the Docker target workspace mount differs")
	}
	workspace, artifacts, bridge := false, t.ArtifactPath == "", t.BridgePath == ""
	hostMounts := make([]bool, len(t.HostMounts))
	for _, mounted := range d.Mounts {
		if matchHostMount(t, mounted, hostMounts) {
			continue
		}
		switch {
		case mounted.Destination == t.Workspace && mounted.Source == t.WorkspaceSource &&
			mounted.Name == t.WorkspaceVolume && mounted.RW && mounted.Type == "volume":
			workspace = true
		case t.ArtifactPath != "" && mounted.Destination == t.ArtifactPath &&
			mounted.Source == t.ArtifactSource && mounted.RW && mounted.Type == "bind":
			artifacts = true
		case t.BridgePath != "" && mounted.Destination == t.BridgePath &&
			mounted.Source == t.BridgeSource && mounted.Name == t.BridgeVolume && !mounted.RW && mounted.Type == "volume":
			bridge = true
		default:
			return errors.New("the Docker target has an unapproved mount")
		}
	}
	if !workspace || !artifacts || !bridge {
		return errors.New("the Docker target stream or workspace mount is absent")
	}
	for _, used := range hostMounts {
		if !used {
			return errors.New("an approved host folder mount is absent")
		}
	}
	return nil
}

func pinnedImageReference(t Target, d inspect) bool {
	if t.ImageReference != "" {
		return d.Config.Image == t.ImageReference
	}
	if d.Config.Image == t.ImageDigest && d.Image == t.ImageDigest {
		return true // Content-addressed local diagnostic image.
	}
	name, digest, ok := strings.Cut(d.Config.Image, "@")
	return ok && name != "" && !strings.Contains(name, "@") && digest == t.ImageDigest
}

func validateImage(t Target, d inspect, i image) error {
	if i.ID != d.Image || i.ID != t.ImageDigest || !pinnedImageReference(t, d) ||
		!revision.MatchString(i.Config.Labels["org.opencontainers.image.revision"]) {
		return errors.New("the Docker image content differs from the target")
	}
	if d.Config.Image == t.ImageDigest {
		return nil
	}
	for _, reference := range i.RepoDigests {
		if reference == d.Config.Image {
			return nil
		}
	}
	return errors.New("the Docker image lacks the pinned registry manifest digest")
}

func validateNetwork(t Target, d inspect, n network) error {
	if n.Name != t.NetworkName || !identifier.MatchString(n.ID) ||
		n.ID != d.NetworkSettings.Networks[t.NetworkName].NetworkID ||
		n.Driver != "bridge" || n.Scope != "local" || n.Internal || n.Ingress || n.Attachable {
		return errors.New("the Docker target has no dedicated local bridge")
	}
	return nil
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if strings.EqualFold(item, value) {
			return true
		}
	}
	return false
}

func validateVolume(t Target, v volume) error {
	if v.Name != t.WorkspaceVolume || v.Driver != "local" || v.Scope != "local" ||
		v.Mountpoint != t.WorkspaceSource || len(v.Options) != 0 {
		return errors.New("the Docker target volume custody differs")
	}
	return nil
}

func validateBridgeVolume(t Target, v volume) error {
	if v.Name != t.BridgeVolume || v.Driver != "local" || v.Scope != "local" ||
		v.Mountpoint != t.BridgeSource || len(v.Options) != 0 {
		return errors.New("the Docker target bridge volume custody differs")
	}
	return nil
}

func readBridgeSnapshot(t Target) error {
	fd, err := unix.Open(filepath.Join(t.BridgeSource, "task.json"), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "measured taskboard snapshot")
	defer file.Close()
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&0777 != 0644 || st.Size < 1 || st.Size > 4096 {
		return errors.New("the taskboard bridge snapshot custody differs")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(raw) > 4096 {
		return errors.New("the taskboard bridge snapshot is oversized")
	}
	var snapshot struct {
		Protocol string `json:"protocol"`
		Task     struct {
			ID int `json:"id"`
		} `json:"task"`
		ValidUntil string `json:"valid_until"`
	}
	if err = json.Unmarshal(raw, &snapshot); err != nil || snapshot.Protocol != "agentgate.taskboard-read.v1" || snapshot.Task.ID != t.BridgeTaskID {
		return errors.New("the taskboard bridge snapshot scope differs")
	}
	until, err := time.Parse(time.RFC3339Nano, snapshot.ValidUntil)
	if err != nil || time.Until(until) <= 0 || time.Until(until) > 15*time.Second {
		return errors.New("the taskboard bridge snapshot is stale")
	}
	return nil
}

func startTime(pid int) (string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 {
		return "", errors.New("the target process stat is malformed")
	}
	fields := strings.Fields(string(raw[end+1:]))
	if len(fields) < 20 {
		return "", errors.New("the target process stat is incomplete")
	}
	return fields[19], nil
}

// Measure retains no Docker socket or namespace descriptor in the workload.
// The caller must remeasure before placement and verify the held process after it.
func Measure(ctx context.Context, t Target) (Measurement, error) {
	var out Measurement
	if err := t.Validate(); err != nil {
		return out, err
	}
	socket, err := os.Lstat(t.SocketPath)
	if err != nil {
		return out, err
	}
	socketStat, ok := socket.Sys().(*syscall.Stat_t)
	if !ok || socket.Mode()&os.ModeSocket == 0 || socketStat.Uid != 0 || socket.Mode().Perm()&0002 != 0 {
		return out, errors.New("the trusted Docker API socket custody differs")
	}
	selfPIDNS, selfErr := os.Readlink("/proc/self/ns/pid")
	initPIDNS, initErr := os.Readlink("/proc/1/ns/pid")
	if selfErr != nil || initErr != nil || selfPIDNS != initPIDNS {
		return out, errors.New("the Docker target reader lacks host PID namespace custody")
	}
	d, err := readInspect(ctx, t)
	if err != nil {
		return out, err
	}
	if err = validateInspect(t, d); err != nil {
		return out, err
	}
	i, err := readImage(ctx, t, d.Image)
	if err != nil {
		return out, err
	}
	if err = validateImage(t, d, i); err != nil {
		return out, err
	}
	n, err := readNetwork(ctx, t)
	if err != nil {
		return out, err
	}
	if err = validateNetwork(t, d, n); err != nil {
		return out, err
	}
	v, err := readVolume(ctx, t)
	if err != nil {
		return out, err
	}
	if err = validateVolume(t, v); err != nil {
		return out, err
	}
	bridgeImageSource := ""
	if t.BridgePath != "" {
		bridge, bridgeErr := readBridgeVolume(ctx, t)
		if bridgeErr != nil {
			return out, bridgeErr
		}
		if bridgeErr = validateBridgeVolume(t, bridge); bridgeErr != nil {
			return out, bridgeErr
		}
		bridgeImage, bridgeErr := measureBridge(ctx, t)
		if bridgeErr != nil {
			return out, bridgeErr
		}
		if bridgeImage != i.Config.Labels["org.opencontainers.image.revision"] {
			return out, errors.New("the trusted bridge image source differs from the target")
		}
		bridgeImageSource = bridgeImage
	}
	start, err := startTime(d.State.PID)
	if err != nil {
		return out, err
	}
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", d.State.PID))
	if err != nil || !strings.Contains(string(status), "\nNoNewPrivs:\t1\n") ||
		!strings.Contains(string(status), "\nCapEff:\t0000000000000000\n") {
		return out, errors.New("the Docker target process privilege readback differs")
	}
	namespaces := map[string]string{}
	for _, kind := range []string{"mnt", "net", "pid", "ipc", "uts"} {
		target, targetErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/%s", d.State.PID, kind))
		host, hostErr := os.Readlink("/proc/1/ns/" + kind)
		if targetErr != nil || hostErr != nil || target == host || !strings.HasPrefix(target, kind+":[") {
			return out, errors.New("the Docker target namespace differs from the host")
		}
		namespaces[kind] = target
	}
	userNamespace, userErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/user", d.State.PID))
	hostUserNamespace, hostUserErr := os.Readlink("/proc/1/ns/user")
	if userErr != nil || hostUserErr != nil || userNamespace != hostUserNamespace {
		return out, errors.New("the Docker target has an unsupported user namespace")
	}
	inside, err := os.Stat(fmt.Sprintf("/proc/%d/root%s", d.State.PID, t.Workspace))
	if err != nil {
		return out, err
	}
	source, err := os.Lstat(t.WorkspaceSource)
	if err != nil {
		return out, err
	}
	a, aok := inside.Sys().(*syscall.Stat_t)
	b, bok := source.Sys().(*syscall.Stat_t)
	if !aok || !bok || !inside.IsDir() || a.Dev != b.Dev || a.Ino != b.Ino ||
		a.Uid != 65534 || a.Gid != 65534 || inside.Mode().Perm()&0002 != 0 {
		return out, errors.New("the Docker target workspace custody differs")
	}
	again, err := startTime(d.State.PID)
	if err != nil || again != start {
		return out, errors.New("the Docker target process changed during measurement")
	}
	out = Measurement{ContainerID: t.ContainerID, ImageDigest: t.ImageDigest, HostPID: d.State.PID,
		ImageSourceRevision: i.Config.Labels["org.opencontainers.image.revision"],
		StartTimeTicks:      start, Namespaces: namespaces, WorkspaceDevice: uint64(a.Dev), WorkspaceInode: a.Ino}
	if bridgeImageSource != "" {
		out.BridgeContainerID = t.BridgeContainerID
		out.BridgeImageDigest = t.BridgeImageDigest
		out.BridgeImageSourceRevision = bridgeImageSource
		out.BridgeTokenIsolated = true
	}
	if t.ArtifactPath != "" {
		insideArtifact, artifactErr := os.Stat(fmt.Sprintf("/proc/%d/root%s", d.State.PID, t.ArtifactPath))
		if artifactErr != nil {
			return Measurement{}, artifactErr
		}
		sourceArtifact, artifactErr := os.Lstat(t.ArtifactSource)
		if artifactErr != nil {
			return Measurement{}, artifactErr
		}
		x, xok := insideArtifact.Sys().(*syscall.Stat_t)
		y, yok := sourceArtifact.Sys().(*syscall.Stat_t)
		if !xok || !yok || !insideArtifact.IsDir() || x.Dev != y.Dev || x.Ino != y.Ino ||
			x.Uid != 0 || insideArtifact.Mode().Perm()&0022 != 0 {
			return Measurement{}, errors.New("the Docker target stream mount custody differs")
		}
		out.ArtifactDevice, out.ArtifactInode = uint64(x.Dev), x.Ino
	}
	if t.BridgePath != "" {
		insideBridge, bridgeErr := os.Stat(fmt.Sprintf("/proc/%d/root%s", d.State.PID, t.BridgePath))
		if bridgeErr != nil {
			return Measurement{}, bridgeErr
		}
		sourceBridge, bridgeErr := os.Lstat(t.BridgeSource)
		if bridgeErr != nil {
			return Measurement{}, bridgeErr
		}
		x, xok := insideBridge.Sys().(*syscall.Stat_t)
		y, yok := sourceBridge.Sys().(*syscall.Stat_t)
		if !xok || !yok || !insideBridge.IsDir() || x.Dev != y.Dev || x.Ino != y.Ino ||
			x.Uid != 0 || x.Gid != 65534 || insideBridge.Mode().Perm() != 0750 {
			return Measurement{}, errors.New("the Docker target read-only bridge mount custody differs")
		}
		out.BridgeDevice, out.BridgeInode = uint64(x.Dev), x.Ino
		if bridgeErr = readBridgeSnapshot(t); bridgeErr != nil {
			return Measurement{}, bridgeErr
		}
		out.BridgeTaskID = t.BridgeTaskID
	}
	if out.HostMounts, err = measureHostMounts(t, d.State.PID); err != nil {
		return Measurement{}, err
	}
	again, err = startTime(d.State.PID)
	if err != nil || again != start {
		return Measurement{}, errors.New("the Docker target changed during mount measurement")
	}
	return out, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package dockerplacement

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

func validBridgeUpstream(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.String() != raw {
		return false
	}
	host, port, err := net.SplitHostPort(u.Host)
	address, addressErr := netip.ParseAddr(host)
	number, portErr := strconv.Atoi(port)
	return err == nil && addressErr == nil && portErr == nil && address.String() == host && address.IsPrivate() &&
		!address.Is4In6() && address.Zone() == "" && number > 0 && number <= 65535 && strconv.Itoa(number) == port
}

// MatchesPilot binds the bridge's configured upstream to the signed, exact
// taskboard service exception rather than to an arbitrary LAN endpoint.
func (t Target) MatchesPilot(taskID int, address string, port int) bool {
	return t.BridgeTaskID == taskID && t.BridgeUpstreamURL == "http://"+net.JoinHostPort(address, strconv.Itoa(port))+"/"
}

func bridgeEnvironment(t Target, values []string) bool {
	required := map[string]string{
		"AGENTGATE_TASKBOARD_SOCKET":     t.BridgePath + "/taskboard.sock",
		"AGENTGATE_TASKBOARD_SOCKET_GID": "65534",
		"AGENTGATE_TASKBOARD_URL":        t.BridgeUpstreamURL,
		"AGENTGATE_TASKBOARD_TASK_ID":    strconv.Itoa(t.BridgeTaskID),
		"AGENTGATE_TASKBOARD_TOKEN_FILE": "/run/secrets/taskboard-token",
		"AGENTGATE_TASKBOARD_SNAPSHOT":   t.BridgePath + "/task.json",
	}
	seen := make(map[string]bool, len(required))
	for _, value := range values {
		key, actual, found := strings.Cut(value, "=")
		if !found {
			return false
		}
		if want, ok := required[key]; ok {
			if seen[key] || actual != want {
				return false
			}
			seen[key] = true
		}
	}
	return len(seen) == len(required)
}

func outsideTargetMounts(source string, t Target) bool {
	if !absolute(source) {
		return false
	}
	for _, root := range []string{t.WorkspaceSource, t.ArtifactSource, t.BridgeSource} {
		if root != "" && (source == root || strings.HasPrefix(source, root+"/")) {
			return false
		}
	}
	return true
}

// Docker reports added capabilities with a CAP_ prefix on some API versions.
// Accept only the single capability requested for the trusted bridge.
func bridgeChownOnly(caps []string) bool {
	return len(caps) == 1 && (caps[0] == "CHOWN" || caps[0] == "CAP_CHOWN")
}

func validateBridgeInspect(t Target, d inspect) error {
	if d.ID != t.BridgeContainerID || !d.State.Running || d.State.PID <= 1 || d.Config.User != "root" ||
		!reflect.DeepEqual(d.Config.Entrypoint, []string{"/usr/local/bin/bun", "/opt/agentgate/taskboard_bridge.mts"}) ||
		len(d.Config.Cmd) != 0 || !bridgeEnvironment(t, d.Config.Env) {
		return errors.New("the trusted taskboard bridge process differs")
	}
	h := d.HostConfig
	if h.Privileged || !h.ReadonlyRoot || h.PIDMode != "" || (h.IPCMode != "" && h.IPCMode != "private") ||
		h.UTSMode != "" || h.UsernsMode != "" || (h.CgroupnsMode != "" && h.CgroupnsMode != "private") ||
		h.NetworkMode != t.BridgeNetworkName || len(h.Devices) != 0 || len(h.DeviceRequests) != 0 ||
		!bridgeChownOnly(h.CapAdd) || !contains(h.CapDrop, "ALL") ||
		(!contains(h.SecurityOpt, "no-new-privileges:true") && !contains(h.SecurityOpt, "no-new-privileges")) ||
		h.PidsLimit < 2 || h.PidsLimit > 64 || h.Memory < 64<<20 || h.Memory > 512<<20 || len(h.Tmpfs) != 0 {
		return errors.New("the trusted taskboard bridge isolation differs")
	}
	if len(d.NetworkSettings.Networks) != 1 || !identifier.MatchString(d.NetworkSettings.Networks[t.BridgeNetworkName].NetworkID) || len(d.Mounts) != 2 {
		return errors.New("the trusted taskboard bridge network or mounts differ")
	}
	volume, token := false, false
	for _, mounted := range d.Mounts {
		switch {
		case mounted.Type == "volume" && mounted.Name == t.BridgeVolume && mounted.Source == t.BridgeSource &&
			mounted.Destination == t.BridgePath && mounted.RW:
			volume = true
		case mounted.Type == "bind" && mounted.Destination == "/run/secrets/taskboard-token" && !mounted.RW &&
			outsideTargetMounts(mounted.Source, t):
			token = true
		default:
			return errors.New("the trusted taskboard bridge has an unapproved mount")
		}
	}
	if !volume || !token {
		return errors.New("the trusted taskboard bridge token or socket volume is absent")
	}
	return nil
}

// measureBridge binds the trusted one-task bridge image, token mount and
// separate network to the same Docker engine that measured the untrusted target.
func measureBridge(ctx context.Context, t Target) (string, error) {
	bridge := t
	bridge.ContainerID, bridge.ImageDigest, bridge.ImageReference, bridge.NetworkName = t.BridgeContainerID, t.BridgeImageDigest, t.BridgeImageReference, t.BridgeNetworkName
	d, err := readInspect(ctx, bridge)
	if err != nil {
		return "", err
	}
	if err = validateBridgeInspect(t, d); err != nil {
		return "", err
	}
	i, err := readImage(ctx, bridge, d.Image)
	if err != nil {
		return "", err
	}
	if err = validateImage(bridge, d, i); err != nil {
		return "", err
	}
	n, err := readNetwork(ctx, bridge)
	if err != nil {
		return "", err
	}
	if err = validateNetwork(bridge, d, n); err != nil {
		return "", err
	}
	return i.Config.Labels["org.opencontainers.image.revision"], nil
}

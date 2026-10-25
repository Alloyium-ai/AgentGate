// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import "encoding/json"

// LaunchSpecVersion is the only accepted LaunchSpec.Version.
const LaunchSpecVersion = "agentgate.launch.v1"

// LaunchSpec is the wire form of an agentgate.launch.v1 document. The service
// validates it (see docs/PROVISIONING.md); a host receives the canonical bytes
// inside LaunchPayload.Spec and may decode them with this type.
type LaunchSpec struct {
	Version         string       `json:"version"`
	Name            string       `json:"name"`
	Target          string       `json:"target"`
	Mode            string       `json:"mode"`
	LifetimeSeconds int          `json:"lifetime_seconds"`
	Agent           LaunchAgent  `json:"agent"`
	Access          LaunchAccess `json:"access"`
	Mounts          []SpecMount  `json:"mounts"`
	Secrets         []SpecSecret `json:"secrets"`
	Approval        string       `json:"approval"`
}

// LaunchAgent is what runs.
type LaunchAgent struct {
	Image   string            `json:"image"`
	Command []string          `json:"command"`
	Env     map[string]string `json:"env"`
	Workdir string            `json:"workdir"`
}

// LaunchAccess names a stored profile version, or carries one inline policy.
type LaunchAccess struct {
	Profile string          `json:"profile,omitempty"`
	Version int             `json:"version,omitempty"`
	Inline  json.RawMessage `json:"inline,omitempty"`
}

// SpecMount is one requested host folder.
type SpecMount struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Mode   string `json:"mode"`
}

// SpecSecret names a secret by reference only.
type SpecSecret struct {
	Ref    string       `json:"ref"`
	Expose SecretExpose `json:"expose"`
}

// SecretExpose says where the agent finds the broker address.
type SecretExpose struct {
	Env string `json:"env"`
}

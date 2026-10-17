// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package policy

import "encoding/json"

const Version = "agentgate.policy.v2"
const SelectedProfile = "selected-inspection.v2"
const KernelProfile = "kernel-policy.v2"

// Document is the typed representation shared by JSON, YAML, and the compiler.
// Its presence in the schema does not qualify an enforcement capability.
type Document struct {
	Defaults             *Defaults                   `json:"defaults,omitempty"`
	SchemaVersion        string                      `json:"schema_version"`
	Profile              string                      `json:"profile"`
	RequiredCapabilities []string                    `json:"required_capabilities"`
	Selected             *Selected                   `json:"selected,omitempty"`
	Files                *Files                      `json:"files,omitempty"`
	Programs             *Programs                   `json:"programs,omitempty"`
	Network              *Network                    `json:"network,omitempty"`
	Sockets              *SocketPolicy               `json:"sockets,omitempty"`
	Identity             *Identity                   `json:"identity,omitempty"`
	Runtime              *Runtime                    `json:"runtime,omitempty"`
	Lifecycle            *Lifecycle                  `json:"lifecycle,omitempty"`
	Evidence             *Evidence                   `json:"evidence,omitempty"`
	Extensions           *map[string]json.RawMessage `json:"extensions,omitempty"`
	RuntimeTemplates     *[]string                   `json:"runtime_templates,omitempty"`
}
type Defaults struct {
	RegisteredOperations string `json:"registered_operations"`
	UnmatchedResources   string `json:"unmatched_resources"`
	MissingManagedPolicy string `json:"missing_managed_policy"`
}
type Selected struct {
	WorkspaceWrite bool   `json:"workspace_write"`
	TCPAddress     string `json:"tcp_address"`
	TCPPort        int    `json:"tcp_port"`
}
type Selector struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}
type FileDefaults struct {
	Read  string `json:"read"`
	Write string `json:"write"`
}
type FileRule struct {
	ID         string   `json:"id"`
	Selector   Selector `json:"selector"`
	Operations []string `json:"operations"`
	Effect     string   `json:"effect"`
}
type Files struct {
	Defaults    FileDefaults `json:"defaults"`
	Rules       []FileRule   `json:"rules"`
	ResourceUse string       `json:"resource_use"`
}
type Approval struct {
	Argv1             []string `json:"argv1"`
	TimeoutSeconds    int      `json:"timeout_seconds"`
	Scope             string   `json:"scope"`
	ArgumentAssurance string   `json:"argument_assurance"`
}
type ProgramRule struct {
	ID       string    `json:"id"`
	Selector Selector  `json:"selector"`
	Effect   string    `json:"effect"`
	Approval *Approval `json:"approval,omitempty"`
}
type Programs struct {
	Default string        `json:"default"`
	Rules   []ProgramRule `json:"rules"`
}
type Destination struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}
type NetworkRule struct {
	ID          string      `json:"id"`
	Family      string      `json:"family"`
	Protocol    string      `json:"protocol"`
	Destination Destination `json:"destination"`
	PortFrom    int         `json:"port_from"`
	PortTo      int         `json:"port_to"`
	Effect      string      `json:"effect"`
}
type DNS struct {
	ResolverProfile string `json:"resolver_profile"`
	CNAME           string `json:"cname"`
	Expiry          string `json:"expiry"`
}
type Network struct {
	Default string        `json:"default"`
	Rules   []NetworkRule `json:"rules"`
	DNS     DNS           `json:"dns"`
}
type Identity struct {
	TrustSource       string `json:"trust_source"`
	ProofOfPossession bool   `json:"proof_of_possession"`
	JobBinding        bool   `json:"job_binding"`
	NodeBinding       bool   `json:"node_binding"`
	BootBinding       bool   `json:"boot_binding"`
	ProcessDomain     string `json:"process_domain"`
	Descendants       string `json:"descendants"`
}
type Seccomp struct {
	Profile       string   `json:"profile"`
	Architecture  string   `json:"architecture"`
	Default       string   `json:"default"`
	AllowSyscalls []string `json:"allow_syscalls"`
}
type MemoryPolicy struct {
	Default   string   `json:"default"`
	Anonymous []string `json:"anonymous"`
	Heap      string   `json:"heap"`
}
type IPCPolicy struct {
	Default  string    `json:"default"`
	Pipes    []string  `json:"pipes"`
	EventFDs *[]string `json:"eventfds,omitempty"`
}
type BootstrapPolicy struct {
	Profile        string   `json:"profile"`
	HelperDigest   string   `json:"helper_digest"`
	Operations     []string `json:"operations"`
	MaxHoldSeconds int      `json:"max_hold_seconds"`
}
type Runtime struct {
	Bootstrap           *BootstrapPolicy `json:"bootstrap,omitempty"`
	Signals             *[]int           `json:"signals,omitempty"`
	IPC                 *IPCPolicy       `json:"ipc,omitempty"`
	Memory              *MemoryPolicy    `json:"memory,omitempty"`
	Profile             string           `json:"profile"`
	UID                 int              `json:"uid"`
	GID                 int              `json:"gid"`
	SupplementaryGroups []int            `json:"supplementary_groups"`
	Capabilities        []string         `json:"capabilities"`
	NoNewPrivileges     bool             `json:"no_new_privileges"`
	Seccomp             Seccomp          `json:"seccomp"`
}
type Lifecycle struct {
	BaselineVersion string `json:"baseline_version"`
	DurationSeconds int    `json:"duration_seconds"`
	Release         string `json:"release"`
	Revoke          string `json:"revoke"`
	Recovery        string `json:"recovery"`
}
type Evidence struct {
	Profile         string `json:"profile"`
	MaxReportedLoss int    `json:"max_reported_loss"`
	BatchEvents     int    `json:"batch_events"`
	BatchSeconds    int    `json:"batch_seconds"`
}

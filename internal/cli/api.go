// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"encoding/json"
	"regexp"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// The API's response shapes, with the API's field names. TestAPITypesCover
// decodes the service's own types into these with unknown fields disallowed,
// so a field the service adds fails the CLI's tests until it is handled.

var apiTokenFormat = regexp.MustCompile(`^agt_[A-Za-z0-9_-]{43}$`)

// Target is a host that runs agentgate-hostd.
type Target struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	State        string   `json:"state"`
	Capabilities []string `json:"capabilities"`
	Hostname     string   `json:"hostname"`
	AgentVersion string   `json:"agent_version"`
	HostKeyID    string   `json:"host_key_id"`
	// HostPublicKey and the seal key fields appear once the service relays
	// the host-signed seal key (secretseal.SignedKeyRecord).
	HostPublicKey    string          `json:"host_public_key,omitempty"`
	EncryptionKey    string          `json:"encryption_key"`
	SealKey          json.RawMessage `json:"seal_key,omitempty"`
	SealKeyID        string          `json:"seal_key_id,omitempty"`
	SealKeyNotAfter  string          `json:"seal_key_not_after,omitempty"`
	JobKeyID         string          `json:"job_key_id"`
	LastSeen         string          `json:"last_seen_at,omitempty"`
	Online           bool            `json:"online"`
	HeartbeatSeconds int             `json:"heartbeat_seconds"`
	Created          string          `json:"created_at"`
	CreatedBy        string          `json:"created_by"`
	Updated          string          `json:"updated_at"`
	Revision         int             `json:"revision"`
	KernelVerified   bool            `json:"kernel_verified"`
	RetiringSince    string          `json:"retiring_since,omitempty"`
	// MountRoots are the host folders launches on the target may mount;
	// none refuses every mount.
	MountRoots []string `json:"mount_roots"`
}

// Enrollment is a one-time host enrollment token.
type Enrollment struct {
	Token      string `json:"token"`
	ExpiresAt  string `json:"expires_at"`
	SingleUse  bool   `json:"single_use"`
	EnrollPath string `json:"enroll_path"`
}

// TargetEnrollment is the answer to target creation and re-enrollment.
type TargetEnrollment struct {
	Target     Target     `json:"target"`
	Enrollment Enrollment `json:"enrollment"`
}

// Profile is a named, versioned access policy. With RequireApproval false,
// only ApprovedVersion (digest ApprovedDigest) launches without a second human.
type Profile struct {
	ID              string `json:"id"`
	Name            string `json:"name"`
	Description     string `json:"description"`
	RequireApproval bool   `json:"require_approval"`
	ApprovedVersion int    `json:"approved_version,omitempty"`
	ApprovedDigest  string `json:"approved_digest,omitempty"`
	ApprovedBy      string `json:"approved_by,omitempty"`
	ApprovedAt      string `json:"approved_at,omitempty"`
	Created         string `json:"created_at"`
	CreatedBy       string `json:"created_by"`
	Revision        int    `json:"revision"`
	LatestVersion   int    `json:"latest_version"`
}

// ProfileVersion is one immutable policy document.
type ProfileVersion struct {
	ID        string          `json:"id"`
	ProfileID string          `json:"profile_id"`
	Number    int             `json:"number"`
	ParentID  string          `json:"parent_id"`
	Document  json.RawMessage `json:"document"`
	Digest    string          `json:"digest"`
	Edits     json.RawMessage `json:"edits"`
	Actor     string          `json:"actor"`
	Reason    string          `json:"reason"`
	Created   string          `json:"created_at"`
}

// GrantEdit is one typed access edit, as the grants endpoint takes it. The
// CLI only builds it from the command line; the service applies it.
type GrantEdit struct {
	Action      string   `json:"action"`
	Kind        string   `json:"kind,omitempty"`
	Values      []string `json:"values,omitempty"`
	Mode        string   `json:"mode,omitempty"`
	UpgradeToV2 bool     `json:"upgrade_to_v2,omitempty"`
}

// grantRevokeKinds and maxGrantValues repeat the service's bounds for usage
// messages before anything is sent (a test compares them with internal/access).
var grantRevokeKinds = []string{"web", "dns", "read", "write", "exec", "deny", "signal", "anon-exec", "mount", "device"}

const maxGrantValues = 16

// PolicyChange is one row of the service's structured change list.
type PolicyChange struct {
	Area   string `json:"area"`
	Field  string `json:"field"`
	Change string `json:"change"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// GrantResult is the answer to a grants request or its dry run.
type GrantResult struct {
	DryRun      bool            `json:"dry_run,omitempty"`
	Changed     bool            `json:"changed"`
	Version     ProfileVersion  `json:"version"`
	Document    json.RawMessage `json:"document,omitempty"`
	FromVersion int             `json:"from_version"`
	FromDigest  string          `json:"from_digest"`
	Digest      string          `json:"digest"`
	Changes     []PolicyChange  `json:"changes"`
	Messages    []string        `json:"messages"`
	Notices     []string        `json:"notices"`
}

// Permissions summarizes what an effective policy allows.
type Permissions struct {
	Network          string   `json:"network_default"`
	IPv6             string   `json:"ipv6"`
	Web              []string `json:"web"`
	DNS              []string `json:"dns_resolvers"`
	Taskboard        string   `json:"taskboard"`
	Broker           string   `json:"broker,omitempty"`
	ReadOnly         []string `json:"read_only"`
	Writable         []string `json:"writable"`
	Execute          []string `json:"execute"`
	Deny             []string `json:"deny"`
	Devices          []string `json:"devices"`
	Signals          []string `json:"signals"`
	AnonymousExecute bool     `json:"anonymous_execute"`
}

// BrokerRule allows methods on one path of a secret's upstreams.
type BrokerRule struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
	Match   string   `json:"match,omitempty"`
}

// PlanSecret names one brokered secret and how the broker uses it; never a
// value. The injection fields appear once the service carries them.
type PlanSecret struct {
	Ref              string            `json:"ref"`
	SecretID         string            `json:"secret_id"`
	Env              string            `json:"env"`
	Upstreams        []string          `json:"upstreams"`
	Header           string            `json:"header"`
	Scheme           string            `json:"scheme,omitempty"`
	Username         string            `json:"username,omitempty"`
	Rules            []BrokerRule      `json:"rules,omitempty"`
	Wildcard         bool              `json:"wildcard_rules,omitempty"`
	ExtraHeaders     map[string]string `json:"extra_headers,omitempty"`
	ForwardHeaders   []string          `json:"forward_headers,omitempty"`
	PolicyDigest     string            `json:"policy_digest,omitempty"`
	BaseURL          string            `json:"base_url,omitempty"`
	ValueFingerprint string            `json:"value_fingerprint,omitempty"`
}

// PlanBroker is a launch's broker endpoint and network.
type PlanBroker struct {
	Address       string `json:"address"`
	Port          int    `json:"port"`
	Subnet        string `json:"subnet"`
	TargetAddress string `json:"target_address"`
}

// LaunchPlan is the resolved, immutable plan of a launch.
type LaunchPlan struct {
	SpecDigest      string                  `json:"spec_digest"`
	PolicyDigest    string                  `json:"policy_digest"`
	Target          map[string]string       `json:"target"`
	Profile         map[string]any          `json:"profile"`
	Mode            string                  `json:"mode"`
	LifetimeSeconds int                     `json:"lifetime_seconds"`
	ExpiresAt       string                  `json:"expires_at,omitempty"`
	ExpiryRule      string                  `json:"expiry_rule"`
	Image           string                  `json:"image"`
	Command         []string                `json:"command"`
	Workdir         string                  `json:"workdir"`
	Approval        string                  `json:"approval"`
	ApprovalReasons []string                `json:"approval_reasons"`
	Permissions     Permissions             `json:"permissions"`
	Mounts          []hostproto.LaunchMount `json:"mounts"`
	Secrets         []PlanSecret            `json:"secrets"`
	Broker          *PlanBroker             `json:"broker,omitempty"`
	KernelVerified  bool                    `json:"kernel_verified"`
	Notices         []string                `json:"notices"`
}

// PlanResult is the answer to POST /launch-plans.
type PlanResult struct {
	DryRun bool            `json:"dry_run"`
	Plan   LaunchPlan      `json:"plan"`
	Spec   json.RawMessage `json:"spec"`
	Policy json.RawMessage `json:"policy"`
}

// Launch is one execution of a launch spec.
type Launch struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	SpecDigest       string          `json:"spec_digest"`
	TargetID         string          `json:"target_id"`
	ProfileVersionID string          `json:"profile_version_id,omitempty"`
	PolicyDigest     string          `json:"policy_digest"`
	Mode             string          `json:"mode"`
	LifetimeSeconds  int             `json:"lifetime_seconds"`
	ApprovalRequired bool            `json:"approval_required"`
	State            string          `json:"state"`
	RequestedBy      string          `json:"requested_by"`
	DecidedBy        string          `json:"decided_by,omitempty"`
	DecisionReason   string          `json:"decision_reason,omitempty"`
	StopReason       string          `json:"stop_reason,omitempty"`
	TerminalReason   string          `json:"terminal_reason,omitempty"`
	EvidenceMissing  string          `json:"evidence_missing,omitempty"`
	KernelVerified   bool            `json:"kernel_verified"`
	Created          string          `json:"created_at"`
	Updated          string          `json:"updated_at"`
	QueuedAt         string          `json:"queued_at,omitempty"`
	ExpiresAt        string          `json:"expires_at,omitempty"`
	StartedAt        string          `json:"started_at,omitempty"`
	EndedAt          string          `json:"ended_at,omitempty"`
	Revision         int             `json:"revision"`
	Plan             json.RawMessage `json:"plan,omitempty"`
	Receipt          json.RawMessage `json:"receipt,omitempty"`
	Spec             json.RawMessage `json:"spec,omitempty"`
	Policy           json.RawMessage `json:"policy,omitempty"`
}

// LaunchCreated is the answer to POST /launches.
type LaunchCreated struct {
	Launch Launch     `json:"launch"`
	Plan   LaunchPlan `json:"plan"`
}

// Job is a host job as the API shows it.
type Job struct {
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	TargetID     string          `json:"target_id"`
	LaunchID     string          `json:"launch_id,omitempty"`
	SecretID     string          `json:"secret_id,omitempty"`
	SpecDigest   string          `json:"spec_digest,omitempty"`
	PolicyDigest string          `json:"policy_digest,omitempty"`
	KeyID        string          `json:"key_id"`
	State        string          `json:"state"`
	Attempts     int             `json:"attempts"`
	Created      string          `json:"created_at"`
	Deadline     string          `json:"deadline"`
	Completed    string          `json:"completed_at,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	EventSeq     uint32          `json:"event_seq"`
}

// LaunchDetail is the answer to GET /launches/{id}.
type LaunchDetail struct {
	Launch Launch `json:"launch"`
	Jobs   []Job  `json:"jobs"`
}

// LaunchEvent is one ordered launch event.
type LaunchEvent struct {
	Seq    int             `json:"seq"`
	Time   string          `json:"time"`
	Kind   string          `json:"kind"`
	From   string          `json:"from_state,omitempty"`
	To     string          `json:"to_state,omitempty"`
	Actor  string          `json:"actor"`
	Reason string          `json:"reason"`
	Data   json.RawMessage `json:"data"`
}

// LogLine is one line of agent output.
type LogLine struct {
	Seq    int    `json:"seq"`
	Time   string `json:"time"`
	Stream string `json:"stream"`
	Text   string `json:"text"`
}

// LogPage is the answer to GET /launches/{id}/logs.
type LogPage struct {
	Items      []LogLine `json:"items"`
	Bytes      int       `json:"bytes"`
	LimitBytes int       `json:"limit_bytes"`
	Truncated  bool      `json:"truncated"`
}

// Secret is secret metadata; the service never holds a value.
type Secret struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	TargetID         string            `json:"target_id"`
	Upstreams        []string          `json:"upstreams"`
	Header           string            `json:"header"`
	Scheme           string            `json:"scheme,omitempty"`
	Username         string            `json:"username,omitempty"`
	Rules            []BrokerRule      `json:"rules,omitempty"`
	Wildcard         bool              `json:"wildcard_rules,omitempty"`
	ExtraHeaders     map[string]string `json:"extra_headers,omitempty"`
	ForwardHeaders   []string          `json:"forward_headers,omitempty"`
	PolicyDigest     string            `json:"policy_digest,omitempty"`
	Fingerprint      string            `json:"ciphertext_sha256"`
	Envelope         *SecretEnvelope   `json:"envelope,omitempty"`
	ValueFingerprint string            `json:"value_fingerprint,omitempty"`
	Receipt          json.RawMessage   `json:"receipt,omitempty"`
	AllowedProfiles  []string          `json:"allowed_profiles"`
	AllowedLaunchers []string          `json:"allowed_launchers"`
	State            string            `json:"state"`
	Removal          string            `json:"removal,omitempty"`
	Created          string            `json:"created_at"`
	CreatedBy        string            `json:"created_by"`
	Updated          string            `json:"updated_at"`
	Revision         int               `json:"revision"`
}

// LauncherSecret is what GET /targets/{id}/secrets shows a launcher.
type LauncherSecret struct {
	Name            string   `json:"name"`
	State           string   `json:"state"`
	Upstreams       []string `json:"upstreams"`
	RuleCount       int      `json:"rule_count"`
	WildcardRules   bool     `json:"wildcard_rules"`
	LauncherAllowed bool     `json:"launcher_allowed"`
	ProfileAllowed  *bool    `json:"profile_allowed,omitempty"`
	Usable          bool     `json:"usable"`
	Reason          string   `json:"reason,omitempty"`
}

// TargetSecrets is the answer to GET /targets/{id}/secrets.
type TargetSecrets struct {
	TargetID string           `json:"target_id"`
	Target   string           `json:"target"`
	Profile  string           `json:"profile,omitempty"`
	Items    []LauncherSecret `json:"items"`
}

// SecretEnvelope is the public context of a relayed sealed envelope.
type SecretEnvelope struct {
	Format       string `json:"format"`
	KeyID        string `json:"key_id"`
	Version      uint64 `json:"version"`
	Nonce        string `json:"nonce"`
	PolicyDigest string `json:"policy_digest"`
}

// SecretReceiptAnswer is GET /secrets/{id}/receipt.
type SecretReceiptAnswer struct {
	SecretID         string          `json:"secret_id"`
	TargetID         string          `json:"target_id"`
	Name             string          `json:"name"`
	State            string          `json:"state"`
	Fingerprint      string          `json:"ciphertext_sha256"`
	ValueFingerprint string          `json:"value_fingerprint"`
	Receipt          json.RawMessage `json:"receipt"`
}

// APIToken is token metadata.
type APIToken struct {
	ID       string   `json:"id"`
	Subject  string   `json:"subject"`
	Name     string   `json:"name"`
	Roles    []string `json:"roles"`
	Created  string   `json:"created_at"`
	Expires  string   `json:"expires_at"`
	Revoked  string   `json:"revoked_at,omitempty"`
	LastUsed string   `json:"last_used_at,omitempty"`
}

// CreatedToken is the only response that carries a token.
type CreatedToken struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Roles     []string `json:"roles"`
	ExpiresAt string   `json:"expires_at"`
	Token     string   `json:"token"`
}

// AuditEntry is one audit record.
type AuditEntry struct {
	ID            int64           `json:"id"`
	Time          string          `json:"time"`
	Actor         string          `json:"actor"`
	ActorKind     string          `json:"actor_kind"`
	Action        string          `json:"action"`
	Resource      string          `json:"resource"`
	Version       string          `json:"version"`
	Run           string          `json:"run"`
	Before        json.RawMessage `json:"before"`
	After         json.RawMessage `json:"after"`
	Reason        string          `json:"reason"`
	RequestID     string          `json:"request_id"`
	CorrelationID string          `json:"correlation_id"`
	Result        string          `json:"result"`
}

// AuditPage is one page of audit records.
type AuditPage struct {
	Items []AuditEntry `json:"items"`
	Next  string       `json:"next_cursor,omitempty"`
}

// Preset is a named set of access sections.
type Preset struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Web         []string        `json:"web"`
	Filesystem  json.RawMessage `json:"filesystem"`
	Process     json.RawMessage `json:"process"`
}

// PresetList is the answer to GET /access-presets.
type PresetList struct {
	Items       []Preset `json:"items"`
	Actions     []string `json:"actions"`
	RevokeKinds []string `json:"revoke_kinds"`
}

// SessionInfo is the answer to GET /api/v1/session.
type SessionInfo struct {
	Actor struct {
		Subject string   `json:"subject"`
		Kind    string   `json:"kind"`
		Name    string   `json:"name"`
		Roles   []string `json:"roles"`
	} `json:"actor"`
	CSRF    string `json:"csrf_token"`
	Expires int64  `json:"expires"`
}

type items[T any] struct {
	Items []T `json:"items"`
}

// terminalState reports whether a launch state is final.
func terminalState(s string) bool {
	switch s {
	case "stopped", "expired", "failed", "rejected", "cancelled":
		return true
	}
	return false
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

// JobVersion is the only accepted Job.Version.
const JobVersion = "agentgate.hostd.job.v1"

// Job types.
const (
	JobProvision     = "provision"
	JobApplyProfile  = "apply-profile"
	JobLaunch        = "launch"
	JobStop          = "stop"
	JobCollect       = "collect"
	JobSecretPut     = "secret-put"
	JobSecretDelete  = "secret-delete"
	JobSnapshotMount = "snapshot-mount"
)

// JobTypes lists every job type in a fixed order.
var JobTypes = []string{JobProvision, JobApplyProfile, JobLaunch, JobStop, JobCollect, JobSecretPut, JobSecretDelete, JobSnapshotMount}

// Job is one unit of host work, sealed under DomainJob with the service job
// key. A host acts on a job only after Check succeeds; otherwise it drops the
// job and reports a "rejected" result.
type Job struct {
	Version      string          `json:"version"`
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	TargetID     string          `json:"target_id"`
	LaunchID     string          `json:"launch_id"`
	SpecDigest   string          `json:"spec_digest"`
	PolicyDigest string          `json:"policy_digest"`
	IssuedAtMS   int64           `json:"issued_at_ms"`
	DeadlineMS   int64           `json:"deadline_ms"`
	Payload      json.RawMessage `json:"payload"`
}

// ProvisionPayload prepares a target: pull the pinned images and confirm the
// guard and enforcement components are installed. It never starts an agent.
type ProvisionPayload struct {
	Images []string `json:"images"`
	Reason string   `json:"reason"`
}

// ApplyProfilePayload stages one validated policy document on the host, for
// example to pre-check it with the native validator. It does not change any
// running launch.
type ApplyProfilePayload struct {
	ProfileID      string          `json:"profile_id"`
	ProfileVersion int             `json:"profile_version"`
	Policy         json.RawMessage `json:"policy"`
}

// LaunchMount is one resolved mount. Path is where the agent sees it.
type LaunchMount struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	Mode   string `json:"mode"`
	Path   string `json:"path"`
}

// LaunchSecret is one brokered secret. The value never appears here: the host
// already holds it from a secret-put job and exposes only the broker address.
// Scheme, Username, Rules and ExtraHeaders say how the broker injects it and
// which requests it forwards: every route needs explicit rules (deny by
// default); the service expands an operator's wildcard into the full rule.
//
// The settings are the secret's sealed injection policy (see SecretPolicy):
// PolicyDigest must equal their digest, and the host refuses the launch
// unless it also equals the digest it stored with the value, then builds the
// broker from its own stored policy, never from this copy.
type LaunchSecret struct {
	Ref            string            `json:"ref"`
	SecretID       string            `json:"secret_id"`
	Env            string            `json:"env"`
	Upstreams      []string          `json:"upstreams"`
	Header         string            `json:"header"`
	Scheme         string            `json:"scheme,omitempty"`
	Username       string            `json:"username,omitempty"`
	Rules          []BrokerRule      `json:"rules"`
	ExtraHeaders   map[string]string `json:"extra_headers,omitempty"`
	ForwardHeaders []string          `json:"forward_headers,omitempty"`
	Wildcard       bool              `json:"wildcard,omitempty"`
	PolicyDigest   string            `json:"policy_digest"`
}

// BrokerRule allows a set of methods on one route-relative path
// (agentgate.broker.v2 rules). Match is "exact" or "prefix" (on a segment
// boundary).
type BrokerRule struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
	Match   string   `json:"match"`
}

// BrokerMethods are the methods a rule may name; CONNECT and TRACE never.
var BrokerMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

// Bounds of the injection metadata.
const (
	MaxBrokerRules        = 64
	MaxBrokerExtraHeaders = 8
	maxRulePathBytes      = 512
)

// LaunchPayload starts one agent. Spec is the exact canonical spec bytes whose
// SHA-256 is Job.SpecDigest; Policy is the exact policy bytes whose SHA-256 is
// Job.PolicyDigest. The host enforces ExpiresAtMS in the kernel policy and
// itself, and reports a heartbeat at least every HeartbeatSeconds.
type LaunchPayload struct {
	Spec             json.RawMessage `json:"spec"`
	Policy           json.RawMessage `json:"policy"`
	ExpiresAtMS      int64           `json:"expires_at_ms"`
	HeartbeatSeconds int             `json:"heartbeat_seconds"`
	Mounts           []LaunchMount   `json:"mounts"`
	Secrets          []LaunchSecret  `json:"secrets"`
}

// StopPayload stops one launch. The host stops the agent, waits up to
// GraceSeconds, kills what remains, empties the domain, releases enforcement,
// and returns the receipt. A stop for a launch that already ended returns the
// recorded receipt.
type StopPayload struct {
	Reason       string `json:"reason"`
	GraceSeconds int    `json:"grace_seconds"`
}

// CollectPayload asks for the receipt of a launch without changing it.
type CollectPayload struct {
	Reason string `json:"reason"`
}

// SecretPutPayload stores one sealed secret on the host. Ciphertext is
// secretseal.Envelope.Encode() of an envelope sealed to this host's published,
// host-signed seal key for this target and name; CiphertextSHA256 is the
// SHA-256 of the decoded envelope bytes. The service cannot decrypt it. The
// settings are the secret's injection policy: their digest must equal
// PolicyDigest and the envelope's policy_digest, which the HPKE associated
// data binds, so the host stores exactly the policy the client sealed (and
// refuses anything else). The host answers with a SecretReceipt in the job
// result.
type SecretPutPayload struct {
	SecretID         string            `json:"secret_id"`
	Name             string            `json:"name"`
	Upstreams        []string          `json:"upstreams"`
	Header           string            `json:"header"`
	Scheme           string            `json:"scheme,omitempty"`
	Username         string            `json:"username,omitempty"`
	Rules            []BrokerRule      `json:"rules"`
	ExtraHeaders     map[string]string `json:"extra_headers,omitempty"`
	ForwardHeaders   []string          `json:"forward_headers,omitempty"`
	Wildcard         bool              `json:"wildcard,omitempty"`
	PolicyDigest     string            `json:"policy_digest"`
	Ciphertext       string            `json:"ciphertext"`
	CiphertextSHA256 string            `json:"ciphertext_sha256"`
}

// SecretDeletePayload removes a stored secret value from the host.
type SecretDeletePayload struct {
	SecretID string `json:"secret_id"`
	Name     string `json:"name"`
}

// SnapshotMountPayload copies a read-only snapshot of a host folder for a
// launch. The host applies its own source rules again.
type SnapshotMountPayload struct {
	Name       string `json:"name"`
	Source     string `json:"source"`
	MaxBytes   int64  `json:"max_bytes"`
	MaxEntries int    `json:"max_entries"`
}

// Bounds for job payload fields.
const (
	MaxJobLifetime     = 25 * time.Hour
	SnapshotMaxBytes   = 256 << 20
	SnapshotMaxEntries = 20000
	MaxSecretBytes     = 8192
	MaxMounts          = 8
	MaxSecrets         = 8
	MountRoot          = "/var/lib/agentgate/mounts"
)

var (
	// NamePattern is the launch, target, profile and secret name rule.
	NamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	// MountNamePattern matches the POC mount name rule.
	MountNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	// BindSourcePattern keeps a bind source to characters that need no quoting
	// (CheckMountSource also bounds it to 4096 bytes).
	BindSourcePattern = regexp.MustCompile(`^/[A-Za-z0-9._@+/-]+$`)
	// ImagePattern requires an immutable digest reference.
	ImagePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,199}(:[A-Za-z0-9._-]{1,64})?@sha256:[a-f0-9]{64}$`)
	// UpstreamPattern is an exact lowercase DNS host name, optionally with a port.
	UpstreamPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+(:[0-9]{1,5})?$`)
	// HeaderPattern is an HTTP header name.
	HeaderPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	envPattern    = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	reasonPattern = regexp.MustCompile(`^[a-z0-9_.:-]{1,64}$`)
)

func knownJobType(t string) bool {
	for _, v := range JobTypes {
		if v == t {
			return true
		}
	}
	return false
}

// launchBound reports whether a job type is bound to a launch and its digests.
func launchBound(t string) bool {
	return t == JobLaunch || t == JobStop || t == JobCollect
}

// Check validates a job for this host at now: version, type, target binding,
// issue time, deadline, digest binding and the typed payload. It returns the
// decoded payload (one of the *Payload types, by value).
func (j Job) Check(targetID string, now time.Time) (any, error) {
	if j.Version != JobVersion || !validID(j.ID) || !knownJobType(j.Type) {
		return nil, errors.New("hostproto: unknown job version, id or type")
	}
	if j.TargetID != targetID || !validID(targetID) {
		return nil, errors.New("hostproto: job is for another target")
	}
	issued, deadline := time.UnixMilli(j.IssuedAtMS), time.UnixMilli(j.DeadlineMS)
	if issued.After(now.Add(MaxClockSkew)) || !deadline.After(now) || !deadline.After(issued) || deadline.Sub(issued) > MaxJobLifetime {
		return nil, errors.New("hostproto: job is expired, not yet valid, or has an unbounded deadline")
	}
	if launchBound(j.Type) {
		if !validID(j.LaunchID) || !validDigest(j.SpecDigest) || !validDigest(j.PolicyDigest) {
			return nil, errors.New("hostproto: launch job requires launch id and both digests")
		}
	} else if j.Type == JobApplyProfile {
		if j.LaunchID != "" || j.SpecDigest != "" || !validDigest(j.PolicyDigest) {
			return nil, errors.New("hostproto: apply-profile binds only a policy digest")
		}
	} else if j.Type == JobSnapshotMount {
		if j.LaunchID != "" && !validID(j.LaunchID) || j.SpecDigest != "" && !validDigest(j.SpecDigest) || j.PolicyDigest != "" {
			return nil, errors.New("hostproto: snapshot-mount binds at most a launch")
		}
	} else if j.LaunchID != "" || j.SpecDigest != "" || j.PolicyDigest != "" {
		return nil, errors.New("hostproto: this job type is not bound to a launch")
	}
	if len(j.Payload) == 0 {
		return nil, errors.New("hostproto: job payload missing")
	}
	return j.decode()
}

func (j Job) decode() (any, error) {
	switch j.Type {
	case JobProvision:
		var p ProvisionPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if p.Images == nil || len(p.Images) > 8 || !reasonPattern.MatchString(p.Reason) {
			return nil, errors.New("hostproto: provision needs an explicit image list and a reason code")
		}
		for _, image := range p.Images {
			if !ImagePattern.MatchString(image) {
				return nil, errors.New("hostproto: provision image is not digest pinned")
			}
		}
		return p, nil
	case JobApplyProfile:
		var p ApplyProfilePayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !validID(p.ProfileID) || p.ProfileVersion < 1 || SHA256Hex(p.Policy) != j.PolicyDigest {
			return nil, errors.New("hostproto: apply-profile policy differs from its digest")
		}
		return p, nil
	case JobLaunch:
		var p LaunchPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if SHA256Hex(p.Spec) != j.SpecDigest || SHA256Hex(p.Policy) != j.PolicyDigest {
			return nil, errors.New("hostproto: launch spec or policy differs from its digest")
		}
		var spec LaunchSpec
		if err := DecodeStrict(p.Spec, &spec); err != nil {
			return nil, err
		}
		if p.ExpiresAtMS <= j.IssuedAtMS || p.ExpiresAtMS > j.DeadlineMS || p.HeartbeatSeconds < 5 || p.HeartbeatSeconds > 60 {
			return nil, errors.New("hostproto: launch expiry or heartbeat out of range")
		}
		if p.ExpiresAtMS-j.IssuedAtMS > int64(spec.LifetimeSeconds)*1000+int64(MaxClockSkew/time.Millisecond) {
			return nil, errors.New("hostproto: launch expiry exceeds the spec lifetime")
		}
		if err := checkMounts(p.Mounts); err != nil {
			return nil, err
		}
		if err := checkSecrets(p.Secrets); err != nil {
			return nil, err
		}
		return p, nil
	case JobStop:
		var p StopPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !reasonPattern.MatchString(p.Reason) || p.GraceSeconds < 0 || p.GraceSeconds > 300 {
			return nil, errors.New("hostproto: stop needs a reason code and 0..300 grace seconds")
		}
		return p, nil
	case JobCollect:
		var p CollectPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !reasonPattern.MatchString(p.Reason) {
			return nil, errors.New("hostproto: collect needs a reason code")
		}
		return p, nil
	case JobSecretPut:
		var p SecretPutPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !validID(p.SecretID) || !NamePattern.MatchString(p.Name) || !HeaderPattern.MatchString(p.Header) || checkUpstreams(p.Upstreams) != nil {
			return nil, errors.New("hostproto: secret-put metadata invalid")
		}
		raw, err := DecodeSealed(p.Ciphertext)
		if err != nil || SHA256Hex(raw) != p.CiphertextSHA256 {
			return nil, errors.New("hostproto: secret-put ciphertext is not a secretseal envelope or differs from its fingerprint")
		}
		sealed, _ := ParseSealed(raw)
		if sealed.TargetID != j.TargetID || sealed.Name != p.Name {
			return nil, errors.New("hostproto: secret-put envelope is sealed for another target or name")
		}
		// A secret may be stored without rules; every launch that uses it is
		// refused (deny by default). Its other settings are checked all the
		// same, against a placeholder rule.
		rules := p.Rules
		if len(rules) == 0 {
			rules = []BrokerRule{{Methods: []string{"GET"}, Path: "/", Match: "exact"}}
		}
		if err := CheckInjection(p.Header, p.Scheme, p.Username, rules, p.ExtraHeaders); err != nil {
			return nil, fmt.Errorf("hostproto: secret-put policy: %w", err)
		}
		if err := checkForwardHeaders(p.ForwardHeaders); err != nil {
			return nil, err
		}
		policy, err := p.Policy()
		if err != nil || policy.Digest() != p.PolicyDigest || sealed.PolicyDigest != p.PolicyDigest {
			return nil, errors.New("hostproto: secret-put policy differs from the policy digest the envelope seals")
		}
		return p, nil
	case JobSecretDelete:
		var p SecretDeletePayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !validID(p.SecretID) || !NamePattern.MatchString(p.Name) {
			return nil, errors.New("hostproto: secret-delete metadata invalid")
		}
		return p, nil
	case JobSnapshotMount:
		var p SnapshotMountPayload
		if err := DecodeStrict(j.Payload, &p); err != nil {
			return nil, err
		}
		if !MountNamePattern.MatchString(p.Name) || CheckMountSource(p.Source) != nil || p.MaxBytes < 1 || p.MaxBytes > SnapshotMaxBytes || p.MaxEntries < 1 || p.MaxEntries > SnapshotMaxEntries {
			return nil, errors.New("hostproto: snapshot-mount fields invalid")
		}
		return p, nil
	}
	return nil, errors.New("hostproto: unknown job type")
}

func checkMounts(mounts []LaunchMount) error {
	if mounts == nil || len(mounts) > MaxMounts {
		return errors.New("hostproto: mounts must be an explicit bounded array")
	}
	seen := map[string]bool{}
	for _, m := range mounts {
		if !MountNamePattern.MatchString(m.Name) || seen[m.Name] || m.Path != MountRoot+"/"+m.Name || CheckMountSource(m.Source) != nil {
			return errors.New("hostproto: mount invalid or repeated")
		}
		if m.Mode != "read-only" && m.Mode != "snapshot" && m.Mode != "read-write" {
			return errors.New("hostproto: mount mode invalid")
		}
		seen[m.Name] = true
	}
	return nil
}

func checkSecrets(secrets []LaunchSecret) error {
	if secrets == nil || len(secrets) > MaxSecrets {
		return errors.New("hostproto: secrets must be an explicit bounded array")
	}
	seen, envs := map[string]bool{}, map[string]bool{}
	for _, s := range secrets {
		if !NamePattern.MatchString(s.Ref) || seen[s.Ref] || !validID(s.SecretID) || !envPattern.MatchString(s.Env) || envs[s.Env] || !HeaderPattern.MatchString(s.Header) || checkUpstreams(s.Upstreams) != nil {
			return errors.New("hostproto: secret binding invalid or repeated")
		}
		if err := CheckInjection(s.Header, s.Scheme, s.Username, s.Rules, s.ExtraHeaders); err != nil {
			return fmt.Errorf("hostproto: secret %s: %w", s.Ref, err)
		}
		if err := checkForwardHeaders(s.ForwardHeaders); err != nil {
			return err
		}
		if policy, err := s.Policy(); err != nil || !validDigest(s.PolicyDigest) || policy.Digest() != s.PolicyDigest {
			return fmt.Errorf("hostproto: secret %s: its settings differ from its policy digest", s.Ref)
		}
		seen[s.Ref], envs[s.Env] = true, true
	}
	return nil
}

// CheckInjection is the structural check of a secret's injection metadata.
// The broker's own configuration validator (internal/broker) is stricter and
// runs again on the host before anything starts.
func CheckInjection(header, scheme, username string, rules []BrokerRule, extra map[string]string) error {
	authorization := strings.EqualFold(header, "authorization")
	switch scheme {
	case "":
		if username != "" {
			return errors.New("a username is only valid with the Basic scheme")
		}
	case "Bearer":
		if !authorization || username != "" {
			return errors.New("Bearer requires the Authorization header and no username")
		}
	case "Basic":
		if !authorization || username == "" || len(username) > 64 || strings.Contains(username, ":") || !visible(username) {
			return errors.New("Basic requires the Authorization header and a visible ASCII username without a colon")
		}
	default:
		return errors.New(`scheme must be "", Bearer or Basic`)
	}
	if len(rules) < 1 || len(rules) > MaxBrokerRules {
		return errors.New("1 to 64 explicit rules are required (deny by default)")
	}
	for _, r := range rules {
		if err := checkRule(r); err != nil {
			return err
		}
	}
	if len(extra) > MaxBrokerExtraHeaders {
		return errors.New("at most 8 extra headers")
	}
	for name, value := range extra {
		lower := strings.ToLower(name)
		if !HeaderPattern.MatchString(name) || strings.EqualFold(name, header) || lower == "authorization" || lower == "x-api-key" ||
			lower == "host" || lower == "cookie" || strings.HasPrefix(lower, "proxy-") || strings.HasPrefix(lower, "x-forwarded-") {
			return errors.New("an extra header names a header the broker never injects")
		}
		if value == "" || len(value) > 256 || strings.TrimSpace(value) != value || !printable(value, 256) || !asciiOnly(value) {
			return errors.New("extra header values are 1 to 256 printable ASCII characters")
		}
	}
	return nil
}

// checkForwardHeaders is the structural check of a secret's forward_headers;
// the broker refuses every header it never forwards.
func checkForwardHeaders(names []string) error {
	if len(names) > MaxForwardHeaders {
		return errors.New("hostproto: at most 16 forward headers")
	}
	for _, n := range names {
		if !HeaderPattern.MatchString(n) {
			return errors.New("hostproto: a forward header is a header name")
		}
	}
	return nil
}

func checkRule(r BrokerRule) error {
	if len(r.Methods) < 1 || len(r.Methods) > len(BrokerMethods) {
		return errors.New("a rule lists 1 to 7 methods")
	}
	seen := map[string]bool{}
	for _, m := range r.Methods {
		known := false
		for _, allowed := range BrokerMethods {
			known = known || m == allowed
		}
		if !known || seen[m] {
			return errors.New("rule methods are unique and among GET HEAD POST PUT PATCH DELETE OPTIONS")
		}
		seen[m] = true
	}
	if r.Match != "exact" && r.Match != "prefix" {
		return errors.New(`a rule match is "exact" or "prefix"`)
	}
	if !CanonicalRulePath(r.Path) {
		return errors.New("a rule path is a canonical absolute path without percent-encoding or dot segments")
	}
	return nil
}

// CanonicalRulePath accepts an absolute path of RFC 3986 path characters
// without percent-encoding, path parameters (";"), dot-only segments,
// segments ending in "." or empty segments (one trailing slash is allowed),
// at most 512 bytes: the broker's rule path form (agentgate.broker.v2 refuses
// a request path with any of these, so a rule holding one never matches).
func CanonicalRulePath(p string) bool {
	if p == "" || p[0] != '/' || len(p) > maxRulePathBytes {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~!$&'()*+,=:@/", c) >= 0) {
			return false
		}
	}
	segments := strings.Split(p[1:], "/")
	for i, seg := range segments {
		if seg == "" {
			if i != len(segments)-1 {
				return false
			}
			continue
		}
		if strings.Trim(seg, ".") == "" || seg[len(seg)-1] == '.' {
			return false
		}
	}
	return true
}

func visible(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func asciiOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func checkUpstreams(values []string) error {
	if len(values) < 1 || len(values) > 8 {
		return errors.New("hostproto: 1 to 8 upstreams required")
	}
	seen := map[string]bool{}
	for _, v := range values {
		if len(v) > 253 || !UpstreamPattern.MatchString(v) || seen[v] {
			return errors.New("hostproto: upstream must be a unique exact host name")
		}
		seen[v] = true
	}
	return nil
}

// ProtectedMountTrees may never be shared or contain a shared tree: system
// trees, container and VM runtimes' state (their images and volumes hold
// other workloads' data and credentials), the host's backups (which include
// copies of /etc/shadow), logs, mail and spools.
var ProtectedMountTrees = []string{"/proc", "/sys", "/dev", "/run", "/var/run", "/etc", "/root", "/boot", "/usr", "/bin",
	"/sbin", "/lib", "/lib32", "/lib64", "/libx32", "/var/lib/docker", "/var/lib/containerd",
	"/var/lib/cloud", "/var/lib/kubelet", "/snap", "/var/lib/agentgate",
	"/var/lib/containers", "/var/lib/rancher", "/var/lib/systemd", "/var/lib/private", "/var/lib/libvirt", "/var/lib/lxd",
	"/var/lib/incus", "/var/lib/sss", "/var/lib/polkit-1", "/var/lib/sudo", "/var/backups", "/var/log", "/var/mail",
	"/var/spool", "/lost+found"}

// MaxMountRoots bounds a target's mount root allowlist.
const MaxMountRoots = 16

// CheckMountRoots validates a target's mount root allowlist: at most
// MaxMountRoots unique roots, each a source CheckMountSource accepts.
func CheckMountRoots(roots []string) error {
	if roots == nil || len(roots) > MaxMountRoots {
		return fmt.Errorf("hostproto: mount roots must be an explicit list of at most %d", MaxMountRoots)
	}
	seen := map[string]bool{}
	for _, r := range roots {
		if err := CheckMountSource(r); err != nil {
			return err
		}
		if seen[r] {
			return fmt.Errorf("hostproto: mount root %s is listed twice", r)
		}
		seen[r] = true
	}
	return nil
}

// MountUnderRoots reports whether source is one of roots or below one. The
// service refuses a launch mount outside the target's roots, and a host
// agent applies the same rule to its own configured roots: an empty list
// allows no host folder at all.
func MountUnderRoots(source string, roots []string) bool {
	for _, r := range roots {
		if source == r || strings.HasPrefix(source, r+"/") {
			return true
		}
	}
	return false
}

// secretComponents are per-user credential stores; a source may not contain or
// sit inside one.
var secretComponents = []string{".ssh", ".gnupg", ".aws", ".azure", ".config", ".docker", ".kube", ".netrc",
	".git-credentials", ".password-store", ".vault-token", ".local"}

// SecretComponents returns the credential store names no mount source or
// root may pass through (a copy; the Python runtime keeps the same list).
func SecretComponents() []string { return append([]string(nil), secretComponents...) }

func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}

// CheckMountSource applies the static source rules both sides share. The host
// applies its own home-directory and filesystem checks on top.
func CheckMountSource(source string) error {
	if len(source) > 4096 || !BindSourcePattern.MatchString(source) || path.Clean(source) != source || source == "/" {
		return fmt.Errorf("hostproto: mount source must be a canonical absolute path of safe characters: %q", source)
	}
	for _, p := range ProtectedMountTrees {
		if overlaps(source, p) {
			return fmt.Errorf("hostproto: mount source %s overlaps protected tree %s", source, p)
		}
	}
	if strings.HasPrefix(source, "/var/lib/agentgate-") {
		return errors.New("hostproto: mount source overlaps an AgentGate instance directory")
	}
	parts := strings.Split(source[1:], "/")
	for _, part := range parts {
		for _, secret := range secretComponents {
			if part == secret {
				return fmt.Errorf("hostproto: mount source passes through the credential store %s", secret)
			}
		}
	}
	if parts[0] == "home" && len(parts) <= 2 {
		return errors.New("hostproto: mount source is a home directory or contains one")
	}
	return nil
}

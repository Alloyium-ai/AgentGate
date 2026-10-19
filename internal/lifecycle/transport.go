// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

const PrepareProtocol = "agentgate.job.prepare.v1"
const RunProtocol = "agentgate.job.run.v1"
const PreparedProtocol = "agentgate.job.prepared.v1"
const StoppedProtocol = "agentgate.job.stopped.v1"
const TerminalProtocol = "agentgate.job.terminal.v1"
const MaxInputBytes = 1 << 20

var environmentKey = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)

// Manifest names an isolated agent process. No field grants a permission.
// Input travels separately; its exact digest remains inside the signed manifest.
type Manifest struct {
	Protocol         string            `json:"protocol"`
	AgentKind        string            `json:"agent_kind"`
	RuntimeVersion   string            `json:"runtime_version"`
	Executable       string            `json:"executable"`
	ExecutableDigest string            `json:"executable_digest"`
	ImageDigest      string            `json:"image_digest"`
	Arguments        []string          `json:"arguments"`
	Workspace        string            `json:"workspace"`
	Environment      map[string]string `json:"environment"`
	InputDigest      string            `json:"input_digest"`
}

type PrepareRequest struct {
	Protocol             string   `json:"protocol"`
	Manifest             Manifest `json:"manifest"`
	Binding              Binding  `json:"binding"`
	RequiredCapabilities []string `json:"required_capabilities"`
}

type PrepareResponse struct {
	PreparationKeyID      string   `json:"preparation_key_id"`
	PreparationSignature  string   `json:"preparation_signature"`
	PreparedAtUnix        int64    `json:"prepared_at_unix"`
	PreparedMonoNS        uint64   `json:"prepared_mono_ns,string"`
	AuditHeader           []byte   `json:"audit_header"`
	AuditHeaderDigest     string   `json:"audit_header_digest"`
	Protocol              string   `json:"protocol"`
	Binding               Binding  `json:"binding"`
	ManifestDigest        string   `json:"manifest_digest"`
	PreparationDeadlineNS uint64   `json:"preparation_deadline_ns,string"`
	Evidence              Evidence `json:"evidence"`
}

type RunRequest struct {
	Protocol      string        `json:"protocol"`
	Manifest      Manifest      `json:"manifest"`
	Authorization Authorization `json:"authorization"`
	Input         []byte        `json:"input"`
}

type StopRequest struct {
	Protocol string  `json:"protocol"`
	Binding  Binding `json:"binding"`
	Reason   string  `json:"reason"`
}

type StopResponse struct {
	Protocol string   `json:"protocol"`
	Binding  Binding  `json:"binding"`
	Evidence Evidence `json:"evidence"`
}

type JobStatus struct {
	Protocol string    `json:"protocol"`
	Record   Record    `json:"record"`
	Terminal *Terminal `json:"terminal,omitempty"`
}

type Terminal struct {
	Protocol        string  `json:"protocol"`
	Binding         Binding `json:"binding"`
	State           string  `json:"state"`
	ExitCode        int     `json:"exit_code"`
	DomainEmpty     bool    `json:"domain_empty"`
	RightsRemoved   bool    `json:"rights_removed"`
	EvidenceDigest  string  `json:"evidence_digest"`
	Output          []byte  `json:"output,omitempty"`
	OutputDigest    string  `json:"output_digest,omitempty"`
	Stderr          []byte  `json:"stderr,omitempty"`
	StderrDigest    string  `json:"stderr_digest,omitempty"`
	EvidenceVerdict string  `json:"evidence_verdict"`
}

func (m Manifest) Validate() error {
	if m.Protocol != "agentgate.job.manifest.v1" || (m.AgentKind != "codex" && m.AgentKind != "claude" && m.AgentKind != "pi" && m.AgentKind != "ssh") {
		return errors.New("an isolated supported agent manifest is required")
	}
	if !utf8.ValidString(m.RuntimeVersion) || len(m.RuntimeVersion) == 0 || len(m.RuntimeVersion) > 128 || strings.ContainsAny(m.RuntimeVersion, "\x00\n\r") {
		return errors.New("the exact agent runtime version is required")
	}
	for _, path := range []string{m.Executable, m.Workspace} {
		if !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || path == "/tmp" || strings.HasPrefix(path, "/tmp/") || strings.ContainsRune(path, 0) {
			return errors.New("the agent requires canonical private executable and workspace paths")
		}
	}
	if !validDigest(m.ExecutableDigest) || !validDigest(m.InputDigest) || !strings.HasPrefix(m.ImageDigest, "sha256:") || !validDigest(strings.TrimPrefix(m.ImageDigest, "sha256:")) {
		return errors.New("the agent manifest requires exact executable, image and input digests")
	}
	if m.Arguments == nil || m.Environment == nil {
		return errors.New("explicit argument and environment collections are required")
	}
	if len(m.Arguments) > 128 || len(m.Environment) > 64 {
		return errors.New("the agent manifest exceeds its argument or environment bound")
	}
	size := 0
	for _, arg := range m.Arguments {
		size += len(arg)
		if !utf8.ValidString(arg) || strings.ContainsRune(arg, 0) {
			return errors.New("the agent argument contains a null byte")
		}
	}
	for key, value := range m.Environment {
		size += len(key) + len(value)
		if !environmentKey.MatchString(key) || !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
			return errors.New("the explicit agent environment is invalid")
		}
	}
	if size > 65536 {
		return errors.New("the agent manifest exceeds its byte bound")
	}
	if m.AgentKind == "ssh" {
		return m.ValidateSSHCommand()
	}
	return nil
}
func (m Manifest) Digest() (string, error) {
	if err := m.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func (r PrepareRequest) Validate() error {
	if r.Protocol != PrepareProtocol || r.Binding.CgroupID != 0 {
		return errors.New("an unallocated prepare request is required")
	}
	if err := r.Binding.validate(true); err != nil {
		return err
	}
	digest, err := r.Manifest.Digest()
	if err != nil {
		return err
	}
	if digest != r.Binding.JobDigest {
		return errors.New("the prepare manifest differs from the job digest")
	}
	if len(r.RequiredCapabilities) == 0 || len(r.RequiredCapabilities) > 64 {
		return errors.New("required capabilities are missing")
	}
	return nil
}
func (r RunRequest) Validate() error {
	if r.Protocol != RunProtocol || len(r.Input) > MaxInputBytes {
		return errors.New("the run request protocol or input bound is invalid")
	}
	if err := r.Authorization.Binding.validate(false); err != nil {
		return err
	}
	digest, err := r.Manifest.Digest()
	if err != nil {
		return err
	}
	inputHash := sha256.Sum256(r.Input)
	if digest != r.Authorization.Binding.JobDigest || hex.EncodeToString(inputHash[:]) != r.Manifest.InputDigest {
		return errors.New("the actual agent input or manifest differs from the signed job")
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"reflect"
	"time"
)

// TrustFile is a protected provisioned configuration, never a caller approval.
type TrustFile struct {
	Protocol           string                `json:"protocol"`
	AuthorityID        string                `json:"authority_id"`
	KeyID              string                `json:"key_id"`
	SigningKeyFile     string                `json:"signing_key_file"`
	StorePath          string                `json:"store_path"`
	Epoch              string                `json:"epoch"`
	SocketPath         string                `json:"socket_path"`
	SocketGID          *int                  `json:"socket_gid,omitempty"`
	MaxLifetimeSeconds int                   `json:"max_lifetime_seconds"`
	Subjects           map[string]SubjectPin `json:"subjects"`
	NodeKeys           map[string]string     `json:"node_keys"`
	Enrollments        []EnrollmentPin       `json:"enrollments"`
	Documents          map[string]string     `json:"documents"` // digest -> protected JSON file
	Targets            map[string]TargetPin  `json:"targets"`   // node ID -> pinned signed report
}
type SubjectPin struct {
	Role      string `json:"role"`
	PublicKey string `json:"public_key"`
}
type RuntimePin struct {
	Files             []runtimeclosure.File `json:"files"`
	FilesDigest       string                `json:"files_digest"`
	Kind              string                `json:"kind"`
	Version           string                `json:"version"`
	Executable        string                `json:"executable"`
	ExecutableDigest  string                `json:"executable_digest"`
	ImageDigest       string                `json:"image_digest"`
	ArgumentsPrefix   []string              `json:"arguments_prefix,omitempty"`
	EntryScript       string                `json:"entry_script,omitempty"`
	EntryScriptDigest string                `json:"entry_script_digest,omitempty"`
	PackageRoot       string                `json:"package_root,omitempty"`
	PackageDigest     string                `json:"package_digest,omitempty"`
}
type EnrollmentPin struct {
	AgentID       string       `json:"agent_id"`
	AgentKey      string       `json:"agent_key"`
	NodeID        string       `json:"node_id"`
	BootID        string       `json:"boot_id"`
	PolicyDigests []string     `json:"policy_digests"`
	Runtimes      []RuntimePin `json:"runtimes"`
}
type TargetPin struct {
	BootID          string            `json:"boot_id"`
	Challenge       string            `json:"challenge"`
	PublicKey       string            `json:"public_key"`
	ReportFile      string            `json:"report_file"`
	CompilerDigest  string            `json:"compiler_digest"`
	ArtifactDigests map[string]string `json:"artifact_digests"`
}
type FileTrust struct{ config TrustFile }

func ReadPrivate(path string, max int64) ([]byte, error) {
	if e := privatePath(path); e != nil {
		return nil, e
	}
	if e := checkPrivateFile(path); e != nil {
		return nil, e
	}
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || st.Size() > max {
		return nil, errors.New("authority_file_bound_exceeded")
	}
	raw, e := io.ReadAll(io.LimitReader(f, max+1))
	if e != nil || int64(len(raw)) > max {
		return nil, errors.New("authority_file_bound_exceeded")
	}
	return raw, nil
}
func LoadTrust(path string) (TrustFile, *FileTrust, error) {
	var c TrustFile
	raw, e := ReadPrivate(path, 2<<20)
	if e != nil {
		return c, nil, e
	}
	if e = lifecycle.DecodeTransport(bytes.NewReader(raw), &c); e != nil || c.Protocol != "agentgate.authority-config.v1" || len(c.Enrollments) == 0 || len(c.Enrollments) > 1024 || len(c.Documents) == 0 || len(c.Documents) > 1024 || len(c.Targets) == 0 || len(c.Targets) > 64 || c.MaxLifetimeSeconds < 1 || c.MaxLifetimeSeconds > 86400 {
		return c, nil, errors.New("authority_trust_invalid")
	}
	for id, p := range c.Subjects {
		if !identifier.MatchString(id) || (p.Role != "agent" && p.Role != "node") {
			return c, nil, errors.New("authority_subject_invalid")
		}
		if _, e = decodeKey(p.PublicKey); e != nil {
			return c, nil, e
		}
	}
	for _, pin := range c.Enrollments {
		agent, ok := c.Subjects[pin.AgentID]
		node, nok := c.Subjects[pin.NodeID]
		if !ok || agent.Role != "agent" || agent.PublicKey != pin.AgentKey || !nok || node.Role != "node" || pin.NodeID == pin.AgentID || !identifier.MatchString(pin.BootID) || len(pin.PolicyDigests) == 0 || len(pin.Runtimes) == 0 {
			return c, nil, errors.New("authority_enrollment_invalid")
		}
		for _, runtime := range pin.Runtimes {
			set, err := runtimeclosure.New(runtime.Files)
			if err != nil || runtime.FilesDigest != set.Digest() {
				return c, nil, errors.New("authority_runtime_file_pins_required")
			}
			if runtime.Kind == "pi" && !validPiPins(runtime) {
				return c, nil, errors.New("authority_pi_runtime_pins_required")
			}
		}
		for _, d := range pin.PolicyDigests {
			if !digestPattern.MatchString(d) || c.Documents[d] == "" {
				return c, nil, errors.New("authority_document_pin_invalid")
			}
		}
	}
	for id, t := range c.Targets {
		if !identifier.MatchString(id) || !identifier.MatchString(t.BootID) || !identifier.MatchString(t.Challenge) || !digestPattern.MatchString(t.CompilerDigest) {
			return c, nil, errors.New("authority_target_pin_invalid")
		}
		if _, e = decodeKey(t.PublicKey); e != nil {
			return c, nil, e
		}
	}
	frozenRaw, e := json.Marshal(c)
	if e != nil {
		return c, nil, e
	}
	var frozen TrustFile
	if e = json.Unmarshal(frozenRaw, &frozen); e != nil {
		return c, nil, e
	}
	return c, &FileTrust{frozen}, nil
}
func decodeKey(s string) (ed25519.PublicKey, error) {
	k, e := base64.RawURLEncoding.Strict().DecodeString(s)
	if e != nil || len(k) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(k) != s {
		return nil, errors.New("authority_public_key_invalid")
	}
	return ed25519.PublicKey(k), nil
}
func (f *FileTrust) Subjects() (map[string]ProofSubject, error) {
	out := map[string]ProofSubject{}
	for id, p := range f.config.Subjects {
		k, e := decodeKey(p.PublicKey)
		if e != nil {
			return nil, e
		}
		out[id] = ProofSubject{p.Role, k}
	}
	return out, nil
}
func (f *FileTrust) NodeKeys() (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	for id, p := range f.config.NodeKeys {
		k, e := decodeKey(p)
		if e != nil {
			return nil, e
		}
		out[id] = k
	}
	return out, nil
}
func (f *FileTrust) VerifyEnrollment(ctx context.Context, b lifecycle.Binding) error {
	if ctx.Err() != nil || b.Validate(false) != nil {
		return errors.New("authority_enrollment_rejected")
	}
	t, ok := f.config.Targets[b.NodeID]
	if !ok || t.BootID != b.BootID || t.CompilerDigest != b.CompilerDigest || !reflect.DeepEqual(t.ArtifactDigests, b.ArtifactDigests) || b.SchemaDigest != policy.SchemaDigest() {
		return errors.New("authority_target_binding_rejected")
	}
	for _, p := range f.config.Enrollments {
		if matchesEnrollment(p, b) {
			return nil
		}
	}
	return errors.New("authority_enrollment_rejected")
}
func (f *FileTrust) VerifyManifest(ctx context.Context, b lifecycle.Binding, m lifecycle.Manifest) error {
	if e := f.VerifyEnrollment(ctx, b); e != nil {
		return e
	}
	for _, p := range f.config.Enrollments {
		if !matchesEnrollment(p, b) {
			continue
		}
		for _, r := range p.Runtimes {
			if r.Kind == m.AgentKind && r.Version == m.RuntimeVersion && r.Executable == m.Executable && r.ExecutableDigest == m.ExecutableDigest && r.ImageDigest == m.ImageDigest && runtimeFilesMatch(r, b, m) && (m.AgentKind != "pi" || piRuntimeMatches(r, m, b)) {
				return nil
			}
		}
	}
	return errors.New("authority_runtime_unapproved")
}
func (f *FileTrust) Resolve(ctx context.Context, digest string) (policy.Document, error) {
	var d policy.Document
	if ctx.Err() != nil {
		return d, ctx.Err()
	}
	path, ok := f.config.Documents[digest]
	if !ok {
		return d, errors.New("authority_document_unapproved")
	}
	raw, e := ReadPrivate(path, 1<<20)
	if e != nil {
		return d, e
	}
	d, e = policy.Parse(raw, "json")
	if e != nil {
		return d, e
	}
	got, e := d.Digest()
	if e != nil || got != digest {
		return d, errors.New("authority_document_digest_differs")
	}
	return d, nil
}
func (f *FileTrust) Current(ctx context.Context, b lifecycle.Binding) (jobgrant.Snapshot, error) {
	var out jobgrant.Snapshot
	if e := f.VerifyEnrollment(ctx, b); e != nil {
		return out, e
	}
	p := f.config.Targets[b.NodeID]
	raw, e := ReadPrivate(p.ReportFile, 1<<20)
	if e != nil {
		return out, e
	}
	key, e := decodeKey(p.PublicKey)
	if e != nil {
		return out, e
	}
	target, e := policy.VerifyTarget(raw, key, policy.TargetBinding{b.NodeID, b.BootID, p.Challenge}, time.Now().Unix())
	if e != nil {
		return out, e
	}
	if e = target.CheckQualificationPolicy(b.PolicyDigest, p.CompilerDigest, p.ArtifactDigests); e != nil {
		return out, e
	}
	out = jobgrant.Snapshot{Target: target, CompilerDigest: p.CompilerDigest, ArtifactDigests: copyArtifacts(p.ArtifactDigests)}
	return out, nil
}

func matchesEnrollment(p EnrollmentPin, b lifecycle.Binding) bool {
	if p.AgentID != b.AgentID || p.AgentKey != b.AgentKey || p.NodeID != b.NodeID || p.BootID != b.BootID {
		return false
	}
	for _, d := range p.PolicyDigests {
		if d == b.PolicyDigest {
			return true
		}
	}
	return false
}

func copyArtifacts(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

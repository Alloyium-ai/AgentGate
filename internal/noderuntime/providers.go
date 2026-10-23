// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/buildinfo"
	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/nodebackend"
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"time"
)

type Clock struct{}

func (Clock) NowNS() (uint64, error)            { return (lifecycle.MonotonicClock{}).NowNS() }
func (c Clock) Now() (time.Time, uint64, error) { mono, err := c.NowNS(); return time.Now(), mono, err }

type Signer struct {
	ID  string
	key ed25519.PrivateKey
}

func (s *Signer) KeyID() string { return s.ID }
func (s *Signer) Sign(ctx context.Context, raw []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || len(s.key) != ed25519.PrivateKeySize {
		return nil, errors.New("the measured node signer is unavailable")
	}
	return ed25519.Sign(s.key, raw), nil
}
func clone[T any](v T) T {
	raw, _ := json.Marshal(v)
	var out T
	_ = json.Unmarshal(raw, &out)
	return out
}

type Sources struct {
	Config                  Config
	Proof                   domainstore.RootProof
	Signer                  *Signer
	NodeKey                 ed25519.PrivateKey
	NodeKeys, AuthorityKeys map[string]ed25519.PublicKey
	Compiler                string
	Resolver                dnslease.Resolver
	qualificationKey        ed25519.PublicKey
	enrollments             map[string]nodeapi.Enrollment
}

func NewSources(c Config) (*Sources, error) {
	if buildinfo.SourceRevision == "" || c.Qualification.SourceRevision != buildinfo.SourceRevision {
		return nil, errors.New("the node source differs from its CI measurement")
	}
	if len(c.ArtifactDigests) == 0 || len(c.ArtifactDigests) > 64 || !identifier.MatchString(c.NodeID) || !identifier.MatchString(c.NodeKeyID) {
		return nil, errors.New("the measured node artifact registry is absent or invalid")
	}
	for name, digest := range c.ArtifactDigests {
		if !identifier.MatchString(name) || !hash64.MatchString(digest) {
			return nil, errors.New("the node artifact registry contains an invalid identity")
		}
	}
	s := &Sources{Config: clone(c), enrollments: map[string]nodeapi.Enrollment{}}
	var err error
	if s.Resolver, err = configuredResolver(s.Config); err != nil {
		return nil, err
	}
	if s.Proof, err = domainstore.MeasureRoot(c.OwnedPrefix, c.RootQualificationDigest); err != nil {
		return nil, err
	}
	if s.NodeKey, err = privateKey(c.NodeKeyFile); err != nil {
		return nil, err
	}
	if s.NodeKeys, err = pinnedKeys(c.NodeKeys); err != nil {
		return nil, err
	}
	if s.AuthorityKeys, err = pinnedKeys(c.AuthorityKeys); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(s.NodeKey.Public(), s.NodeKeys[c.NodeID+"/"+c.NodeKeyID]) {
		return nil, errors.New("the private node key differs from its pinned registry")
	}
	for _, key := range s.AuthorityKeys {
		if reflect.DeepEqual(key, s.NodeKey.Public()) {
			return nil, errors.New("node and authority signing keys overlap")
		}
	}
	if s.qualificationKey, err = publicKey(c.Qualification.PublicKey); err != nil {
		return nil, err
	}
	if c.Qualification.Challenge == "" || len(c.Qualification.SourceRevision) != 40 {
		return nil, errors.New("the node qualification challenge or source is absent")
	}
	s.Config.ArtifactDigests = clone(c.ArtifactDigests)
	s.Config.ArtifactDigests["domain-root"] = s.Proof.Digest()
	s.Compiler = nodebackend.CompilerDigest(c.ArtifactDigests["node"])
	s.Signer = &Signer{ID: c.NodeKeyID, key: append(ed25519.PrivateKey{}, s.NodeKey...)}
	if len(c.Documents) == 0 || len(c.Documents) > 64 || len(c.Enrollments) == 0 || len(c.Enrollments) > 64 {
		return nil, errors.New("the node requires bounded approved documents and enrolled agents")
	}
	for digest := range c.Documents {
		if _, err = s.Resolve(context.Background(), digest); err != nil {
			return nil, err
		}
	}
	for _, e := range c.Enrollments {
		if !identifier.MatchString(e.AgentID) || !e.Enabled || len(e.Runtimes) == 0 || len(e.Runtimes) > 3 {
			return nil, errors.New("the node enrollment registry is invalid")
		}
		if err = separateAgentKey(e.AgentKey, s.NodeKeys, s.AuthorityKeys); err != nil {
			return nil, err
		}
		if _, ok := s.enrollments[e.AgentID]; ok {
			return nil, errors.New("the node enrollment repeats")
		}
		for kind, r := range e.Runtimes {
			arguments, inputDigest := []string{}, policy.SchemaDigest()
			workspace := "/var/lib/agentgate/workspace"
			environment := map[string]string{}
			if kind == "ssh" {
				arguments = []string{"-c", ":"}
				inputDigest = lifecycle.SSHEmptyInputDigest
				if c.PilotTarget == nil {
					return nil, errors.New("the enrolled SSH runtime has no configured Docker target")
				}
				workspace = c.PilotTarget.Workspace
				environment = enrolledEnvironment(r.Environment)
			} else if len(r.Environment) != 0 {
				return nil, errors.New("a non-SSH enrollment has an SSH toolchain environment")
			}
			manifest := lifecycle.Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: kind, RuntimeVersion: r.Version, Executable: r.Executable, ExecutableDigest: r.ExecutableDigest, ImageDigest: r.ImageDigest, Arguments: arguments, Workspace: workspace, Environment: environment, InputDigest: inputDigest}
			if err = manifest.Validate(); err != nil {
				return nil, err
			}
			if kind != "ssh" {
				if err = jobartifacts.VerifyExecutable(r.Executable, r.ExecutableDigest); err != nil {
					return nil, err
				}
			} else if c.PilotTarget == nil || r.ImageDigest != c.PilotTarget.ImageDigest || manifest.Workspace != c.PilotTarget.Workspace {
				return nil, errors.New("the enrolled SSH runtime differs from the configured Docker target")
			}
		}
		s.enrollments[e.AgentID] = clone(e)
	}
	for _, e := range s.enrollments {
		for kind, runtime := range e.Runtimes {
			arguments := append([]string{}, runtime.ArgumentsPrefix...)
			workspace := "/var/lib/agentgate/workspace"
			environment := map[string]string{}
			if kind == "ssh" {
				arguments = append(arguments, ":")
				workspace = c.PilotTarget.Workspace
				environment = enrolledEnvironment(runtime.Environment)
			}
			m := lifecycle.Manifest{AgentKind: kind, RuntimeVersion: runtime.Version, Executable: runtime.Executable, ExecutableDigest: runtime.ExecutableDigest, ImageDigest: runtime.ImageDigest, Arguments: arguments, Workspace: workspace, Environment: environment, InputDigest: lifecycle.SSHEmptyInputDigest}
			if err = s.VerifyRuntime(context.Background(), lifecycle.Binding{AgentID: e.AgentID, ArtifactDigests: s.Config.ArtifactDigests}, m); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}
func enrolledEnvironment(values map[string]string) map[string]string {
	out := make(map[string]string, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}
func (s *Sources) Resolve(ctx context.Context, digest string) (policy.Document, error) {
	if err := ctx.Err(); err != nil {
		return policy.Document{}, err
	}
	path, ok := s.Config.Documents[digest]
	if !ok || !hash64.MatchString(digest) {
		return policy.Document{}, errors.New("the policy digest is not approved on this node")
	}
	raw, err := readOwned(path, policy.MaxBytes, false)
	if err != nil {
		return policy.Document{}, err
	}
	d, err := policy.Parse(raw, "json")
	if err != nil {
		return d, err
	}
	got, err := d.Digest()
	if err != nil || got != digest {
		return policy.Document{}, errors.New("the approved document bytes differ")
	}
	return d, nil
}
func (s *Sources) Enrollment(ctx context.Context, agent string) (nodeapi.Enrollment, error) {
	if err := ctx.Err(); err != nil {
		return nodeapi.Enrollment{}, err
	}
	e, ok := s.enrollments[agent]
	if !ok || !e.Enabled {
		return e, errors.New("the agent is not enrolled on this node")
	}
	return clone(e), nil
}

type Enrollments struct{ Sources *Sources }

func (e Enrollments) Resolve(ctx context.Context, id string) (nodeapi.Enrollment, error) {
	return e.Sources.Enrollment(ctx, id)
}
func (s *Sources) VerifyEnrollment(ctx context.Context, b lifecycle.Binding) error {
	e, err := s.Enrollment(ctx, b.AgentID)
	if err != nil {
		return err
	}
	if e.AgentKey != b.AgentKey || b.NodeID != s.Config.NodeID || b.BootID != s.Proof.BootID {
		return errors.New("the grant enrollment binding differs")
	}
	return nil
}
func (s *Sources) Snapshot(ctx context.Context) (jobgrant.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return jobgrant.Snapshot{}, err
	}
	raw, err := readOwned(s.Config.Qualification.ReportFile, policy.MaxBytes, false)
	if err != nil {
		return jobgrant.Snapshot{}, err
	}
	target, err := policy.VerifyTarget(raw, s.qualificationKey, policy.TargetBinding{Node: s.Config.NodeID, Boot: s.Proof.BootID, Challenge: s.Config.Qualification.Challenge}, time.Now().Unix())
	if err != nil {
		return jobgrant.Snapshot{}, err
	}
	if target.Report().SourceRevision != s.Config.Qualification.SourceRevision {
		return jobgrant.Snapshot{}, errors.New("the qualified node source differs")
	}
	for _, capability := range target.Report().Capabilities {
		if capability.State == "enforced" {
			policies := make([]string, 0, len(s.Config.Documents))
			for digest := range s.Config.Documents {
				policies = append(policies, digest)
			}
			if err = target.CheckQualificationScope(policies, s.Compiler, s.Config.ArtifactDigests); err != nil {
				return jobgrant.Snapshot{}, err
			}
			break
		}
	}
	return jobgrant.Snapshot{Target: target, CompilerDigest: s.Compiler, ArtifactDigests: clone(s.Config.ArtifactDigests)}, nil
}
func (s *Sources) Current(ctx context.Context, b lifecycle.Binding) (jobgrant.Snapshot, error) {
	if b.NodeID != s.Config.NodeID || b.BootID != s.Proof.BootID || b.SchemaDigest != policy.SchemaDigest() || b.CompilerDigest != s.Compiler || !reflect.DeepEqual(b.ArtifactDigests, s.Config.ArtifactDigests) {
		return jobgrant.Snapshot{}, errors.New("the current node qualification binding differs")
	}
	return s.Snapshot(ctx)
}
func (s *Sources) Target(ctx context.Context) (policy.VerifiedTarget, error) {
	snapshot, err := s.Snapshot(ctx)
	return snapshot.Target, err
}
func (s *Sources) WatchdogKey() (ed25519.PublicKey, error) {
	return publicKey(s.Config.WatchdogPublicKey)
}
func (s *Sources) NodeKeyEncoding() string {
	return base64.RawURLEncoding.EncodeToString(s.NodeKey.Public().(ed25519.PublicKey))
}

func separateAgentKey(raw string, nodes, authorities map[string]ed25519.PublicKey) error {
	key, err := publicKey(raw)
	if err != nil {
		return err
	}
	for _, registry := range []map[string]ed25519.PublicKey{nodes, authorities} {
		for _, trusted := range registry {
			if reflect.DeepEqual(key, trusted) {
				return errors.New("the agent key overlaps a node or authority role")
			}
		}
	}
	return nil
}

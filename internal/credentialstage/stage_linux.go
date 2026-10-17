//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package credentialstage retains sealed credentials in a private mount namespace.
// It grants no file permission and does not verify an authority signature.
// The caller must verify Authorization before Prepare and retain the namespace
// until every workload process and unplaced trusted helper stops.
package credentialstage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"runtime"
	"slices"
	"sync"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"golang.org/x/sys/unix"
)

type Config struct {
	CredentialPolicy lifecycle.CredentialPolicy
	// CheckRead must evaluate the exact immutable policy for this reference.
	// An explicit exact read rule is necessary but does not replace this check.
	CheckRead func(context.Context, lifecycle.Binding, lifecycle.Manifest, lifecycle.CredentialReference) error
	// VerifyStopped must freshly check the whole domain and every unplaced helper.
	// A self-reported empty flag or an old stopped receipt is insufficient.
	VerifyStopped func(context.Context, lifecycle.Binding, lifecycle.Evidence) error
}

type FileMeasurement struct {
	ReferenceID  string `json:"reference_id"`
	ExposedPath  string `json:"exposed_path"`
	Digest       string `json:"digest"`
	Seals        int    `json:"seals"`
	MountFlags   uint64 `json:"mount_flags,string"`
	MountID      uint64 `json:"mount_id,string"`
	Device       uint64 `json:"device,string"`
	Inode        uint64 `json:"inode,string"`
	TargetDevice uint64 `json:"target_device,string"`
	TargetInode  uint64 `json:"target_inode,string"`
	Private      bool   `json:"private"`
}

// Measurement contains metadata only. It excludes source paths and file bytes.
type Measurement struct {
	Protocol        string            `json:"protocol"`
	Binding         lifecycle.Binding `json:"binding"`
	NamespaceDevice uint64            `json:"namespace_device,string"`
	NamespaceInode  uint64            `json:"namespace_inode,string"`
	Files           []FileMeasurement `json:"files"`
	Digest          string            `json:"digest"`
}

type Stage struct {
	mu            sync.Mutex
	namespace     *os.File
	pinned        []*lifecycle.PinnedCredential
	targets       []*os.File
	measurement   Measurement
	verifyStopped func(context.Context, lifecycle.Binding, lifecycle.Evidence) error
	exported      bool
	closed        bool
}

func snapshot[T any](value T) T {
	data, _ := json.Marshal(value)
	var copy T
	_ = json.Unmarshal(data, &copy)
	return copy
}

func measurementDigest(m Measurement) string {
	m.Digest = ""
	raw, _ := json.Marshal(m)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Prepare mounts only pinned descriptors. Source paths never enter the namespace worker.
// Existing targets and every parent must be protected against the runtime UID.
func (c Config) Prepare(ctx context.Context, authorization lifecycle.Authorization, manifest lifecycle.Manifest, references []lifecycle.CredentialReference) (*Stage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.CheckRead == nil || c.VerifyStopped == nil {
		return nil, errors.New("credential staging requires explicit read and fresh stop verifiers")
	}
	a := snapshot(authorization)
	m := snapshot(manifest)
	refs := slices.Clone(references)
	if err := c.validate(a, m, refs); err != nil {
		return nil, err
	}
	s := &Stage{verifyStopped: c.VerifyStopped, measurement: Measurement{Protocol: "agentgate.credential-stage.v1", Binding: snapshot(a.Binding), Files: []FileMeasurement{}}}
	for _, reference := range refs {
		if err := ctx.Err(); err != nil {
			s.dispose()
			return nil, err
		}
		if err := c.CheckRead(ctx, snapshot(a.Binding), snapshot(m), reference); err != nil {
			s.dispose()
			return nil, errors.New("the exact credential read permission was rejected")
		}
		pinned, err := lifecycle.PinCredential(m, a.Binding, reference, c.CredentialPolicy)
		if err != nil {
			s.dispose()
			return nil, errors.New("credential custody validation failed")
		}
		s.pinned = append(s.pinned, pinned)
	}
	// A locked worker exits without UnlockOSThread. Go destroys that OS thread,
	// so no runtime worker can later inherit the private namespace.
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		result <- s.prepareNamespace(ctx)
	}()
	if err := <-result; err != nil {
		s.dispose()
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		s.dispose()
		return nil, err
	}
	s.measurement.Digest = measurementDigest(s.measurement)
	return s, nil
}

func (c Config) validate(a lifecycle.Authorization, m lifecycle.Manifest, refs []lifecycle.CredentialReference) error {
	if err := a.Binding.Validate(false); err != nil {
		return err
	}
	job, err := m.Digest()
	if err != nil || job != a.Binding.JobDigest || len(a.Grant) == 0 {
		return errors.New("credential staging requires the exact authorized manifest and domain")
	}
	document, err := policy.Parse(a.Document, "json")
	if err != nil {
		return errors.New("credential staging requires a valid shared policy document")
	}
	digest, err := document.Digest()
	if err != nil || digest != a.Binding.PolicyDigest || a.Binding.SchemaDigest != policy.SchemaDigest() || !reflect.DeepEqual(document.RequiredCapabilities, a.RequiredCapabilities) {
		return errors.New("credential policy differs from its immutable binding")
	}
	if document.Profile != policy.KernelProfile || document.Runtime == nil || document.Runtime.Bootstrap == nil || !slices.Contains(document.Runtime.Bootstrap.Operations, "credential_namespace") || document.Runtime.UID == 0 || document.Runtime.UID != int(c.CredentialPolicy.RuntimeUID) {
		return errors.New("credential namespace bootstrap and the exact runtime UID must be explicit")
	}
	if len(refs) == 0 || len(refs) > len(a.Binding.ArtifactDigests) {
		return errors.New("an explicit bounded credential reference collection is required")
	}
	ids, paths := map[string]bool{}, map[string]bool{}
	for _, ref := range refs {
		if ids[ref.ID] || paths[ref.ExposedPath] || ref.AgentID != a.Binding.AgentID || ref.AgentKind != m.AgentKind || a.Binding.ArtifactDigests["credential."+ref.ID] != ref.Digest {
			return errors.New("credential references must have distinct exact identity and artifact bindings")
		}
		ids[ref.ID], paths[ref.ExposedPath] = true, true
		explicit := false
		if document.Files != nil {
			for _, rule := range document.Files.Rules {
				if rule.Selector.Kind == "exact" && rule.Selector.Path == ref.ExposedPath && rule.Effect == "allow" && slices.Contains(rule.Operations, "read") {
					explicit = true
				}
			}
		}
		if !explicit || policy.FileEffect(*document.Files, ref.ExposedPath, "read") != "allow" {
			return errors.New("each credential requires an effective explicit exact read rule")
		}
	}
	return nil
}

// NamespaceFD returns a new CLOEXEC descriptor for the trusted held helper.
// The caller owns the returned descriptor and must close it after helper setup.
// Successful export permanently disables Abort, even after the duplicate closes.
func (s *Stage) NamespaceFD() (*os.File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.namespace == nil {
		return nil, errors.New("credential namespace is closed")
	}
	fd, err := unix.FcntlInt(s.namespace.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("credential namespace descriptor cannot duplicate")
	}
	s.exported = true
	return os.NewFile(uintptr(fd), "credential-namespace"), nil
}

func (s *Stage) Measurement() Measurement {
	s.mu.Lock()
	defer s.mu.Unlock()
	return snapshot(s.measurement)
}

// Close retains all custody if either stop check fails. The caller can retry.
func (s *Stage) Close(ctx context.Context, stopped lifecycle.Evidence) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	e := snapshot(stopped)
	b := snapshot(s.measurement.Binding)
	if b.CgroupID == 0 || e.NoDomain || lifecycle.VerifyReadback(e, b, "stopped") != nil {
		return errors.New("credential cleanup requires exact whole-domain stopped evidence")
	}
	if s.verifyStopped == nil || s.verifyStopped(ctx, snapshot(b), e) != nil {
		return errors.New("fresh domain and helper termination verification failed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.dispose()
}

// Abort releases only a namespace that never reached a trusted helper.
func (s *Stage) Abort() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.exported {
		return errors.New("an exported credential namespace requires verified stop cleanup")
	}
	return s.dispose()
}

func (s *Stage) dispose() error {
	var errs []error
	if s.namespace != nil {
		errs = append(errs, s.namespace.Close())
		s.namespace = nil
	}
	for _, f := range s.targets {
		errs = append(errs, f.Close())
	}
	for _, p := range s.pinned {
		errs = append(errs, p.Close())
	}
	s.targets, s.pinned, s.closed = nil, nil, true
	return errors.Join(errs...)
}

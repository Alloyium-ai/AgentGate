// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
)

const QualificationVersionPurpose = "agentgate.native-version-qualification.v1"
const QualificationVersionRuntime = "0.155.1"
const QualificationVersionExecutable = "/opt/agent/codex/bin/codex"
const QualificationVersionSHA256 = "0753dfe1d8b87a52436deb13eb1c549661ef4c84fee2c5aa688385eebeccb761"

// QualificationVersionSpec selects one measured version command. It grants no normal admission rights.
type QualificationVersionSpec QualificationFixtureSpec

func versionInputDigest() string { sum := sha256.Sum256(nil); return hex.EncodeToString(sum[:]) }
func versionStreams(spec QualificationVersionSpec) map[string][]string {
	sum := sha256.Sum256([]byte(spec.Binding.NodeID + "\n" + spec.Binding.RunID))
	root := filepath.Join(spec.OwnedRoot, "streams", "job-"+hex.EncodeToString(sum[:]))
	return map[string][]string{filepath.Join(root, "input"): {"read"}, filepath.Join(root, "output"): {"read", "write"}, filepath.Join(root, "error"): {"read", "write"}}
}
func validateVersionManifest(spec QualificationVersionSpec) error {
	m := spec.Manifest
	files, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil || spec.Binding.ArtifactDigests["runtime.codex.files"] != files.Digest() {
		return errors.New("the native version fixture requires its explicit static file closure")
	}
	if m.Validate() != nil || m.AgentKind != "codex" || m.RuntimeVersion != QualificationVersionRuntime || m.Executable != QualificationVersionExecutable || m.ExecutableDigest != QualificationVersionSHA256 || spec.Binding.ArtifactDigests["runtime.codex"] != QualificationVersionSHA256 || !slices.Equal(m.Arguments, []string{"--version"}) || len(m.Environment) != 0 || m.Workspace != spec.OwnedRoot || m.InputDigest != versionInputDigest() {
		return errors.New("the native version fixture requires its pinned empty-input command")
	}
	digest, err := m.Digest()
	if err != nil || digest != spec.Binding.JobDigest {
		return errors.New("the native version manifest binding differs")
	}
	return nil
}
func validateVersionRuntime(spec QualificationVersionSpec, d policy.Document) error {
	r := d.Runtime
	if r.UID != 65534 || r.GID != 65534 || len(r.Capabilities) != 0 || len(r.SupplementaryGroups) != 0 || !r.NoNewPrivileges || d.Lifecycle.DurationSeconds > 30 || len(d.Network.Rules) != 0 || len(d.Sockets.Rules) != 0 {
		return errors.New("the native version fixture exceeds its fixed runtime")
	}
	if r.IPC != nil && (len(r.IPC.Pipes) != 0 || r.IPC.EventFDs != nil && len(*r.IPC.EventFDs) != 0) || r.Signals != nil && len(*r.Signals) != 0 {
		return errors.New("the native version fixture grants IPC or signal rights")
	}
	if r.Memory != nil {
		if r.Memory.Default != "deny" || (r.Memory.Heap != "allow" && r.Memory.Heap != "deny") {
			return errors.New("the native version memory defaults differ")
		}
		for _, op := range r.Memory.Anonymous {
			if !slices.Contains([]string{"map", "read", "write", "protect"}, op) {
				return errors.New("the native version fixture grants executable anonymous memory")
			}
		}
	}
	calls := []string{"arch_prctl", "brk", "clock_gettime", "close", "dup2", "execve", "exit", "exit_group", "fstat", "futex", "getegid", "geteuid", "getgid", "getpid", "getrandom", "gettid", "getuid", "lseek", "mmap", "mprotect", "munmap", "newfstatat", "openat", "read", "rseq", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "set_robust_list", "set_tid_address", "write"}
	if r.Seccomp.Profile != "explicit-allowlist-notify.v2" || r.Seccomp.Architecture != "x86_64" || r.Seccomp.Default != "deny" {
		return errors.New("the native version syscall defaults differ")
	}
	for _, name := range r.Seccomp.AllowSyscalls {
		if !slices.Contains(calls, name) {
			return errors.New("the native version fixture grants an unsupported syscall")
		}
	}
	if !slices.Contains(r.Seccomp.AllowSyscalls, "execve") {
		return errors.New("the native version fixture lacks its explicit execution permission")
	}
	if r.Bootstrap == nil || r.Bootstrap.HelperDigest != spec.Binding.ArtifactDigests["held-helper"] || r.Bootstrap.MaxHoldSeconds > 30 {
		return errors.New("the native version bootstrap binding differs")
	}
	operations := append([]string{}, r.Bootstrap.Operations...)
	slices.Sort(operations)
	if !slices.Equal(operations, []string{"barrier_read", "filter_finalize", "listener_send", "working_directory"}) {
		return errors.New("the native version bootstrap operations differ")
	}
	return nil
}
func validateVersionResources(spec QualificationVersionSpec, d policy.Document) error {
	allows := 0
	for _, rule := range d.Programs.Rules {
		if rule.Effect == "allow" {
			allows++
			if rule.Selector.Kind != "exact" || rule.Selector.Path != QualificationVersionExecutable || rule.Approval != nil {
				return errors.New("the native version fixture grants another executable")
			}
		}
	}
	if allows != 1 {
		return errors.New("the native version fixture requires one pinned executable")
	}
	streams := versionStreams(spec)
	for _, rule := range d.Files.Rules {
		if rule.Effect != "allow" {
			continue
		}
		if rule.Selector.Kind != "exact" {
			return errors.New("the native version fixture requires exact file selectors")
		}
		allowed := streams[rule.Selector.Path]
		if rule.Selector.Path == QualificationVersionExecutable {
			allowed = []string{"read", "mmap", "map_execute", "mprotect"}
		}
		if len(allowed) == 0 {
			return errors.New("the native version file allowance leaves its exact streams and image")
		}
		for _, op := range rule.Operations {
			if !slices.Contains(allowed, op) {
				return errors.New("the native version file operation differs")
			}
		}
	}
	return nil
}
func validateVersionSpec(spec QualificationVersionSpec) error {
	b := spec.Binding
	if b.Validate(true) != nil || b.CgroupID != 0 || !fixtureRoot(spec.OwnedRoot) || !validDigest(spec.TargetDigest) || len(spec.SourceRevision) != 40 || strings.Trim(spec.SourceRevision, "0123456789abcdef") != "" || b.SchemaDigest != policy.SchemaDigest() {
		return errors.New("the native version fixture scope differs")
	}
	if err := validateVersionManifest(spec); err != nil {
		return err
	}
	d, err := policy.Parse(spec.Document, "json")
	if err != nil {
		return err
	}
	digest, err := d.Digest()
	if err != nil || digest != b.PolicyDigest || spec.CandidateDigest != digest || d.CheckDeclaredRequirements() != nil || d.Profile != policy.KernelProfile || d.Runtime == nil || d.Files == nil || d.Programs == nil || d.Network == nil || d.Sockets == nil || d.Lifecycle == nil {
		return errors.New("the native version execution must preserve its candidate document")
	}
	if err = validateVersionRuntime(spec, d); err != nil {
		return err
	}
	return validateVersionResources(spec, d)
}
func QualificationVersionScopeDigest(spec QualificationVersionSpec) (string, error) {
	if err := validateVersionSpec(spec); err != nil {
		return "", err
	}
	return fixtureDigest(struct {
		Purpose string
		Spec    QualificationVersionSpec
	}{QualificationVersionPurpose, spec}), nil
}
func NewQualificationVersionPermit(ctx context.Context, spec QualificationVersionSpec) (*QualificationFixturePermit, error) {
	digest, err := QualificationVersionScopeDigest(spec)
	if err != nil {
		return nil, err
	}
	return newQualificationPermit(ctx, QualificationFixtureSpec(spec), QualificationVersionPurpose, digest)
}
func NewQualificationVersionManager(backend Backend, verifier Verifier, journal Journal, clock Clock, identity Identity, stopTimeout time.Duration, guard WatchdogGuard, key []byte, permit *QualificationFixturePermit) (*Manager, error) {
	if permit == nil || permit.Purpose() != QualificationVersionPurpose {
		return nil, errors.New("the native version manager requires its own permit purpose")
	}
	return newQualificationManager(backend, verifier, journal, clock, identity, stopTimeout, guard, key, permit)
}

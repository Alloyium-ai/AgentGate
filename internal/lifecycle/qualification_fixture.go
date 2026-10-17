// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"alloyium.local/kernel-poc/internal/buildinfo"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"golang.org/x/sys/unix"
)

const QualificationFixturePurpose = "agentgate.fixed-lifecycle-qualification.v1"
const QualificationFixtureRuntime = "agentgate-fixed-lifecycle-worker.v1"

type QualificationFixtureSpec struct {
	Binding         Binding  `json:"binding"`
	Manifest        Manifest `json:"manifest"`
	Document        []byte   `json:"document"`
	CandidateDigest string   `json:"candidate_digest"`
	TargetDigest    string   `json:"target_digest"`
	SourceRevision  string   `json:"source_revision"`
	OwnedRoot       string   `json:"owned_root"`
}

// QualificationFixturePermit has no transport representation or admission flag.
// Only the measured node in a marked disposable VM can construct this permit.
type QualificationFixturePermit struct {
	mu      sync.Mutex
	spec    QualificationFixtureSpec
	digest  string
	domain  uint64
	purpose string
}

func fixtureDigest(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func fixtureRoot(root string) bool {
	return canonicalPrivate(root) && filepath.Dir(root) == "/var/lib" && strings.HasPrefix(filepath.Base(root), "kernel-poc-qualification-")
}
func fixtureManifest(spec QualificationFixtureSpec) error {
	m := spec.Manifest
	if m.Validate() != nil || m.AgentKind != "codex" || m.RuntimeVersion != QualificationFixtureRuntime || filepath.Base(m.Executable) != "qualification-lifecycle-worker" || !strings.HasPrefix(m.Executable, "/var/lib/") || m.ExecutableDigest != spec.Binding.ArtifactDigests["qualification-lifecycle-worker"] || len(m.Arguments) != 0 || len(m.Environment) != 0 || m.Workspace != spec.OwnedRoot {
		return errors.New("the qualification permit only supports its fixed worker")
	}
	if m.InputDigest != fixtureInputDigest('T') && m.InputDigest != fixtureInputDigest('E') {
		return errors.New("the qualification worker input differs")
	}
	digest, err := m.Digest()
	if err != nil || digest != spec.Binding.JobDigest {
		return errors.New("the qualification manifest binding differs")
	}
	return nil
}
func fixtureInputDigest(value byte) string {
	sum := sha256.Sum256([]byte{value})
	return hex.EncodeToString(sum[:])
}
func fixtureDocument(spec QualificationFixtureSpec) error {
	d, err := policy.Parse(spec.Document, "json")
	if err != nil {
		return err
	}
	digest, err := d.Digest()
	if err != nil || digest != spec.Binding.PolicyDigest || d.CheckDeclaredRequirements() != nil || d.Profile != policy.KernelProfile || d.Runtime == nil || d.Files == nil || d.Programs == nil || d.Network == nil || d.Sockets == nil || d.Lifecycle == nil {
		return errors.New("the qualification fixture document differs")
	}
	r := d.Runtime
	if r.UID != 65534 || r.GID != 65534 || len(r.Capabilities) != 0 || len(r.SupplementaryGroups) != 0 || !r.NoNewPrivileges || d.Lifecycle.DurationSeconds > 30 || len(d.Network.Rules) != 0 || len(d.Sockets.Rules) != 0 {
		return errors.New("the qualification fixture exceeds its fixed runtime")
	}
	if r.Memory != nil && (len(r.Memory.Anonymous) != 0 || r.Memory.Heap != "deny") {
		return errors.New("the lifecycle fixture grants memory rights")
	}
	if r.IPC != nil && (len(r.IPC.Pipes) != 0 || r.IPC.EventFDs != nil && len(*r.IPC.EventFDs) != 0) || r.Signals != nil && len(*r.Signals) != 0 {
		return errors.New("the lifecycle fixture grants IPC or signal rights")
	}
	calls := []string{"read", "write", "close", "openat", "fstat", "dup2", "execve", "exit_group", "getpid", "getppid", "clone", "futex", "clock_gettime", "lseek"}
	for _, name := range r.Seccomp.AllowSyscalls {
		if !slices.Contains(calls, name) {
			return errors.New("the lifecycle fixture grants an unsupported syscall")
		}
	}
	for _, name := range []string{"read", "write", "close", "openat", "fstat", "dup2", "execve", "exit_group", "getpid", "getppid", "clone", "futex"} {
		if !slices.Contains(r.Seccomp.AllowSyscalls, name) {
			return errors.New("the lifecycle fixture lacks an explicit worker syscall")
		}
	}
	if r.Bootstrap == nil || r.Bootstrap.HelperDigest != spec.Binding.ArtifactDigests["held-helper"] || r.Bootstrap.MaxHoldSeconds > 30 {
		return errors.New("the qualification helper binding differs")
	}
	operations := append([]string{}, r.Bootstrap.Operations...)
	slices.Sort(operations)
	if !slices.Equal(operations, []string{"barrier_read", "filter_finalize", "listener_send", "working_directory"}) {
		return errors.New("the qualification fixture bootstrap differs")
	}
	allows := 0
	for _, rule := range d.Programs.Rules {
		if rule.Effect == "allow" {
			allows++
			if rule.Selector.Kind != "exact" || rule.Selector.Path != spec.Manifest.Executable || rule.Approval != nil {
				return errors.New("the qualification fixture grants another executable")
			}
		}
	}
	if allows != 1 {
		return errors.New("the qualification fixture requires one fixed executable")
	}
	for _, rule := range d.Files.Rules {
		if rule.Effect != "allow" {
			continue
		}
		if rule.Selector.Kind != "exact" {
			return errors.New("the qualification fixture requires exact file selectors")
		}
		worker := rule.Selector.Path == spec.Manifest.Executable
		stream := !worker && strings.HasPrefix(rule.Selector.Path, spec.OwnedRoot+"/")
		if !stream && !worker {
			return errors.New("the qualification file allowance leaves its owned root")
		}
		for _, op := range rule.Operations {
			if !(stream && (op == "read" || op == "write")) && !(worker && (op == "read" || op == "mmap" || op == "map_execute" || op == "mprotect")) {
				return errors.New("the qualification file operation differs")
			}
		}
	}
	return nil
}
func validateFixtureSpec(spec QualificationFixtureSpec) error {
	if spec.Binding.Validate(true) != nil || spec.Binding.CgroupID != 0 || !fixtureRoot(spec.OwnedRoot) || !validDigest(spec.CandidateDigest) || !validDigest(spec.TargetDigest) || (len(spec.SourceRevision) != 40 || strings.Trim(spec.SourceRevision, "0123456789abcdef") != "") || spec.Binding.SchemaDigest != policy.SchemaDigest() {
		return errors.New("the qualification fixture scope is invalid")
	}
	if err := fixtureManifest(spec); err != nil {
		return err
	}
	return fixtureDocument(spec)
}
func verifyFixtureFile(ctx context.Context, path, digest string) error {
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&022 != 0 || st.Mode&0111 == 0 {
		return errors.New("the qualification artifact custody differs")
	}
	set, err := runtimeclosure.New([]runtimeclosure.File{{Path: path, SHA256: digest, Bytes: st.Size, Mode: st.Mode & 0777, GID: st.Gid}})
	if err != nil {
		return err
	}
	_, err = set.Verify(ctx)
	return err
}
func NewQualificationFixturePermit(ctx context.Context, spec QualificationFixtureSpec) (*QualificationFixturePermit, error) {
	if err := validateFixtureSpec(spec); err != nil {
		return nil, err
	}
	digest, err := QualificationFixtureScopeDigest(spec)
	if err != nil {
		return nil, err
	}
	return newQualificationPermit(ctx, spec, QualificationFixturePurpose, digest)
}

func newQualificationPermit(ctx context.Context, spec QualificationFixtureSpec, purpose, digest string) (*QualificationFixturePermit, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("the qualification fixture requires root custody")
	}
	if err := kernel.Preflight(); err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) != spec.Binding.BootID || buildinfo.SourceRevision != spec.SourceRevision {
		return nil, errors.New("the qualification fixture boot or source differs")
	}
	now, err := kernel.MonotonicNS()
	if err != nil || spec.Binding.DeadlineNS <= now || spec.Binding.DeadlineNS-now > uint64(30*time.Second) {
		return nil, errors.New("the qualification fixture deadline exceeds its bound")
	}
	for path := spec.OwnedRoot; ; path = filepath.Dir(path) {
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&022 != 0 {
			return nil, errors.New("the qualification fixture root custody differs")
		}
		if path == "/" {
			break
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if err = verifyFixtureFile(ctx, executable, spec.Binding.ArtifactDigests["node"]); err != nil {
		return nil, err
	}
	if err = verifyFixtureFile(ctx, spec.Manifest.Executable, spec.Manifest.ExecutableDigest); err != nil {
		return nil, err
	}
	object, err := elf.Open(spec.Manifest.Executable)
	if err != nil {
		return nil, err
	}
	defer object.Close()
	if object.Machine != elf.EM_X86_64 {
		return nil, errors.New("the qualification worker architecture differs")
	}
	for _, program := range object.Progs {
		if program.Type == elf.PT_INTERP {
			return nil, errors.New("the fixed qualification worker must be static")
		}
	}
	owned := clone(spec)
	return &QualificationFixturePermit{spec: owned, digest: digest, purpose: purpose}, nil
}

func (p *QualificationFixturePermit) Purpose() string {
	if p == nil {
		return ""
	}
	if p.purpose == "" {
		return QualificationFixturePurpose
	}
	return p.purpose
}
func (p *QualificationFixturePermit) Digest() string {
	if p == nil {
		return ""
	}
	return p.digest
}
func (p *QualificationFixturePermit) TargetDigest() string {
	if p == nil {
		return ""
	}
	return p.spec.TargetDigest
}
func (p *QualificationFixturePermit) CheckBinding(binding Binding, initial bool) error {
	if p == nil || !validDigest(p.digest) {
		return errors.New("the qualification fixture permit is absent")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	expected := clone(p.spec.Binding)
	expected.CgroupID = binding.CgroupID
	if !expected.same(binding) || binding.CgroupID == 0 && !initial || binding.CgroupID != 0 && (p.domain == 0 || p.domain != binding.CgroupID) {
		return errors.New("the qualification fixture binding differs")
	}
	return nil
}
func (p *QualificationFixturePermit) Resolve(binding Binding) error {
	if p == nil || !validDigest(p.digest) || binding.CgroupID == 0 {
		return errors.New("the qualification fixture domain is absent")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	expected := clone(p.spec.Binding)
	expected.CgroupID = binding.CgroupID
	if !expected.same(binding) || p.domain != 0 && p.domain != binding.CgroupID {
		return errors.New("the qualification fixture domain changed")
	}
	p.domain = binding.CgroupID
	return nil
}
func (p *QualificationFixturePermit) CheckDocument(document []byte) error {
	if p == nil {
		return errors.New("the qualification fixture permit is absent")
	}
	d, err := policy.Parse(document, "json")
	if err != nil {
		return err
	}
	digest, err := d.Digest()
	if err != nil || digest != p.spec.Binding.PolicyDigest {
		return errors.New("the qualification fixture document changed")
	}
	return nil
}
func (p *QualificationFixturePermit) CheckManifest(manifest Manifest) error {
	if p == nil || !reflect.DeepEqual(manifest, p.spec.Manifest) {
		return errors.New("the qualification fixture manifest changed")
	}
	return nil
}
func (p *QualificationFixturePermit) CheckAuthorization(a Authorization) error {
	if err := p.CheckBinding(a.Binding, false); err != nil {
		return err
	}
	if err := p.CheckDocument(a.Document); err != nil {
		return err
	}
	d, err := policy.Parse(a.Document, "json")
	if err != nil || !slices.Equal(a.RequiredCapabilities, d.RequiredCapabilities) {
		return errors.New("the qualification fixture requirements changed")
	}
	return nil
}
func (p *QualificationFixturePermit) CheckCapabilities(e Evidence, required []string) error {
	if p.CheckBinding(e.Binding, false) != nil || e.FixturePurpose != p.Purpose() || len(required) == 0 || len(e.Capabilities) != len(required) {
		return errors.New("the qualification fixture evidence differs")
	}
	for _, id := range required {
		cap := e.Capabilities[id]
		if cap.State != "fixture-only" || !slices.Equal(cap.Mechanisms, []string{p.Purpose()}) || cap.EvidenceDigest != p.digest {
			return errors.New("the qualification fixture capability is not a report")
		}
	}
	return nil
}

// NewQualificationFixtureManager keeps fixture evidence outside normal admission.
func NewQualificationFixtureManager(backend Backend, verifier Verifier, journal Journal, clock Clock, identity Identity, stopTimeout time.Duration, guard WatchdogGuard, key []byte, permit *QualificationFixturePermit) (*Manager, error) {
	if permit == nil || permit.Purpose() != QualificationFixturePurpose {
		return nil, errors.New("the fixed worker manager requires its own permit purpose")
	}
	return newQualificationManager(backend, verifier, journal, clock, identity, stopTimeout, guard, key, permit)
}

func newQualificationManager(backend Backend, verifier Verifier, journal Journal, clock Clock, identity Identity, stopTimeout time.Duration, guard WatchdogGuard, key []byte, permit *QualificationFixturePermit) (*Manager, error) {
	owned, ok := backend.(interface{ QualificationFixtureDigest() string })
	signed, signatureScope := verifier.(interface{ QualificationFixtureDigest() string })
	if !signatureScope || permit == nil || signed.QualificationFixtureDigest() != permit.Digest() {
		return nil, errors.New("the fixture manager requires its exact signature verifier")
	}
	if permit == nil || !validDigest(permit.Digest()) || !ok || owned.QualificationFixtureDigest() != permit.Digest() || identity.NodeID != permit.spec.Binding.NodeID || identity.BootID != permit.spec.Binding.BootID {
		return nil, errors.New("the fixture manager requires the exact opaque backend permit")
	}
	manager, err := NewGuarded(backend, verifier, journal, clock, identity, stopTimeout, guard, key)
	if err != nil {
		return nil, err
	}
	manager.fixture = permit
	return manager, nil
}
func (m *Manager) checkCapabilities(e Evidence, required []string) error {
	if m.fixture != nil {
		return m.fixture.CheckCapabilities(e, required)
	}
	if e.FixturePurpose != "" {
		return errors.New("fixture evidence cannot qualify normal admission")
	}
	return checkCapabilities(e, required)
}
func (m *Manager) checkEvidence(e Evidence, b Binding, phase string) error {
	if phase != "stopped" {
		if m.fixture == nil && e.FixturePurpose != "" {
			return errors.New("fixture evidence cannot enter normal admission")
		}
		if m.fixture != nil && (e.FixturePurpose != m.fixture.Purpose() || m.fixture.CheckBinding(b, false) != nil) {
			return errors.New("the fixture evidence purpose or binding differs")
		}
	}
	return checkEvidence(e, b, phase)
}

func (p *QualificationFixturePermit) InitialBinding() Binding {
	if p == nil {
		return Binding{}
	}
	return clone(p.spec.Binding)
}

// QualificationFixtureScopeDigest identifies a specification; it creates no permit.
func QualificationFixtureScopeDigest(spec QualificationFixtureSpec) (string, error) {
	if err := validateFixtureSpec(spec); err != nil {
		return "", err
	}
	return fixtureDigest(struct {
		Purpose string
		Spec    QualificationFixtureSpec
	}{QualificationFixturePurpose, spec}), nil
}

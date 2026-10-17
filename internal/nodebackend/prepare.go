// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/anonrules"
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

// Limits reduce resource use. They confer no permission on a job.
type Limits struct {
	MemoryBytes uint64
	PIDs        uint32
	CPUQuotaUS  uint32
}

func (l Limits) validate() error {
	if l.MemoryBytes < 16<<20 || l.MemoryBytes > 8<<30 || l.PIDs < 1 || l.PIDs > 1024 || l.CPUQuotaUS < 1000 || l.CPUQuotaUS > 200000 {
		return errors.New("explicit bounded memory, PID and CPU limits are required")
	}
	return nil
}
func (b *Backend) limits(r domainstore.Reservation) error {
	path := filepath.Join(domainstore.RootPath, r.Name)
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Ino != r.Binding.CgroupID {
		return errors.New("the limit domain inode differs")
	}
	values := map[string]string{"memory.max": strconv.FormatUint(b.config.Limits.MemoryBytes, 10), "pids.max": strconv.FormatUint(uint64(b.config.Limits.PIDs), 10), "cpu.max": fmt.Sprintf("%d 100000", b.config.Limits.CPUQuotaUS)}
	for name, value := range values {
		f, e := unix.Openat(fd, name, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return e
		}
		_, e = unix.Write(f, []byte(value))
		unix.Close(f)
		if e != nil {
			return e
		}
		raw, e := readAt(fd, name)
		if e != nil {
			return e
		}
		if strings.TrimSpace(string(raw)) != value {
			return errors.New("the resource limit readback differs")
		}
	}
	return nil
}
func readAt(fd int, name string) ([]byte, error) {
	f, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer unix.Close(f)
	raw := make([]byte, 4096)
	n, err := unix.Read(f, raw)
	if err != nil {
		return nil, err
	}
	if n == len(raw) {
		return nil, errors.New("the control read exceeds its bound")
	}
	return raw[:n], nil
}
func (b *Backend) qualification(ctx context.Context, r *run) error {
	if b.fixture != nil {
		if err := b.fixture.CheckBinding(r.binding, r.binding.CgroupID == 0); err != nil {
			return err
		}
		raw, err := r.document.Canonical()
		if err != nil {
			return err
		}
		return b.fixture.CheckDocument(raw)
	}
	snapshot, err := b.config.Qualification.Current(ctx, r.binding)
	if err != nil {
		return err
	}
	report := snapshot.Target.Report()
	if snapshot.Target.Digest() == "" || report.Node != r.binding.NodeID || report.Boot != r.binding.BootID || report.PolicySchemaDigest != r.binding.SchemaDigest || snapshot.CompilerDigest != r.binding.CompilerDigest || !reflect.DeepEqual(snapshot.ArtifactDigests, r.binding.ArtifactDigests) {
		return errors.New("the current qualification differs from the prepared binding")
	}
	for _, id := range r.document.RequiredCapabilities {
		cap := report.Capabilities[id]
		if cap.State != "enforced" || len(cap.Mechanisms) == 0 || !validDigest(cap.ReceiptSHA256) {
			return fmt.Errorf("the requested capability is unqualified: %s", id)
		}
	}
	if r.qualification.Target.Digest() != "" {
		old, e := jobgrant.QualificationDigest(r.qualification)
		if e != nil {
			return e
		}
		now, e := jobgrant.QualificationDigest(snapshot)
		if e != nil {
			return e
		}
		if now != old {
			return errors.New("the prepared target qualification changed")
		}
	}
	snapshot.ArtifactDigests = copyValue(snapshot.ArtifactDigests)
	r.qualification = snapshot
	return nil
}
func (b *Backend) evidence(r *run, phase string, process *lifecycle.HeldProcess, empty bool) (lifecycle.Evidence, error) {
	active := phase == "released"
	if phase == "prepared" {
		phase = "quarantined"
	}
	if active {
		phase = "active"
	}
	e := lifecycle.Evidence{Binding: copyValue(r.binding), Phase: phase, Quarantined: !active, Released: active, Empty: empty, Process: process, Capabilities: map[string]lifecycle.Capability{}}
	if phase == "installed" || active {
		if r.kernelDeadline == 0 || r.kernelDeadline > r.binding.DeadlineNS {
			return e, errors.New("the installed grant expiry bound is absent")
		}
		e.EffectiveDeadlineNS = r.kernelDeadline
	}
	if r.group == nil || r.observation == nil {
		return e, errors.New("the prepared attachments are absent")
	}
	hooks := map[string][]string{"files": r.group.Files.Hooks(), "peers": r.group.Peers.Hooks(), "sockets": r.group.Sockets.Hooks(), "custody": r.group.Custody.Hooks(), "process": r.group.Process.Hooks(), "syscalls": r.observation.Hooks()}
	if len(hooks["files"]) != 21 || len(hooks["peers"]) != 6 || len(hooks["sockets"]) != 15 || len(hooks["custody"]) != 2 || len(hooks["process"]) != 3 || len(hooks["syscalls"]) != len(syscallrules.Programs()) {
		return e, errors.New("the mandatory attachment count differs")
	}
	if r.group.Anonymous != nil {
		if err := anonrules.VerifyCoupling(r.group.Files, r.group.Anonymous); err != nil {
			return e, err
		}
		hooks["anonymous"] = r.group.Anonymous.Hooks()
	}
	e.MandatoryHooks = true
	if b.fixture != nil {
		e.FixturePurpose = b.fixture.Purpose()
	}
	report := r.qualification.Target.Report()
	for _, id := range r.document.RequiredCapabilities {
		if b.fixture != nil {
			e.Capabilities[id] = lifecycle.Capability{State: "fixture-only", Mechanisms: []string{b.fixture.Purpose()}, EvidenceDigest: b.fixture.Digest()}
			continue
		}
		cap := report.Capabilities[id]
		state := "unsupported"
		if cap.State == "enforced" {
			state = "qualified"
		}
		e.Capabilities[id] = lifecycle.Capability{State: state, Mechanisms: append([]string{}, cap.Mechanisms...), EvidenceDigest: cap.ReceiptSHA256}
	}
	counters, err := r.group.Counters()
	if err != nil {
		return e, err
	}
	observer, err := r.observation.Counters()
	if err != nil {
		return e, err
	}
	e.Decisions = counters.Decisions
	e.Lost = counters.Lost + observer.Lost
	e.CountersAvailable = true
	var observed syscallrules.Binding
	if r.observation.Collection.Maps["audit_bindings"].Lookup(r.binding.CgroupID, &observed) != nil || observed != (syscallrules.Binding{Generation: r.binding.Generation, ExpiresNS: r.deadline()}) {
		return e, errors.New("the syscall observation readback differs")
	}
	installed := ""
	if phase != "installed" && !active {
		quarantine, readErr := r.group.ReadQuarantine()
		if readErr != nil {
			return e, readErr
		}
		installed, err = quarantine.Digest()
		if err != nil {
			return e, err
		}
	}
	if phase == "installed" || active {
		if installed, err = r.group.VerifyInstalled(r.plan); err != nil {
			return e, err
		}
	}
	e.ReadbackDigest = digest(struct {
		Binding             lifecycle.Binding
		Phase               string
		Hooks               map[string][]string
		Plan                string
		Installed           string
		Counters            kernel.Counters
		Observer            kernel.Counters
		EffectiveDeadlineNS uint64
	}{r.binding, phase, hooks, r.plan.Digest(), installed, counters, observer, e.EffectiveDeadlineNS})
	e.Digest = lifecycle.EvidenceDigest(e)
	return e, nil
}
func (b *Backend) Prepare(ctx context.Context, binding lifecycle.Binding) (out lifecycle.Evidence, err error) {
	if binding.Validate(true) != nil || binding.CgroupID != 0 || binding.NodeID != b.config.Domain.NodeID || binding.BootID != b.config.Domain.Proof.BootID || binding.CompilerDigest != b.config.CompilerDigest || !reflect.DeepEqual(binding.ArtifactDigests, b.config.ArtifactDigests) {
		return out, errors.New("the new backend binding differs from the measured node")
	}
	doc, err := b.config.Documents.Resolve(ctx, binding.PolicyDigest)
	if err != nil {
		return out, err
	}
	doc = copyValue(doc)
	if needsCredentials(doc) && b.config.Credentials == nil {
		return out, errors.New("the credential namespace has no configured broker custody")
	}
	if doc.Runtime != nil && doc.Runtime.IPC != nil && doc.Runtime.IPC.EventFDs != nil && len(*doc.Runtime.IPC.EventFDs) > 0 && b.config.Artifacts.Anonymous == "" {
		return out, errors.New("the requested eventfd guard artifact is unavailable")
	}
	docDigest, err := doc.Digest()
	if err != nil || docDigest != binding.PolicyDigest {
		return out, errors.New("the immutable prepared document differs")
	}
	now, err := b.config.Clock.NowNS()
	if err != nil {
		return out, err
	}
	if binding.DeadlineNS <= now {
		return out, errors.New("the prepared deadline expired")
	}
	r := &run{binding: copyValue(binding), document: doc, phase: "preparing", exitCode: -1}
	if err = b.qualification(ctx, r); err != nil {
		return out, err
	}
	b.mu.Lock()
	if _, ok := b.runs[binding.RunID]; ok {
		b.mu.Unlock()
		return out, errors.New("the backend run already exists")
	}
	if len(b.runs) >= b.config.MaxRuns {
		b.mu.Unlock()
		return out, errors.New("the node domain capacity is full")
	}
	b.runs[binding.RunID] = r
	b.mu.Unlock()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.reservation, err = b.domains.Reserve(ctx, binding); err != nil {
		return out, err
	}
	if r.binding, err = b.domains.Create(ctx, r.reservation); err != nil {
		return out, err
	}
	if b.fixture != nil {
		if err = b.fixture.Resolve(r.binding); err != nil {
			return out, err
		}
	}
	if r.reservation, err = b.domains.Resolve(ctx, r.binding); err != nil {
		return out, err
	}
	if r.plan, err = b.compile(ctx, r); err != nil {
		return out, err
	}
	if err = r.plan.ValidateChildBootstrap(b.config.ArtifactDigests["held-helper"]); err != nil {
		return out, err
	}
	if err = b.limits(r.reservation); err != nil {
		return out, err
	}
	path := filepath.Join(domainstore.RootPath, r.reservation.Name)
	if r.group, err = enforcement.New(path, r.binding.CgroupID, b.config.Artifacts); err != nil {
		return out, err
	}
	if r.observation, err = kernel.AttachOwnedProfile(b.config.ObservationObject, path, "syscalls", r.binding.CgroupID, b.config.ObservationProfile); err != nil {
		return out, err
	}
	observed := syscallrules.Binding{Generation: r.binding.Generation, ExpiresNS: r.binding.DeadlineNS}
	m := r.observation.Collection.Maps["audit_bindings"]
	if m == nil {
		return out, errors.New("the syscall observation binding map is absent")
	}
	if err = m.Update(r.binding.CgroupID, observed, ebpf.UpdateExist); err != nil {
		return out, err
	}
	var readback syscallrules.Binding
	if err = m.Lookup(r.binding.CgroupID, &readback); err != nil {
		return out, err
	}
	if readback != observed {
		return out, errors.New("the syscall observation readback differs")
	}
	qd := ""
	if b.fixture != nil {
		qd = b.fixture.Digest()
	} else {
		qd, err = jobgrant.QualificationDigest(r.qualification)
		if err != nil {
			return out, err
		}
	}
	r.header = jobaudit.Header{Protocol: jobaudit.HeaderProtocol, Binding: copyValue(r.binding), DocumentDigest: r.binding.PolicyDigest, QualificationDigest: qd, RequiredCapabilities: append([]string{}, doc.RequiredCapabilities...), CreatedMonoNS: now}
	if b.fixture != nil {
		r.header.FixturePurpose = b.fixture.Purpose()
	}
	names := []string{}
	for name := range jobaudit.ResourceFormats() {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		format := jobaudit.ResourceFormats()[name]
		r.header.RequiredStreams = append(r.header.RequiredStreams, jobaudit.Stream{Name: name, Kind: "resource", Version: format.Version, ArtifactDigest: r.binding.ArtifactDigests[name]})
	}
	for name, format := range jobaudit.ObservationFormats() {
		r.header.RequiredStreams = append(r.header.RequiredStreams, jobaudit.Stream{Name: name, Kind: "observation", Version: format.Version, ArtifactDigest: r.binding.ArtifactDigests[name]})
	}
	r.header.RequiredStreams = append(r.header.RequiredStreams, jobaudit.Stream{Name: "node", Kind: "control", Version: "nodecontrol.v1", ArtifactDigest: r.binding.ArtifactDigests["node"]})
	if r.headerBytes, err = jobaudit.HeaderBytes(r.header); err != nil {
		return out, err
	}
	if r.headerDigest, err = jobaudit.HeaderDigest(r.header); err != nil {
		return out, err
	}
	if r.writer, err = jobaudit.Open(jobaudit.Config{Path: filepath.Join(b.config.AuditRoot, r.reservation.Name+".audit"), Header: r.header, Registry: nodecontrol.Registry(b.config.Registry, r.binding), Clock: b.config.Clock, Document: r.document, AuthorityKeys: b.config.AuthorityKeys, NodeKeys: b.config.NodeKeys, MaxRecords: 100000, MaxBytes: 256 << 20}); err != nil {
		return out, err
	}
	runtimes := map[string]*kernel.Runtime{"files": r.group.Files, "peers": r.group.Peers, "sockets": r.group.Sockets, "custody": r.group.Custody, "process": r.group.Process, "syscalls": r.observation}
	if r.collectors, err = newCollectors(r.writer, b.config.Registry, runtimes); err != nil {
		return out, err
	}
	collectCtx, cancel := context.WithCancel(context.Background())
	r.collectCancel = cancel
	r.collectors.start(collectCtx)
	quarantine, readErr := r.group.ReadQuarantine()
	if readErr != nil {
		return out, readErr
	}
	wire, wireErr := quarantine.Wire()
	if wireErr != nil {
		return out, wireErr
	}
	if err = r.control(ctx, "quarantine_readback", wire); err != nil {
		return out, err
	}
	r.phase = "prepared"
	return b.evidence(r, r.phase, nil, true)
}
func (b *Backend) ListDomains(ctx context.Context) ([]lifecycle.Binding, error) {
	return b.domains.ListOwnedDomains(ctx)
}
func (b *Backend) VerifyHeld(ctx context.Context, binding lifecycle.Binding, p lifecycle.HeldProcess) error {
	r, err := b.get(binding.RunID)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(r.binding, binding) || r.child == nil || r.child.Held == nil {
		return errors.New("the held helper custody is absent")
	}
	return r.child.Held.Verify(ctx, p)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type testClock struct {
	now uint64
	err error
}

func (c *testClock) NowNS() (uint64, error) { return c.now, c.err }

type testVerifier struct {
	err   error
	calls int
}

func (v *testVerifier) Verify(context.Context, Authorization) error { v.calls++; return v.err }

type testBackend struct {
	domains           map[string]Binding
	processes         map[string]HeldProcess
	held              map[string]bool
	calls             []string
	unqualified       bool
	corrupt           string
	stopIncomplete    bool
	effectiveDeadline uint64
}

func backendFixture() *testBackend {
	return &testBackend{domains: map[string]Binding{}, processes: map[string]HeldProcess{}, held: map[string]bool{}, effectiveDeadline: 999}
}
func fixtureBinding() Binding {
	return Binding{AgentID: "agent-one", AgentKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), JobDigest: strings.Repeat("a", 64), GrantID: "grant-one", RunID: "run-one", NodeID: "node-one", BootID: "boot-one", PolicyDigest: strings.Repeat("b", 64), SchemaDigest: strings.Repeat("c", 64), CompilerDigest: strings.Repeat("d", 64), ArtifactDigests: map[string]string{"file-open": strings.Repeat("e", 64), "watchdog": strings.Repeat("9", 64)}, Generation: 1, DeadlineNS: 1000}
}
func (b *testBackend) evidence(binding Binding, phase string) Evidence {
	e := Evidence{Binding: clone(binding), Phase: phase, MandatoryHooks: true, Quarantined: true, ReadbackDigest: strings.Repeat("f", 64), Capabilities: map[string]Capability{"fs.rules.v1": {State: "qualified", Mechanisms: []string{"test-only-hook"}, EvidenceDigest: strings.Repeat("1", 64)}}}
	if p, ok := b.processes[binding.RunID]; ok {
		e.Process = &p
	}
	if b.unqualified {
		c := e.Capabilities["fs.rules.v1"]
		c.State = "probe-only"
		e.Capabilities["fs.rules.v1"] = c
	}
	if phase == "installed" || phase == "active" {
		e.EffectiveDeadlineNS = b.effectiveDeadline
	}
	if phase == "quarantined" {
		e.Empty = true
	}
	if phase == "active" || phase == "recovered" {
		e.Quarantined = false
		e.Released = true
	}
	if phase == "stopped" {
		e.Quarantined = false
		e.Terminated = true
		e.NoDomain = binding.CgroupID == 0
		e.Empty = !b.stopIncomplete
		e.RightsRemoved = true
	}
	if b.corrupt == phase {
		e.Binding.Generation++
	}
	e.Digest = EvidenceDigest(e)
	return e
}
func (b *testBackend) ListDomains(context.Context) ([]Binding, error) {
	b.calls = append(b.calls, "list")
	out := []Binding{}
	for _, v := range b.domains {
		out = append(out, clone(v))
	}
	return out, nil
}
func (b *testBackend) Prepare(_ context.Context, v Binding) (Evidence, error) {
	b.calls = append(b.calls, "prepare")
	v.CgroupID = uint64(100 + len(b.domains))
	b.domains[v.RunID] = clone(v)
	b.held[v.RunID] = true
	return b.evidence(v, "quarantined"), nil
}
func (b *testBackend) Place(_ context.Context, v Binding, p HeldProcess) (Evidence, error) {
	b.calls = append(b.calls, "place")
	b.processes[v.RunID] = p
	return b.evidence(v, "placed"), nil
}
func (b *testBackend) Install(_ context.Context, a Authorization) (Evidence, error) {
	b.calls = append(b.calls, "install")
	if !b.held[a.Binding.RunID] {
		return Evidence{}, errors.New("test tried live map replacement")
	}
	return b.evidence(a.Binding, "installed"), nil
}
func (b *testBackend) Release(_ context.Context, v Binding) (Evidence, error) {
	b.calls = append(b.calls, "release")
	b.held[v.RunID] = false
	return b.evidence(v, "active"), nil
}
func (b *testBackend) Stop(_ context.Context, v Binding, _ string) (Evidence, error) {
	b.calls = append(b.calls, "stop")
	if !b.stopIncomplete {
		delete(b.domains, v.RunID)
	}
	return b.evidence(v, "stopped"), nil
}
func (b *testBackend) Recover(_ context.Context, r Record) (Evidence, error) {
	b.calls = append(b.calls, "recover")
	return b.evidence(r.Binding, "recovered"), nil
}

func journalFixture(t *testing.T) *SQLiteJournal {
	t.Helper()
	scratch := os.Getenv("AGENTGATE_TEST_SCRATCH")
	if scratch == "" {
		candidate := os.Getenv("TMPDIR")
		if canonicalPrivate(candidate) {
			scratch = candidate
		}
	}
	if scratch == "" {
		t.Skip("set AGENTGATE_TEST_SCRATCH to an owned private directory")
	}
	dir, err := os.MkdirTemp(scratch, "lifecycle-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	journal, err := OpenJournal(filepath.Join(dir, "journal.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { journal.Close() })
	return journal
}

// The fake clock controls job expiry. This budget covers real durable fixture I/O.
const fixtureCleanupTimeout = 10 * time.Second

func managerFixture(t *testing.T) (*Manager, *testBackend, *testVerifier, *testClock, *SQLiteJournal) {
	t.Helper()
	backend := backendFixture()
	verifier := &testVerifier{}
	clock := &testClock{now: 1}
	journal := journalFixture(t)
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	guard := &fixtureGuard{key: key, clock: clock}
	manager, err := NewGuarded(backend, verifier, journal, clock, Identity{"node-one", "boot-one"}, fixtureCleanupTimeout, guard, key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return manager, backend, verifier, clock, journal
}
func installedFixture(t *testing.T, configure ...func(*testBackend)) (*Manager, *testBackend, *testVerifier, *testClock, *SQLiteJournal, Record) {
	t.Helper()
	m, b, v, c, j := managerFixture(t)
	ctx := context.Background()
	if err := m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := m.Prepare(ctx, fixtureBinding())
	if err != nil {
		t.Fatal(err)
	}
	r, err = m.Place(ctx, r.Binding.RunID, HeldProcess{PID: 1234, StartTimeTicks: 900, BarrierID: "barrier-one"})
	if err != nil {
		t.Fatal(err)
	}
	for _, setup := range configure {
		setup(b)
	}
	r, err = m.Install(ctx, r.Binding.RunID, Authorization{Binding: r.Binding, Grant: "test-signed-grant", Document: []byte(`{"default":"deny"}`), RequiredCapabilities: []string{"fs.rules.v1"}})
	if err != nil {
		t.Fatal(err)
	}
	return m, b, v, c, j, r
}
func TestAdmissionRequiresReconciliationAndHeldInstall(t *testing.T) {
	m, b, _, _, _ := managerFixture(t)
	ctx := context.Background()
	if _, err := m.Prepare(ctx, fixtureBinding()); !errors.Is(err, ErrNotReady) {
		t.Fatalf("missing recovery accepted: %v", err)
	}
	if len(b.calls) != 0 {
		t.Fatal("backend ran before recovery")
	}
	if err := m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	r, err := m.Prepare(ctx, fixtureBinding())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.Install(ctx, r.Binding.RunID, Authorization{}); err == nil {
		t.Fatal("install without held PID accepted")
	}
	if _, err = m.Release(ctx, r.Binding.RunID); err == nil {
		t.Fatal("release before installation accepted")
	}
	if strings.Contains(strings.Join(b.calls, ","), "release") {
		t.Fatal("release backend ran")
	}
}
func TestQualifiedLifecycleAndExpiryStopWholeDomain(t *testing.T) {
	m, b, v, c, j, r := installedFixture(t)
	ctx := context.Background()
	active, err := m.Release(ctx, r.Binding.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if active.State != "active" || v.calls != 2 {
		t.Fatal("release skipped authorization verification")
	}
	if _, err = m.Install(ctx, r.Binding.RunID, *r.Authorization); err == nil {
		t.Fatal("running map replacement accepted")
	}
	c.now = r.Binding.DeadlineNS
	if err = m.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	stopped, _ := m.Record(r.Binding.RunID)
	if stopped.State != "stopped" || len(b.domains) != 0 {
		t.Fatal("expiry did not confirm empty domain")
	}
	records, err := j.Load(ctx)
	if err != nil || len(records) != 1 || records[0].State != "stopped" {
		t.Fatal("terminal state is not durable", err)
	}
	if got := strings.Join(b.calls, ","); got != "list,prepare,place,install,release,stop" {
		t.Fatal(got)
	}
}
func TestUnqualifiedCapabilityNeverReleasesWorkload(t *testing.T) {
	m, b, _, _, _, r := installedFixture(t, func(backend *testBackend) { backend.unqualified = true })
	if _, err := m.Release(context.Background(), r.Binding.RunID); err == nil {
		t.Fatal("unqualified required capability released")
	}
	for _, call := range b.calls {
		if call == "release" {
			t.Fatal("backend released an unqualified workload")
		}
	}
	if m.Ready() {
		t.Fatal("failure did not close admission")
	}
}
func TestAuthorityFailureAndWrongReadbackFailClosed(t *testing.T) {
	for _, failure := range []string{"authority", "active"} {
		t.Run(failure, func(t *testing.T) {
			m, b, v, _, _, r := installedFixture(t)
			if failure == "authority" {
				v.err = errors.New("test authority outage")
			} else {
				b.corrupt = failure
			}
			if _, err := m.Release(context.Background(), r.Binding.RunID); err == nil {
				t.Fatal("unsafe release succeeded")
			}
			record, _ := m.Record(r.Binding.RunID)
			if record.State != "stopped" || len(b.domains) != 0 {
				t.Fatal("failed release left live domain")
			}
		})
	}
}
func TestRecoveryVerifiesActiveBindingAndStopsOrphans(t *testing.T) {
	m, b, v, c, j, r := installedFixture(t)
	ctx := context.Background()
	if _, err := m.Release(ctx, r.Binding.RunID); err != nil {
		t.Fatal(err)
	}
	orphan := fixtureBinding()
	orphan.RunID = "orphan-run"
	orphan.GrantID = "orphan-grant"
	orphan.Generation = 2
	orphan.CgroupID = 800
	b.domains[orphan.RunID] = orphan
	recovered, err := NewGuarded(b, v, j, c, Identity{"node-one", "boot-one"}, fixtureCleanupTimeout, m.guard, m.watchdogKey)
	if err != nil {
		t.Fatal(err)
	}
	if err = recovered.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if !recovered.Ready() || len(b.domains) != 1 {
		t.Fatal("orphan reconciliation differs")
	}
	var stops int
	if err = j.db.QueryRow(`SELECT count(*) FROM lifecycle_orphan_stops`).Scan(&stops); err != nil || stops != 1 {
		t.Fatal("orphan evidence missing", err)
	}
	active, _ := recovered.Record(r.Binding.RunID)
	if active.State != "active" || active.Evidence[len(active.Evidence)-1].Phase != "recovered" {
		t.Fatal("pinned generation did not recover")
	}
}
func TestRestartWithChangedBootOrExpiredGrantStops(t *testing.T) {
	for _, failure := range []string{"boot", "expiry", "authority"} {
		t.Run(failure, func(t *testing.T) {
			m, b, v, c, j, r := installedFixture(t)
			ctx := context.Background()
			if _, err := m.Release(ctx, r.Binding.RunID); err != nil {
				t.Fatal(err)
			}
			identity := Identity{"node-one", "boot-one"}
			if failure == "boot" {
				identity.BootID = "boot-two"
			}
			if failure == "expiry" {
				c.now = 1000
			}
			if failure == "authority" {
				v.err = errors.New("test outage")
			}
			recovered, err := New(b, v, j, c, identity, fixtureCleanupTimeout)
			if err != nil {
				t.Fatal(err)
			}
			if err = recovered.Recover(ctx); err != nil {
				t.Fatal(err)
			}
			stopped, _ := recovered.Record(r.Binding.RunID)
			if stopped.State != "stopped" || len(b.domains) != 0 {
				t.Fatal("restart retained unsafe domain")
			}
		})
	}
}
func TestIncompleteTerminationRetainsStopPending(t *testing.T) {
	m, b, _, _, _, r := installedFixture(t)
	b.stopIncomplete = true
	if _, err := m.Stop(context.Background(), r.Binding.RunID, "operator-revoke"); err == nil {
		t.Fatal("nonempty domain reported stopped")
	}
	record, _ := m.Record(r.Binding.RunID)
	if record.State != "stop-pending" || m.Ready() {
		t.Fatal("unsafe stop state")
	}
}
func TestConcurrentRunReplayHasOneReservation(t *testing.T) {
	m, _, _, _, _ := managerFixture(t)
	ctx := context.Background()
	if err := m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	var group sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		group.Add(1)
		go func() { defer group.Done(); _, err := m.Prepare(ctx, fixtureBinding()); results <- err }()
	}
	group.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrReplay) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatal("duplicate reservation", success)
	}
}

func TestLostPreparationReplyExpiresBeforeGrant(t *testing.T) {
	m, b, _, clock, _ := managerFixture(t)
	ctx := context.Background()
	if err := m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	binding := fixtureBinding()
	binding.DeadlineNS = uint64(60 * time.Second)
	record, err := m.PrepareFor(ctx, binding, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if record.PreparationDeadlineNS >= binding.DeadlineNS {
		t.Fatal("preparation lease did not bound the held reservation")
	}
	clock.now = record.PreparationDeadlineNS
	if err = m.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	stopped, _ := m.Record(binding.RunID)
	if stopped.State != "stopped" || len(b.domains) != 0 {
		t.Fatal("lost preparation reply retained the domain")
	}
	if _, err = m.Place(ctx, binding.RunID, HeldProcess{1234, 900, "late-barrier"}); err == nil {
		t.Fatal("late authorization revived an expired preparation")
	}
}
func TestRestartStopsUnfinishedPreparation(t *testing.T) {
	m, b, v, clock, journal := managerFixture(t)
	ctx := context.Background()
	if err := m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	record, err := m.Prepare(ctx, fixtureBinding())
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := New(b, v, journal, clock, Identity{"node-one", "boot-one"}, fixtureCleanupTimeout)
	if err != nil {
		t.Fatal(err)
	}
	if err = restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	stopped, _ := restarted.Record(record.Binding.RunID)
	if stopped.State != "stopped" || len(b.domains) != 0 {
		t.Fatal("restart retained an incomplete preparation")
	}
}

type failedAllocationBackend struct {
	*testBackend
	allocated, wrongBinding bool
}

func (b *failedAllocationBackend) Prepare(ctx context.Context, binding Binding) (Evidence, error) {
	if b.allocated {
		_, _ = b.testBackend.Prepare(ctx, binding)
	}
	return Evidence{}, errors.New("unit allocation failed before reply")
}
func (b *failedAllocationBackend) Stop(ctx context.Context, binding Binding, reason string) (Evidence, error) {
	if b.allocated && binding.CgroupID == 0 {
		if actual, exists := b.domains[binding.RunID]; exists {
			binding = actual
		}
	}
	evidence, err := b.testBackend.Stop(ctx, binding, reason)
	if b.wrongBinding {
		evidence.Binding.GrantID = "wrong-cleanup-grant"
		evidence.Digest = EvidenceDigest(evidence)
	}
	return evidence, err
}
func TestFailedPrepareCleanupResolvesOnlyTheActualCgroup(t *testing.T) {
	for _, allocated := range []bool{false, true} {
		t.Run(fmt.Sprint(allocated), func(t *testing.T) {
			m, backend, _, _, journal := managerFixture(t)
			m.backend = &failedAllocationBackend{testBackend: backend, allocated: allocated}
			if err := m.Recover(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, err := m.Prepare(context.Background(), fixtureBinding()); err == nil {
				t.Fatal("failed allocation reported success")
			}
			record, ok := m.Record("run-one")
			if !ok || record.State != "stopped" {
				t.Fatal("failed allocation cleanup did not persist")
			}
			if allocated && record.Binding.CgroupID == 0 {
				t.Fatal("the actual cleanup binding was lost")
			}
			if !allocated && (record.Binding.CgroupID != 0 || !record.Evidence[len(record.Evidence)-1].NoDomain) {
				t.Fatal("absence proof became a cgroup zero kill")
			}
			stored, err := journal.Lookup(context.Background(), "run-one")
			if err != nil || !stored.Binding.same(record.Binding) {
				t.Fatal("the resolved stop binding is not durable", err)
			}
		})
	}
}
func TestFailedPrepareCannotResolveAnotherGrantDuringCleanup(t *testing.T) {
	m, backend, _, _, _ := managerFixture(t)
	m.backend = &failedAllocationBackend{testBackend: backend, allocated: true, wrongBinding: true}
	if err := m.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Prepare(context.Background(), fixtureBinding()); err == nil {
		t.Fatal("changed cleanup binding passed")
	}
	record, _ := m.Record("run-one")
	if record.State != "stop-pending" || record.Binding.CgroupID != 0 || m.Ready() {
		t.Fatal("a foreign grant supplied stop proof")
	}
}

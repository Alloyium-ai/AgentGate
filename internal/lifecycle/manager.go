// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

type Manager struct {
	fixture     *QualificationFixturePermit
	guard       WatchdogGuard
	watchdogKey ed25519.PublicKey
	backend     Backend
	verifier    Verifier
	journal     Journal
	clock       Clock
	identity    Identity
	stopTimeout time.Duration
	ready       atomic.Bool
	records     sync.Map
	locks       sync.Map
	recovery    sync.Mutex
	operations  sync.RWMutex
}

func New(backend Backend, verifier Verifier, journal Journal, clock Clock, identity Identity, stopTimeout time.Duration) (*Manager, error) {
	if backend == nil || verifier == nil || journal == nil || clock == nil || !identifier.MatchString(identity.NodeID) || !identifier.MatchString(identity.BootID) || stopTimeout <= 0 || stopTimeout > 30*time.Second {
		return nil, errors.New("lifecycle dependencies and bounded cleanup timeout are required")
	}
	return &Manager{backend: backend, verifier: verifier, journal: journal, clock: clock, identity: identity, stopTimeout: stopTimeout}, nil
}

// NewGuarded requires a separate watchdog transport and a pinned custody key.
func NewGuarded(backend Backend, verifier Verifier, journal Journal, clock Clock, identity Identity, stopTimeout time.Duration, guard WatchdogGuard, key ed25519.PublicKey) (*Manager, error) {
	if guard == nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("an independent watchdog and pinned key are required")
	}
	manager, err := New(backend, verifier, journal, clock, identity, stopTimeout)
	if err != nil {
		return nil, err
	}
	manager.guard = guard
	manager.watchdogKey = append(ed25519.PublicKey{}, key...)
	return manager, nil
}
func (m *Manager) watchdogFresh(ctx context.Context, r Record) error {
	now, err := m.clock.NowNS()
	if m.guard == nil || r.Watchdog == nil || err != nil || VerifyWatchdogAck(*r.Watchdog, r.Binding, m.watchdogKey, now) != nil || m.guard.Check(ctx, clone(*r.Watchdog)) != nil {
		return errors.New("independent watchdog custody is unavailable")
	}
	return nil
}
func (m *Manager) Ready() bool { return m.ready.Load() }
func (m *Manager) lock(id string) func() {
	value, _ := m.locks.LoadOrStore(id, &sync.Mutex{})
	lock := value.(*sync.Mutex)
	lock.Lock()
	return lock.Unlock
}
func (m *Manager) Record(runID string) (Record, bool) {
	if value, ok := m.records.Load(runID); ok {
		return clone(value.(Record)), true
	}
	ctx, cancel := context.WithTimeout(context.Background(), m.stopTimeout)
	defer cancel()
	record, err := m.journal.Lookup(ctx, runID)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			m.ready.Store(false)
		}
		return Record{}, false
	}
	return clone(record), true
}

func (m *Manager) persist(ctx context.Context, r *Record, state string, evidence *Evidence) error {
	next := clone(*r)
	next.State = state
	next.Revision++
	if evidence != nil {
		next.Evidence = append(next.Evidence, clone(*evidence))
	}
	if err := m.journal.Save(ctx, next, r.Revision); err != nil {
		if !errors.Is(err, ErrReplay) {
			m.ready.Store(false)
		}
		return err
	}
	*r = next
	if state == "stopped" {
		m.records.Delete(r.Binding.RunID)
	} else {
		m.records.Store(r.Binding.RunID, clone(next))
	}
	return nil
}
func (m *Manager) fresh(b Binding) error {
	if b.NodeID != m.identity.NodeID || b.BootID != m.identity.BootID {
		return errors.New("lifecycle node or boot differs")
	}
	now, err := m.clock.NowNS()
	if err != nil || now >= b.DeadlineNS {
		return errors.New("lifecycle deadline is expired or unavailable")
	}
	return nil
}
func (m *Manager) heldFresh(r Record) error {
	if err := m.fresh(r.Binding); err != nil {
		return err
	}
	now, err := m.clock.NowNS()
	if err != nil || r.PreparationDeadlineNS == 0 || now >= r.PreparationDeadlineNS {
		return errors.New("the preparation lease expired")
	}
	return nil
}

func (m *Manager) Prepare(ctx context.Context, binding Binding) (Record, error) {
	return m.PrepareFor(ctx, binding, m.stopTimeout)
}

// PrepareFor bounds a deny quarantine independently of the eventual grant lifetime.
func (m *Manager) PrepareFor(ctx context.Context, binding Binding, lease time.Duration) (Record, error) {
	m.operations.RLock()
	defer m.operations.RUnlock()
	b := clone(binding)
	if lease <= 0 || lease > 30*time.Second {
		return Record{}, errors.New("the preparation lease must be positive and at most thirty seconds")
	}
	if !m.Ready() {
		return Record{}, ErrNotReady
	}
	if err := b.validate(true); err != nil {
		return Record{}, err
	}
	if b.CgroupID != 0 {
		return Record{}, errors.New("lifecycle Prepare requires an unallocated domain")
	}
	if err := m.fresh(b); err != nil {
		return Record{}, err
	}
	defer m.lock(b.AgentID)()
	if !m.Ready() {
		return Record{}, ErrNotReady
	}
	if _, ok := m.Record(b.RunID); ok {
		return Record{}, ErrReplay
	}
	now, clockErr := m.clock.NowNS()
	if clockErr != nil {
		return Record{}, errors.New("the preparation clock is unavailable")
	}
	deadline := b.DeadlineNS
	if uint64(lease) <= ^uint64(0)-now && now+uint64(lease) < deadline {
		deadline = now + uint64(lease)
	}
	r := Record{Binding: b, PreparationDeadlineNS: deadline, Evidence: []Evidence{}}
	if err := m.persist(ctx, &r, "preparing", nil); err != nil {
		return Record{}, err
	}
	if m.guard != nil && m.guard.Reserve(ctx, clone(b), deadline) != nil {
		return r, m.abort(&r, "watchdog-reservation-failed")
	}
	e, err := m.backend.Prepare(ctx, b)
	if err != nil {
		return r, m.abort(&r, "prepare-failed")
	}
	expected := b
	expected.CgroupID = e.Binding.CgroupID
	if expected.CgroupID == 0 || !expected.same(e.Binding) || m.checkEvidence(e, expected, "quarantined") != nil || !e.Empty {
		return r, m.abort(&r, "prepare-proof-failed")
	}
	r.Binding = expected
	if m.guard != nil {
		ack, guardErr := m.guard.Arm(ctx, clone(expected))
		now, clockErr := m.clock.NowNS()
		if guardErr != nil || clockErr != nil || VerifyWatchdogAck(ack, expected, m.watchdogKey, now) != nil {
			return r, m.abort(&r, "watchdog-custody-failed")
		}
		r.Watchdog = &ack
	}
	if err = m.heldFresh(r); err != nil {
		return r, m.abort(&r, "prepare-lease-expired")
	}
	if err = m.persist(ctx, &r, "quarantined", &e); err != nil {
		return r, m.abort(&r, "prepare-journal-failed")
	}
	return clone(r), nil
}
func (m *Manager) current(runID string, states ...string) (Record, error) {
	if !m.Ready() {
		return Record{}, ErrNotReady
	}
	r, ok := m.Record(runID)
	if !ok {
		return r, errors.New("lifecycle run is unknown")
	}
	for _, state := range states {
		if r.State == state {
			return r, nil
		}
	}
	return r, errors.New("lifecycle transition is not permitted")
}
func (m *Manager) Place(ctx context.Context, runID string, process HeldProcess) (Record, error) {
	m.operations.RLock()
	defer m.operations.RUnlock()
	initial, ok := m.Record(runID)
	if !ok {
		return Record{}, errors.New("lifecycle run is unknown")
	}
	defer m.lock(initial.Binding.AgentID)()
	r, err := m.current(runID, "quarantined")
	if err != nil {
		return r, err
	}
	if process.PID <= 1 || process.StartTimeTicks == 0 || !identifier.MatchString(process.BarrierID) {
		return r, errors.New("lifecycle requires a held process identity")
	}
	if err = m.heldFresh(r); err != nil {
		return r, m.abort(&r, "place-expired")
	}
	r.Process = &process
	if err = m.persist(ctx, &r, "placing", nil); err != nil {
		return r, err
	}
	e, err := m.backend.Place(ctx, r.Binding, process)
	if err != nil || m.checkEvidence(e, r.Binding, "placed") != nil || !reflect.DeepEqual(e.Process, &process) {
		return r, m.abort(&r, "place-proof-failed")
	}
	if err = m.persist(ctx, &r, "placed", &e); err != nil {
		return r, m.abort(&r, "place-journal-failed")
	}
	return clone(r), nil
}
func (m *Manager) Install(ctx context.Context, runID string, authorization Authorization) (Record, error) {
	m.operations.RLock()
	defer m.operations.RUnlock()
	initial, ok := m.Record(runID)
	if !ok {
		return Record{}, errors.New("lifecycle run is unknown")
	}
	defer m.lock(initial.Binding.AgentID)()
	r, err := m.current(runID, "placed")
	if err != nil {
		return r, err
	}
	a := clone(authorization)
	if !r.Binding.same(a.Binding) || len(a.Grant) == 0 || len(a.Grant) > 32768 || len(a.Document) == 0 || len(a.Document) > 1<<20 {
		return r, m.abort(&r, "authorization-binding-failed")
	}
	if err = m.heldFresh(r); err != nil {
		return r, m.abort(&r, "install-expired")
	}
	if err = m.verifier.Verify(ctx, a); err != nil {
		return r, m.abort(&r, "authorization-unverified")
	}
	r.Authorization = &a
	if err = m.persist(ctx, &r, "installing", nil); err != nil {
		return r, err
	}
	e, err := m.backend.Install(ctx, a)
	if err != nil || m.checkEvidence(e, r.Binding, "installed") != nil || !reflect.DeepEqual(e.Process, r.Process) {
		return r, m.abort(&r, "install-proof-failed")
	}
	if err = m.persist(ctx, &r, "installed", &e); err != nil {
		return r, m.abort(&r, "install-journal-failed")
	}
	return clone(r), nil
}
func (m *Manager) Release(ctx context.Context, runID string) (Record, error) {
	m.operations.RLock()
	defer m.operations.RUnlock()
	initial, ok := m.Record(runID)
	if !ok {
		return Record{}, errors.New("lifecycle run is unknown")
	}
	defer m.lock(initial.Binding.AgentID)()
	r, err := m.current(runID, "installed")
	if err != nil {
		return r, err
	}
	if r.Authorization == nil || len(r.Evidence) == 0 || m.checkCapabilities(r.Evidence[len(r.Evidence)-1], r.Authorization.RequiredCapabilities) != nil {
		return r, m.abort(&r, "capability-unqualified")
	}
	cutoff := r.Evidence[len(r.Evidence)-1].EffectiveDeadlineNS
	if cutoff == 0 || cutoff > r.Binding.DeadlineNS {
		return r, m.abort(&r, "release-effective-deadline-unavailable")
	}
	if err = m.heldFresh(r); err != nil {
		return r, m.abort(&r, "release-expired")
	}
	if err = m.verifier.Verify(ctx, *r.Authorization); err != nil {
		return r, m.abort(&r, "release-unverified")
	}
	if err = m.heldFresh(r); err != nil {
		return r, m.abort(&r, "release-preparation-expired")
	}
	if err = m.watchdogFresh(ctx, r); err != nil {
		return r, m.abort(&r, "watchdog-custody-unavailable")
	}
	if err = m.persist(ctx, &r, "release-pending", nil); err != nil {
		return r, err
	}
	if !m.Ready() {
		return r, m.abort(&r, "release-reconciliation-required")
	}
	if err = m.heldFresh(r); err != nil {
		return r, m.abort(&r, "release-preparation-expired")
	}
	if err = m.watchdogFresh(ctx, r); err != nil {
		return r, m.abort(&r, "watchdog-custody-unavailable")
	}
	now, clockErr := m.clock.NowNS()
	if clockErr != nil {
		return r, m.abort(&r, "release-clock-unavailable")
	}
	if now >= cutoff {
		return r, m.abort(&r, "grant-expired")
	}
	if r.Watchdog == nil || m.guard.Activate(ctx, *r.Watchdog, cutoff) != nil {
		return r, m.abort(&r, "watchdog-activation-failed")
	}
	if err = m.watchdogFresh(ctx, r); err != nil {
		return r, m.abort(&r, "watchdog-activation-unconfirmed")
	}
	e, err := m.backend.Release(ctx, r.Binding)
	if err != nil || m.checkEvidence(e, r.Binding, "active") != nil || e.EffectiveDeadlineNS != cutoff || !reflect.DeepEqual(e.Process, r.Process) || m.checkCapabilities(e, r.Authorization.RequiredCapabilities) != nil {
		return r, m.abort(&r, "release-proof-failed")
	}
	if err = m.persist(ctx, &r, "active", &e); err != nil {
		return r, m.abort(&r, "release-journal-failed")
	}
	return clone(r), nil
}
func (m *Manager) stop(ctx context.Context, r *Record, reason string) error {
	if r.State == "stopped" {
		return nil
	}
	if r.StopReason == "" {
		r.StopReason = reason
	}
	if !identifier.MatchString(r.StopReason) {
		m.ready.Store(false)
		r.StopReason = "termination-retry"
	}
	reason = r.StopReason
	if m.guard != nil {
		m.guard.Forget(clone(r.Binding))
	}
	if err := m.persist(ctx, r, "stop-pending", nil); err != nil {
		_, _ = m.backend.Stop(ctx, r.Binding, reason)
		return errors.New("lifecycle stop intent is not durable")
	}
	e, err := m.backend.Stop(ctx, r.Binding, reason)
	expected := clone(r.Binding)
	if expected.CgroupID == 0 && e.Binding.CgroupID != 0 && r.Authorization == nil && r.Process == nil {
		expected.CgroupID = e.Binding.CgroupID
	}
	if err != nil || m.checkEvidence(e, expected, "stopped") != nil || !expected.same(e.Binding) {
		m.ready.Store(false)
		return errors.New("lifecycle whole-domain termination is unconfirmed")
	}
	r.Binding = expected
	return m.persist(ctx, r, "stopped", &e)
}
func (m *Manager) abort(r *Record, code string) error {
	m.ready.Store(false)
	r.LastError = code
	ctx, cancel := context.WithTimeout(context.Background(), m.stopTimeout)
	defer cancel()
	if err := m.stop(ctx, r, code); err != nil {
		return fmt.Errorf("lifecycle %s: cleanup is unconfirmed", code)
	}
	return fmt.Errorf("lifecycle %s: the domain stopped", code)
}
func (m *Manager) Stop(ctx context.Context, runID, reason string) (Record, error) {
	m.operations.RLock()
	defer m.operations.RUnlock()
	r, ok := m.Record(runID)
	if !ok {
		return r, errors.New("lifecycle run is unknown")
	}
	if !identifier.MatchString(reason) {
		return r, errors.New("lifecycle stop reason must be a bounded code")
	}
	defer m.lock(r.Binding.AgentID)()
	r, _ = m.Record(runID)
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), m.stopTimeout)
	defer cancel()
	if err := m.stop(cleanup, &r, reason); err != nil {
		return r, err
	}
	return clone(r), nil
}

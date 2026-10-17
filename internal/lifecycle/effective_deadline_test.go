// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestWatchdogPersistsEarlierCutoffAndStopsWithoutHeartbeatExtension(t *testing.T) {
	f := watcher(t)
	ack := f.arm(t)
	ctx := context.Background()
	cutoff := uint64(1500 * time.Millisecond)
	if err := f.core.Activate(ctx, ack, f.daemon, cutoff); err != nil {
		t.Fatal(err)
	}
	f.clock.now = uint64(750 * time.Millisecond)
	if err := f.core.Heartbeat(ctx, ack, f.daemon); err != nil {
		t.Fatal(err)
	}
	leases, err := f.store.LoadWatchdog(ctx)
	if err != nil || len(leases) != 1 || leases[0].EffectiveDeadlineNS != cutoff || leases[0].HeartbeatDeadlineNS != cutoff || !leases[0].Ack.Binding.same(f.binding) {
		t.Fatal("the durable cutoff or immutable binding differs", err)
	}
	changed := leases[0]
	changed.Revision++
	changed.EffectiveDeadlineNS++
	if f.store.SaveWatchdog(ctx, changed, leases[0].Revision) == nil {
		t.Fatal("the active cutoff changed")
	}
	f.clock.now = cutoff
	if f.core.Check(ctx, ack, f.daemon) == nil || f.core.Heartbeat(ctx, ack, f.daemon) == nil {
		t.Fatal("the expired cutoff renewed")
	}
	if err = f.core.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.stopper.stops) != 1 || f.stopper.stops[0].Reason != "watchdog-grant-expired" || !f.stopper.stops[0].Binding.same(f.binding) {
		t.Fatal("the earlier cutoff did not stop the exact domain")
	}
	history, err := f.store.WatchdogHistory(ctx)
	if err != nil || len(history) != 1 || history[0].State != "stopped" || history[0].EffectiveDeadlineNS != cutoff {
		t.Fatal("the cutoff retirement is not durable", err)
	}
}

type deadlineStopStore struct {
	WatchdogStore
	expired bool
}

func (s *deadlineStopStore) SaveWatchdogStop(ctx context.Context, e WatchdogStopEvidence) error {
	<-ctx.Done()
	s.expired = true
	return ctx.Err()
}

func TestWatchdogExpiredPersistenceBudgetClosesReadinessAndAllowsRetry(t *testing.T) {
	f := watcher(t)
	f.arm(t)
	store := &deadlineStopStore{WatchdogStore: f.store}
	f.core.store = store
	f.core.config.StopTimeout = time.Millisecond
	if f.core.stop(context.Background(), f.binding, "watchdog-grant-expired") == nil || !store.expired || f.core.ready {
		t.Fatal("a missed durable stop kept readiness")
	}
	leases, err := f.store.LoadWatchdog(context.Background())
	if err != nil || len(leases) != 1 || leases[0].State != "armed" {
		t.Fatal("the failed durable stop lost its retry record", err)
	}
	f.core.store = f.store
	f.core.config.StopTimeout = 10 * time.Second
	f.clock.now = uint64(10 * time.Second)
	if err = f.core.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	history, err := f.store.WatchdogHistory(context.Background())
	if err != nil || len(history) != 1 || history[0].State != "stopped" {
		t.Fatal("the retried stop is not durable", err)
	}
}
func TestWatchdogActivationRejectsMissingPastAndWidenedCutoffs(t *testing.T) {
	for _, name := range []string{"missing", "past", "widened"} {
		t.Run(name, func(t *testing.T) {
			f := watcher(t)
			ack := f.arm(t)
			cutoff := uint64(0)
			if name == "past" {
				cutoff = f.clock.now
			}
			if name == "widened" {
				cutoff = f.binding.DeadlineNS + 1
			}
			if f.core.Activate(context.Background(), ack, f.daemon, cutoff) == nil {
				t.Fatal("the invalid cutoff activated")
			}
			leases, err := f.store.LoadWatchdog(context.Background())
			if err != nil || len(leases) != 1 || leases[0].State != "armed" || leases[0].EffectiveDeadlineNS != 0 {
				t.Fatal("the rejected activation changed custody", err)
			}
		})
	}
}
func TestOldActiveLeaseWithoutCutoffOnlyPermitsStop(t *testing.T) {
	f := watcher(t)
	ack := f.arm(t)
	ctx := context.Background()
	leases, err := f.store.LoadWatchdog(ctx)
	if err != nil {
		t.Fatal(err)
	}
	old := leases[0]
	old.State = "active"
	old.Revision++
	// Write the historical wire shape directly. New SaveWatchdog must reject it.
	if f.store.SaveWatchdog(ctx, old, leases[0].Revision) == nil {
		t.Fatal("a new unbounded execution lease passed")
	}
	raw, _ := json.Marshal(old)
	if _, err = f.store.db.ExecContext(ctx, `UPDATE watchdog_leases SET state=?,revision=?,record=? WHERE run_id=?`, old.State, old.Revision, string(raw), old.Ack.Binding.RunID); err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.LoadWatchdog(ctx); err != nil {
		t.Fatal("the historical lease cannot be retired", err)
	}
	if f.core.Check(ctx, ack, f.daemon) == nil || f.core.Heartbeat(ctx, ack, f.daemon) == nil {
		t.Fatal("an old unbounded lease renewed")
	}
	if err = f.core.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.stopper.stops) != 1 || f.stopper.stops[0].Reason != "watchdog-effective-deadline-missing" || f.core.ready {
		t.Fatal("the unbounded historical lease did not close admission")
	}
}
func TestManagerUsesInstalledCutoffForActivationAndSweep(t *testing.T) {
	m, b, _, c, j, r := installedFixture(t)
	ctx := context.Background()
	cutoff := b.effectiveDeadline
	if _, err := m.Release(ctx, r.Binding.RunID); err != nil {
		t.Fatal(err)
	}
	if m.guard.(*fixtureGuard).effectiveDeadline != cutoff {
		t.Fatal("the manager inferred the binding deadline")
	}
	actual := &reasonBackend{testBackend: b}
	m.backend = actual
	c.now = cutoff
	if err := m.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	stopped, err := j.Lookup(ctx, r.Binding.RunID)
	if err != nil || stopped.State != "stopped" || len(actual.reasons) != 1 || actual.reasons[0] != "grant-expired" || !stopped.Binding.same(r.Binding) || c.now >= r.Binding.DeadlineNS {
		t.Fatal("the manager missed the earlier cutoff", err)
	}
}
func TestManagerRejectsMissingOrChangedInstalledCutoff(t *testing.T) {
	for _, name := range []string{"missing", "widened", "expired", "changed-after-activation"} {
		t.Run(name, func(t *testing.T) {
			m, b, _, c, _, r := installedFixture(t)
			if name == "changed-after-activation" {
				b.effectiveDeadline--
				if _, err := m.Release(context.Background(), r.Binding.RunID); err == nil {
					t.Fatal("an active cutoff substitution passed")
				}
				return
			}
			if name == "expired" {
				c.now = b.effectiveDeadline
			} else {
				stored, _ := m.Record(r.Binding.RunID)
				e := &stored.Evidence[len(stored.Evidence)-1]
				e.EffectiveDeadlineNS = 0
				if name == "widened" {
					e.EffectiveDeadlineNS = r.Binding.DeadlineNS + 1
				}
				e.Digest = EvidenceDigest(*e)
				m.records.Store(r.Binding.RunID, stored)
			}
			if _, err := m.Release(context.Background(), r.Binding.RunID); err == nil {
				t.Fatal("the invalid cutoff released")
			}
			for _, call := range b.calls {
				if call == "release" {
					t.Fatal("the backend released before a valid cutoff")
				}
			}
		})
	}
}
func TestZeroEffectiveDeadlinePreservesHistoricalEvidenceEncoding(t *testing.T) {
	b := backendFixture()
	binding := fixtureBinding()
	e := b.evidence(binding, "stopped")
	raw, err := json.Marshal(e)
	if err != nil || bytes.Contains(raw, []byte("effective_deadline_ns")) || checkEvidence(e, binding, "stopped") != nil {
		t.Fatal("historical stopped evidence changed", err)
	}
	e = b.evidence(binding, "installed")
	e.EffectiveDeadlineNS = 0
	e.Digest = EvidenceDigest(e)
	if checkEvidence(e, binding, "installed") == nil {
		t.Fatal("an installed zero cutoff passed")
	}
}

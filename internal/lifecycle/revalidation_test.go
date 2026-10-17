// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

type typedStopError StopCause

func (e typedStopError) Error() string                  { return string(e) }
func (e typedStopError) LifecycleStopReason() StopCause { return StopCause(e) }

type reasonBackend struct {
	*testBackend
	reasons        []string
	stopContextErr error
}

func (b *reasonBackend) Stop(ctx context.Context, binding Binding, reason string) (Evidence, error) {
	b.reasons = append(b.reasons, reason)
	b.stopContextErr = ctx.Err()
	return b.testBackend.Stop(ctx, binding, reason)
}
func TestActiveVerificationFailureStopsBeforeTheJobDeadline(t *testing.T) {
	for _, state := range []string{"revoked", "unknown-revocation", "enrollment-lost", "qualification-expired", "qualification-outage", "watchdog-outage"} {
		t.Run(state, func(t *testing.T) {
			m, b, v, c, j, r := installedFixture(t)
			ctx := context.Background()
			if _, err := m.Release(ctx, r.Binding.RunID); err != nil {
				t.Fatal(err)
			}
			actual := &reasonBackend{testBackend: b}
			m.backend = actual
			if state == "watchdog-outage" {
				m.guard.(*fixtureGuard).err = errors.New("unit independent watchdog unavailable")
			} else {
				v.err = errors.New(state)
			}
			if c.now >= r.Binding.DeadlineNS {
				t.Fatal("fixture already expired")
			}
			if err := m.Sweep(ctx); err != nil {
				t.Fatal(err)
			}
			stopped, err := j.Lookup(ctx, r.Binding.RunID)
			if err != nil || stopped.State != "stopped" || len(b.domains) != 0 || m.Ready() {
				t.Fatal("unverified active domain survived", err)
			}
			want := "active-authorization-unverified"
			if state == "watchdog-outage" {
				want = "active-watchdog-unavailable"
			}
			if len(actual.reasons) != 1 || actual.reasons[0] != want || !stopped.Binding.same(r.Binding) {
				t.Fatal("active stop lost its exact reason or binding", actual.reasons)
			}
			evidence := stopped.Evidence[len(stopped.Evidence)-1]
			if !evidence.Terminated || !evidence.Empty || !evidence.RightsRemoved {
				t.Fatal("active stop lacks complete cleanup")
			}
		})
	}
}
func TestValidActiveAuthorizationContinuesAndIsRechecked(t *testing.T) {
	m, b, v, c, _, r := installedFixture(t)
	ctx := context.Background()
	if _, err := m.Release(ctx, r.Binding.RunID); err != nil {
		t.Fatal(err)
	}
	before := v.calls
	for i := 0; i < 2; i++ {
		if err := m.Sweep(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if v.calls != before+2 || len(b.domains) != 1 || !m.Ready() || c.now >= r.Binding.DeadlineNS {
		t.Fatal("valid active custody did not continue")
	}
}

func TestVerifiedGrantStopCauseReachesWholeDomainTermination(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{"expired", typedStopError(GrantExpired), "grant-expired"},
		{"revoked", typedStopError(GrantRevoked), "revoked"},
		{"wrapped-revoked", fmt.Errorf("authority: %w", typedStopError(GrantRevoked)), "revoked"},
		{"unknown-cause", typedStopError("completed"), "active-authorization-unverified"},
		{"untyped-revoked", errors.New("revoked"), "active-authorization-unverified"},
	} {
		t.Run(test.name, func(t *testing.T) {
			m, b, v, c, journal, r := installedFixture(t)
			ctx := context.Background()
			if _, err := m.Release(ctx, r.Binding.RunID); err != nil {
				t.Fatal(err)
			}
			actual := &reasonBackend{testBackend: b}
			m.backend = actual
			v.err = test.err
			if err := m.Sweep(ctx); err != nil {
				t.Fatal(err)
			}
			stopped, err := journal.Lookup(ctx, r.Binding.RunID)
			if err != nil || stopped.State != "stopped" || !stopped.Binding.same(r.Binding) || len(b.domains) != 0 || m.Ready() || c.now >= r.Binding.DeadlineNS {
				t.Fatal("the verified cause failed to terminate the exact active domain", err)
			}
			if len(actual.reasons) != 1 || actual.reasons[0] != test.want || actual.stopContextErr != nil {
				t.Fatal("whole-domain termination lost its bounded cause", actual.reasons, actual.stopContextErr)
			}
		})
	}
}

type blockedVerifier struct {
	release  chan struct{}
	returned chan struct{}
	once     sync.Once
}

func (v *blockedVerifier) Verify(context.Context, Authorization) error {
	<-v.release
	v.once.Do(func() { close(v.returned) })
	return nil
}

type delayedStopJournal struct {
	Journal
	delay     time.Duration
	stopError error
}

func (j delayedStopJournal) Save(ctx context.Context, r Record, revision uint64) error {
	if r.State == "stopped" {
		if j.stopError != nil {
			return j.stopError
		}
		timer := time.NewTimer(j.delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	return j.Journal.Save(ctx, r, revision)
}
func TestBlockedActiveVerifierCannotPreventDomainTermination(t *testing.T) {
	m, b, _, c, journal, r := installedFixture(t)
	ctx := context.Background()
	if _, err := m.Release(ctx, r.Binding.RunID); err != nil {
		t.Fatal(err)
	}
	v := &blockedVerifier{release: make(chan struct{}), returned: make(chan struct{})}
	m.verifier = v
	// Bound verification through the caller. Keep the independent cleanup budget.
	// The delayed journal makes a reused 50ms cleanup deadline fail deterministically.
	m.journal = delayedStopJournal{Journal: journal, delay: 75 * time.Millisecond}
	check, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	defer func() {
		close(v.release)
		select {
		case <-v.returned:
		case <-time.After(time.Second):
			t.Error("the test verifier did not exit")
		}
	}()
	actual := &reasonBackend{testBackend: b}
	m.backend = actual
	done := make(chan error, 1)
	go func() { done <- m.Sweep(check) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the verifier blocked fail-closed termination")
	}
	if len(b.domains) != 0 || m.Ready() || c.now >= r.Binding.DeadlineNS || len(actual.reasons) != 1 || actual.reasons[0] != "active-verification-timeout" {
		t.Fatal("a blocked verifier retained the domain")
	}
	if !errors.Is(check.Err(), context.DeadlineExceeded) || actual.stopContextErr != nil {
		t.Fatal("termination reused the expired verification context", actual.stopContextErr)
	}
	stopped, err := journal.Lookup(ctx, r.Binding.RunID)
	if err != nil || stopped.State != "stopped" || !stopped.Binding.same(r.Binding) {
		t.Fatal("the independent stop lost durable exact custody", err)
	}
}
func TestTerminationJournalDeadlineRetainsStopForRetry(t *testing.T) {
	m, b, _, _, journal, r := installedFixture(t)
	ctx := context.Background()
	if _, err := m.Release(ctx, r.Binding.RunID); err != nil {
		t.Fatal(err)
	}
	m.journal = delayedStopJournal{Journal: journal, stopError: context.DeadlineExceeded}
	if _, err := m.Stop(ctx, r.Binding.RunID, "test-stop"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("the stopped checkpoint must preserve its deadline failure", err)
	}
	pending, err := journal.Lookup(ctx, r.Binding.RunID)
	if err != nil || pending.State != "stop-pending" || len(b.domains) != 0 || m.Ready() {
		t.Fatal("incomplete durable stop lost physical custody or allowed admission", err)
	}
	m.journal = journal
	if _, err = m.Stop(ctx, r.Binding.RunID, "termination-retry"); err != nil {
		t.Fatal(err)
	}
	stopped, err := journal.Lookup(ctx, r.Binding.RunID)
	if err != nil || stopped.State != "stopped" || !stopped.Binding.same(r.Binding) {
		t.Fatal("the stop retry lost its exact durable binding", err)
	}
}
func TestActiveRevalidationRetainsUnconfirmedStopForRetry(t *testing.T) {
	m, b, v, _, _, r := installedFixture(t)
	ctx := context.Background()
	if _, err := m.Release(ctx, r.Binding.RunID); err != nil {
		t.Fatal(err)
	}
	v.err = errors.New("unknown revocation state")
	b.stopIncomplete = true
	if m.Sweep(ctx) == nil {
		t.Fatal("an incomplete active stop passed")
	}
	record, _ := m.Record(r.Binding.RunID)
	if record.State != "stop-pending" || m.Ready() {
		t.Fatal("unconfirmed stop lost custody")
	}
	b.stopIncomplete = false
	if err := m.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	record, _ = m.Record(r.Binding.RunID)
	if record.State != "stopped" || len(b.domains) != 0 {
		t.Fatal("unconfirmed active termination did not retry")
	}
}

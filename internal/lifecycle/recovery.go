// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"time"
)

func domainKey(b Binding) string { return fmt.Sprintf("%s/%s/%d", b.NodeID, b.BootID, b.CgroupID) }

// Recover reconciles every owned kernel domain before it admits new work.
// Missing journal entries never authorize an existing domain.
func (m *Manager) Recover(ctx context.Context) error {
	m.ready.Store(false)
	m.recovery.Lock()
	defer m.recovery.Unlock()
	m.operations.Lock()
	defer m.operations.Unlock()
	domains, err := m.backend.ListDomains(ctx)
	if err != nil {
		return errors.New("lifecycle owned-domain inventory is unavailable")
	}
	records, loadErr := m.journal.Load(ctx)
	m.records.Range(func(key, value any) bool { m.records.Delete(key); return true })
	known := map[string]Record{}
	liveDomains := map[string]Binding{}
	for _, r := range records {
		known[domainKey(r.Binding)] = r
		if r.State != "stopped" {
			m.records.Store(r.Binding.RunID, clone(r))
		}
	}
	failures := []error{}
	for _, b := range domains {
		if err = b.validate(false); err != nil {
			failures = append(failures, errors.New("lifecycle owned-domain inventory contains an invalid binding"))
			continue
		}
		liveDomains[domainKey(b)] = b
		r, ok := known[domainKey(b)]
		if !ok || !r.Binding.same(b) || r.State == "stopped" || loadErr != nil {
			if err = m.stopOrphan(ctx, b); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if loadErr != nil {
		return errors.New("lifecycle journal recovery failed; owned domains were quarantined or stopped")
	}
	for _, r := range records {
		if r.State == "stopped" {
			continue
		}
		current, exists := liveDomains[domainKey(r.Binding)]
		live := exists && current.same(r.Binding)
		if r.State == "active" && live && m.fresh(r.Binding) == nil && r.Authorization != nil && m.verifier.Verify(ctx, *r.Authorization) == nil && m.watchdogFresh(ctx, r) == nil {
			e, recoverErr := m.backend.Recover(ctx, clone(r))
			if recoverErr == nil && m.checkEvidence(e, r.Binding, "recovered") == nil && m.checkCapabilities(e, r.Authorization.RequiredCapabilities) == nil && reflect.DeepEqual(e.Process, r.Process) {
				if err = m.persist(ctx, &r, "active", &e); err != nil {
					failures = append(failures, m.abort(&r, "recovery-journal-failed"))
				}
				continue
			}
		}
		if err = m.stop(ctx, &r, "recovery-fail-closed"); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	m.ready.Store(true)
	return nil
}
func (m *Manager) stopOrphan(ctx context.Context, b Binding) error {
	e, err := m.backend.Stop(ctx, b, "orphan-recovery")
	if err != nil || m.checkEvidence(e, b, "stopped") != nil {
		return errors.New("lifecycle orphan domain termination is unconfirmed")
	}
	if err = m.journal.SaveOrphan(ctx, e); err != nil {
		return errors.New("lifecycle orphan stop evidence is not durable")
	}
	return nil
}

func (m *Manager) Sweep(ctx context.Context) error {
	m.recovery.Lock()
	defer m.recovery.Unlock()
	now, clockErr := m.clock.NowNS()
	failures := []error{}
	m.records.Range(func(_, value any) bool {
		r := value.(Record)
		if r.State == "stopped" {
			return true
		}
		heldExpired := r.State != "active" && r.PreparationDeadlineNS > 0 && now >= r.PreparationDeadlineNS
		reason := ""
		var effectiveDeadline uint64
		for _, e := range r.Evidence {
			if e.Phase == "installed" || e.Phase == "active" {
				effectiveDeadline = e.EffectiveDeadlineNS
			}
		}
		switch {
		case clockErr != nil:
			reason = "monotonic-clock-unavailable"
			m.ready.Store(false)
		case now >= r.Binding.DeadlineNS:
			reason = "grant-expired"
		case r.State == "active" && (effectiveDeadline == 0 || effectiveDeadline > r.Binding.DeadlineNS):
			reason = "active-effective-deadline-unavailable"
			m.ready.Store(false)
		case r.State == "active" && now >= effectiveDeadline:
			reason = "grant-expired"
		case heldExpired:
			reason = "preparation-lease-expired"
		case r.State == "stop-pending":
			reason = "termination-retry"
		case r.State == "active":
			reason = m.activeVerification(ctx, clone(r))
			if reason != "" {
				m.ready.Store(false)
			}
		}
		if reason != "" {
			if _, err := m.Stop(ctx, r.Binding.RunID, reason); err != nil {
				failures = append(failures, err)
			}
		}
		return true
	})
	return errors.Join(failures...)
}

func (m *Manager) Shutdown(ctx context.Context) error {
	m.ready.Store(false)
	failures := []error{}
	m.records.Range(func(_, value any) bool {
		r := value.(Record)
		if _, err := m.Stop(ctx, r.Binding.RunID, "manager-shutdown"); err != nil {
			failures = append(failures, err)
		}
		return true
	})
	return errors.Join(failures...)
}

// Watch is a local cleanup timer. It supplies no independent watchdog custody.
func (m *Manager) Watch(ctx context.Context, interval time.Duration) error {
	if interval <= 0 || interval > time.Second {
		return errors.New("lifecycle watchdog interval must be positive and at most one second")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			cleanup, cancel := context.WithTimeout(context.Background(), m.stopTimeout)
			defer cancel()
			return m.Shutdown(cleanup)
		case <-ticker.C:
			if err := m.Sweep(ctx); err != nil {
				return err
			}
		}
	}
}

// Bound each active check even if a dependency fails to honor cancellation.
// A timed-out check cannot release a domain or renew independent custody.
func (m *Manager) activeVerification(ctx context.Context, r Record) string {
	if r.Authorization == nil {
		return "active-authorization-missing"
	}
	timeout := m.stopTimeout
	if timeout > time.Second {
		timeout = time.Second
	}
	check, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result := make(chan string, 1)
	go func() {
		if err := m.verifier.Verify(check, *r.Authorization); err != nil {
			result <- authorizationStopReason(err)
			return
		}
		if m.watchdogFresh(check, r) != nil {
			result <- "active-watchdog-unavailable"
			return
		}
		result <- ""
	}()
	select {
	case reason := <-result:
		return reason
	case <-check.Done():
		return "active-verification-timeout"
	}
}

func authorizationStopReason(err error) string {
	var reason LifecycleStopReason
	if errors.As(err, &reason) {
		switch cause := reason.LifecycleStopReason(); cause {
		case GrantExpired, GrantRevoked:
			return string(cause)
		}
	}
	return "active-authorization-unverified"
}

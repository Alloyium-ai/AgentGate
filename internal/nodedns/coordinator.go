// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package nodedns coordinates trusted per-job DNS leases. It opens no agent DNS listener.
package nodedns

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/policy"
)

type Config struct {
	Binding  dnslease.Binding
	Network  policy.Network
	Resolver dnslease.Resolver
	Now      dnslease.Clock
}

// Publisher owns the central policy lock, signed rules, map readback, and domain stop.
// Activate verifies the already installed initial snapshot. Publish repeats Snapshot.Check.
// Stop must stop the whole domain and retain enforcement until confirmed cleanup.
type Publisher interface {
	Activate(context.Context, dnslease.Binding, dnslease.Snapshot) error
	Publish(context.Context, dnslease.Binding, dnslease.Snapshot) error
	Stop(context.Context, dnslease.Binding, string) error
}
type manager interface {
	Forward(context.Context, dnslease.Binding, []byte) dnslease.Outcome
	Snapshot(dnslease.Binding) (dnslease.Snapshot, error)
	Revoke(dnslease.Binding) (dnslease.Snapshot, error)
}
type Coordinator struct {
	mu            sync.Mutex
	phase         string
	initial       dnslease.Snapshot
	initialErr    error
	binding       dnslease.Binding
	networkDigest string
	evidence      dnslease.ResolverEvidence
	manager       manager
	clock         *clock
	resolver      *resolver
	questions     [][]byte
	wait          func(context.Context, time.Duration) error
}

func New(config Config) (*Coordinator, error) {
	if config.Now == nil || config.Resolver == nil {
		return nil, errors.New("a trusted monotonic clock and pinned resolver are required")
	}
	c := &Coordinator{phase: "new", binding: config.Binding, networkDigest: dnslease.NetworkDigest(config.Network), evidence: config.Resolver.Evidence(), wait: wait}
	c.clock = &clock{source: config.Now}
	c.resolver = &resolver{source: config.Resolver, evidence: c.evidence}
	m, err := dnslease.New(dnslease.Config{Binding: config.Binding, Network: config.Network, Resolver: c.resolver, Now: c.clock.now})
	if err != nil {
		return nil, err
	}
	c.manager = m
	c.questions, err = questions(config.Network)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ResolveAll runs once before launch. Any failed complete set returns a zero-rule snapshot.
// Fatal exhaustion can leave revision zero; the caller must stop and create a fresh binding.
func (c *Coordinator) ResolveAll(ctx context.Context) (out dnslease.Snapshot, err error) {
	c.mu.Lock()
	if c.phase != "new" {
		c.mu.Unlock()
		return out, errors.New("initial DNS resolution can run only once")
	}
	c.phase = "resolving"
	c.mu.Unlock()
	defer func() {
		if recover() != nil {
			err = errors.New("initial DNS resolution panicked")
		}
		if err != nil {
			denied, revokeErr := c.manager.Revoke(c.binding)
			out = denied
			err = errors.Join(err, revokeErr)
		}
		c.mu.Lock()
		c.phase = "resolved"
		c.initial = out
		c.initialErr = err
		c.mu.Unlock()
	}()
	if ctx == nil {
		return out, errors.New("a resolution context is required")
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	if _, err = c.live(); err != nil {
		return out, err
	}
	out, err = c.manager.Snapshot(c.binding)
	if err != nil {
		return out, err
	}
	out, err, _ = c.resolve(ctx, out, nil)
	if err != nil {
		return out, err
	}
	out, err = c.manager.Snapshot(c.binding)
	if err != nil {
		return out, err
	}
	now, err := c.live()
	if err != nil {
		return out, err
	}
	if err = out.Check(c.binding, c.networkDigest, c.evidence, 0, now); err != nil {
		return out, err
	}
	if out.Reason() != "" {
		return out, fmt.Errorf("the complete DNS lease set is unavailable: %s", out.Reason())
	}
	return out, nil
}

// Run owns one coordinator lifetime. Every exit invokes Stop with a fresh bounded context.
// It never grants resolver access or a socket receive operation to the agent.
func (c *Coordinator) Run(ctx context.Context, publisher Publisher, initial dnslease.Snapshot) (err error) {
	if ctx == nil || publisher == nil {
		return errors.New("a coordinator context and publisher are required")
	}
	c.mu.Lock()
	if c.phase != "resolved" {
		c.mu.Unlock()
		return errors.New("DNS coordinator requires a resolved unused binding")
	}
	c.phase = "running"
	resolved, initialErr := c.initial, c.initialErr
	c.mu.Unlock()
	reason := "dns-loop-ended"
	defer func() {
		if recover() != nil {
			err = errors.New("DNS coordinator panicked")
			reason = "dns-loop-panic"
		}
		stopCtx, cancel := controlContext(ctx)
		stopErr := safeStop(publisher, stopCtx, c.binding, reason)
		cancel()
		err = errors.Join(err, stopErr)
		_, _ = c.manager.Revoke(c.binding)
		c.mu.Lock()
		c.phase = "closed"
		c.mu.Unlock()
	}()
	if initialErr != nil || initial.Digest() != resolved.Digest() || initial.Revision() != resolved.Revision() {
		reason = "dns-initial-snapshot-mismatch"
		return errors.New("the initial complete DNS snapshot differs")
	}
	if err = ctx.Err(); err != nil {
		reason = "dns-context-ended"
		return err
	}
	now, err := c.live()
	if err != nil {
		reason = "dns-clock-or-deadline"
		return err
	}
	if err = initial.Check(c.binding, c.networkDigest, c.evidence, 0, now); err != nil {
		reason = "dns-initial-snapshot-invalid"
		return err
	}
	if err = publisher.Activate(ctx, c.binding, initial); err != nil {
		reason = "dns-activation-failed"
		return err
	}
	last := initial
	publish := func(snapshot dnslease.Snapshot) error {
		now, err := c.clock.now()
		if err != nil {
			return err
		}
		if err = snapshot.Check(c.binding, c.networkDigest, c.evidence, last.Revision(), now); err != nil {
			return err
		}
		control, cancel := controlContext(ctx)
		defer cancel()
		if err = publisher.Publish(control, c.binding, snapshot); err != nil {
			return err
		}
		last = snapshot
		return nil
	}
	due := c.next(last, now)
	for {
		if err = ctx.Err(); err != nil {
			reason = "dns-context-ended"
			return err
		}
		now, err = c.live()
		if err != nil {
			reason = "dns-clock-or-deadline"
			return err
		}
		if due > now {
			delay := due - now
			if delay > uint64(time.Minute) {
				delay = uint64(time.Minute)
			}
			if err = c.wait(ctx, time.Duration(delay)); err != nil {
				reason = "dns-wait-ended"
				return err
			}
			after, clockErr := c.clock.now()
			if clockErr != nil {
				reason = "dns-clock-failed"
				return clockErr
			}
			if after <= now {
				reason = "dns-clock-stalled"
				return errors.New("the monotonic clock did not advance after the wait")
			}
			continue
		}
		var fatal bool
		_, err, fatal = c.resolve(ctx, last, publish)
		if fatal {
			reason = "dns-refresh-failed"
			return err
		}
		// Ordinary resolver failures already published full deny. Retry uses that snapshot.
		now, err = c.live()
		if err != nil {
			reason = "dns-clock-or-deadline"
			return err
		}
		due = c.next(last, now)
	}
}
func (c *Coordinator) live() (uint64, error) {
	now, err := c.clock.now()
	if err != nil {
		return 0, err
	}
	if now >= c.binding.DeadlineNS {
		return now, errors.New("the DNS job binding expired")
	}
	return now, nil
}
func (c *Coordinator) next(snapshot dnslease.Snapshot, now uint64) uint64 {
	if len(c.questions) == 0 {
		return c.binding.DeadlineNS
	}
	if snapshot.Reason() != "" {
		if c.binding.DeadlineNS-now <= uint64(time.Second) {
			return c.binding.DeadlineNS
		}
		return now + uint64(time.Second)
	}
	expires := snapshot.NextExpiryNS()
	if expires == 0 || expires <= now {
		return now
	}
	remaining := expires - now
	lead := remaining / 4
	if lead > uint64(5*time.Second) {
		lead = uint64(5 * time.Second)
	}
	if lead == 0 {
		lead = 1
	}
	return minimum(expires-lead, c.binding.DeadlineNS)
}
func minimum(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}
func wait(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
func controlContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
}

func safeStop(publisher Publisher, ctx context.Context, binding dnslease.Binding, reason string) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("the DNS domain stop panicked")
		}
	}()
	return publisher.Stop(ctx, binding, reason)
}

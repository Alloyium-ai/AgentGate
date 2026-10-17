// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

type WatchdogConfig struct {
	Identity         Identity
	InstanceID       string
	ArtifactDigest   string
	HeartbeatTimeout time.Duration
	StopTimeout      time.Duration
}

// IndependentWatchdog runs outside the node daemon and uses separate durable
// state. A deployment must supervise this process before it qualifies Release.
type IndependentWatchdog struct {
	config  WatchdogConfig
	key     ed25519.PrivateKey
	store   WatchdogStore
	stopper WatchdogDomainStopper
	monitor DaemonMonitor
	clock   Clock
	mu      sync.Mutex
	ready   bool
}

func NewIndependentWatchdog(config WatchdogConfig, key ed25519.PrivateKey, store WatchdogStore, stopper WatchdogDomainStopper, monitor DaemonMonitor, clock Clock) (*IndependentWatchdog, error) {
	if !identifier.MatchString(config.Identity.NodeID) || !identifier.MatchString(config.Identity.BootID) || !identifier.MatchString(config.InstanceID) || !validDigest(config.ArtifactDigest) || config.HeartbeatTimeout <= 0 || config.HeartbeatTimeout > 2*time.Second || config.StopTimeout <= 0 || config.StopTimeout > 30*time.Second || len(key) != ed25519.PrivateKeySize || store == nil || stopper == nil || monitor == nil || clock == nil {
		return nil, errors.New("watchdog dependencies and bounded timeouts are required")
	}
	return &IndependentWatchdog{config: config, key: append(ed25519.PrivateKey{}, key...), store: store, stopper: stopper, monitor: monitor, clock: clock}, nil
}
func (w *IndependentWatchdog) deadline(now uint64, limit uint64) uint64 {
	if now > ^uint64(0)-uint64(w.config.HeartbeatTimeout) {
		return now
	}
	deadline := now + uint64(w.config.HeartbeatTimeout)
	if deadline > limit {
		deadline = limit
	}
	return deadline
}
func (w *IndependentWatchdog) stop(ctx context.Context, b Binding, reason string) error {
	if b.validate(false) != nil || b.NodeID != w.config.Identity.NodeID || b.BootID != w.config.Identity.BootID {
		w.ready = false
		return errors.New("watchdog stop requires a resolved owned binding")
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), w.config.StopTimeout)
	defer cancel()
	e, err := w.stopper.StopOwnedDomain(cleanup, clone(b), reason)
	if (!e.Retired && err != nil) || !e.Binding.same(b) || e.Reason != reason || !confirmedWatchdogStop(e) {
		w.ready = false
		return errors.New("watchdog whole-domain termination is unconfirmed")
	}
	if w.store.SaveWatchdogStop(cleanup, e) != nil {
		w.ready = false
		return errors.New("watchdog stop evidence is not durable")
	}
	return nil
}

// Recover always stops existing owned domains. A watchdog restart cannot inherit
// an execution lease from a process that it did not continuously supervise.
func (w *IndependentWatchdog) Recover(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.ready = false
	domains, inventoryErr := w.stopper.ListOwnedDomains(ctx)
	leases, loadErr := w.store.LoadWatchdog(ctx)
	failures := []error{}
	if inventoryErr != nil {
		failures = append(failures, errors.New("watchdog owned-domain inventory is unavailable"))
	}
	var err error
	observed := map[string]Binding{}
	stopped := map[string]Binding{}
	for _, b := range domains {
		if b.validate(false) != nil || b.NodeID != w.config.Identity.NodeID || b.BootID != w.config.Identity.BootID {
			failures = append(failures, errors.New("watchdog owned-domain inventory is invalid"))
			continue
		}
		observed[b.RunID] = b
		if err = w.stop(ctx, b, "watchdog-restart"); err != nil {
			failures = append(failures, err)
		} else {
			stopped[b.RunID] = b
		}
	}
	if loadErr != nil {
		failures = append(failures, errors.New("watchdog lease store is corrupt or unavailable"))
	}
	for _, lease := range leases {
		if lease.State == "stopped" {
			continue
		}
		b := lease.Ack.Binding
		if b.BootID != w.config.Identity.BootID {
			if err = w.retireOldBoot(ctx, lease); err != nil {
				failures = append(failures, err)
			}
			continue
		}
		if VerifyWatchdogAck(lease.Ack, b, w.key.Public().(ed25519.PublicKey), lease.Ack.IssuedNS) != nil {
			failures = append(failures, errors.New("watchdog recovery lease signature is invalid"))
			continue
		}
		if inventoryErr != nil && (lease.State == "armed" || lease.State == "active") {
			if actual, ok := stopped[b.RunID]; !ok || !actual.same(b) {
				if err = w.stop(ctx, b, "watchdog-inventory-unavailable"); err != nil {
					failures = append(failures, err)
					continue
				}
				stopped[b.RunID] = b
			}
		}
		if actual, seen := observed[b.RunID]; seen {
			if stoppedBinding, ok := stopped[b.RunID]; !ok || !stoppedBinding.same(actual) {
				continue
			}
		}
		expected := lease.Revision
		lease.Revision++
		lease.State = "stopped"
		if err = w.store.SaveWatchdog(ctx, lease, expected); err != nil {
			failures = append(failures, err)
		}
	}
	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	w.ready = true
	return nil
}
func (w *IndependentWatchdog) leases(ctx context.Context) (map[string]WatchdogLease, error) {
	leases, err := w.store.LoadWatchdog(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]WatchdogLease{}
	for _, lease := range leases {
		b := lease.Ack.Binding
		if validWatchdogLease(lease) != nil || VerifyWatchdogAck(lease.Ack, b, w.key.Public().(ed25519.PublicKey), lease.Ack.IssuedNS) != nil || out[b.RunID].Revision != 0 {
			return nil, errors.New("watchdog durable lease is invalid")
		}
		out[b.RunID] = lease
	}
	return out, nil
}
func watchdogLeaseMatches(lease WatchdogLease, b Binding) bool {
	expected := lease.Ack.Binding
	if lease.State == "reserved" && expected.CgroupID == 0 {
		expected.CgroupID = b.CgroupID
	}
	return expected.same(b)
}
func (w *IndependentWatchdog) Reserve(ctx context.Context, b Binding, daemon DaemonIdentity, preparationDeadline uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	now, err := w.clock.NowNS()
	if !w.ready || err != nil || b.validate(true) != nil || b.CgroupID != 0 || b.ArtifactDigests["watchdog"] != w.config.ArtifactDigest || b.NodeID != w.config.Identity.NodeID || b.BootID != w.config.Identity.BootID || now == 0 || now >= preparationDeadline || preparationDeadline > b.DeadlineNS || preparationDeadline-now > uint64(30*time.Second) || daemon.validate() != nil || w.monitor.Alive(ctx, daemon) != nil {
		return errors.New("watchdog preparation reservation is invalid")
	}
	ack := WatchdogAck{Protocol: WatchdogAckProtocol, Binding: clone(b), Daemon: daemon, WatchdogID: w.config.InstanceID, ArtifactDigest: w.config.ArtifactDigest, IssuedNS: now}
	ack.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(w.key, watchdogAckBytes(ack)))
	heartbeat := w.deadline(now, b.DeadlineNS)
	if heartbeat > preparationDeadline {
		heartbeat = preparationDeadline
	}
	lease := WatchdogLease{Ack: ack, PreparationDeadlineNS: preparationDeadline, HeartbeatDeadlineNS: heartbeat, Revision: 1, State: "reserved"}
	if err = w.store.SaveWatchdog(ctx, lease, 0); err != nil {
		return errors.New("watchdog preparation reservation is not durable")
	}
	return nil
}

func (w *IndependentWatchdog) Reservation(ctx context.Context, b Binding, daemon DaemonIdentity) (WatchdogAck, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	leases, err := w.leases(ctx)
	if err != nil {
		return WatchdogAck{}, errors.New("watchdog preparation reservation is unavailable")
	}
	lease, ok := leases[b.RunID]
	now, clockErr := w.clock.NowNS()
	if !w.ready || !ok || lease.State != "reserved" || !lease.Ack.Binding.same(b) || lease.Ack.Daemon != daemon || clockErr != nil || now >= lease.HeartbeatDeadlineNS || (lease.State != "active" && now >= lease.PreparationDeadlineNS) || w.monitor.Alive(ctx, daemon) != nil {
		return WatchdogAck{}, errors.New("watchdog preparation reservation differs")
	}
	return clone(lease.Ack), nil
}
func (w *IndependentWatchdog) Arm(ctx context.Context, b Binding, daemon DaemonIdentity) (WatchdogAck, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	now, err := w.clock.NowNS()
	if !w.ready || err != nil || b.validate(false) != nil || b.NodeID != w.config.Identity.NodeID || b.BootID != w.config.Identity.BootID || now == 0 || now >= b.DeadlineNS || daemon.validate() != nil || w.monitor.Alive(ctx, daemon) != nil {
		return WatchdogAck{}, errors.New("watchdog custody is unavailable")
	}
	leases, err := w.leases(ctx)
	if err != nil {
		w.ready = false
		return WatchdogAck{}, errors.New("watchdog lease store is unavailable")
	}
	reserved, exists := leases[b.RunID]
	expected := reserved.Ack.Binding
	expected.CgroupID = b.CgroupID
	if !exists || reserved.State != "reserved" || !expected.same(b) || reserved.Ack.Daemon != daemon || now >= reserved.PreparationDeadlineNS || now >= reserved.HeartbeatDeadlineNS {
		return WatchdogAck{}, errors.New("watchdog preparation reservation is absent or expired")
	}
	domains, err := w.stopper.ListOwnedDomains(ctx)
	if err != nil {
		w.ready = false
		return WatchdogAck{}, errors.New("watchdog domain inventory is unavailable")
	}
	found := false
	for _, owned := range domains {
		if owned.same(b) {
			found = true
		}
	}
	if !found {
		return WatchdogAck{}, errors.New("watchdog domain ownership differs")
	}
	ack := WatchdogAck{Protocol: WatchdogAckProtocol, Binding: clone(b), Daemon: daemon, WatchdogID: w.config.InstanceID, ArtifactDigest: w.config.ArtifactDigest, IssuedNS: now}
	ack.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(w.key, watchdogAckBytes(ack)))
	heartbeat := w.deadline(now, b.DeadlineNS)
	if heartbeat > reserved.PreparationDeadlineNS {
		heartbeat = reserved.PreparationDeadlineNS
	}
	lease := WatchdogLease{Ack: ack, PreparationDeadlineNS: reserved.PreparationDeadlineNS, HeartbeatDeadlineNS: heartbeat, Revision: reserved.Revision + 1, State: "armed"}
	if w.store.SaveWatchdog(ctx, lease, reserved.Revision) != nil {
		w.ready = false
		return WatchdogAck{}, errors.New("watchdog custody is not durable")
	}
	return clone(ack), nil
}
func (w *IndependentWatchdog) check(ctx context.Context, ack WatchdogAck, daemon DaemonIdentity, renew bool) error {
	now, err := w.clock.NowNS()
	if !w.ready || err != nil || VerifyWatchdogAck(ack, ack.Binding, w.key.Public().(ed25519.PublicKey), now) != nil || ack.WatchdogID != w.config.InstanceID || ack.ArtifactDigest != w.config.ArtifactDigest || ack.Daemon != daemon || w.monitor.Alive(ctx, daemon) != nil {
		return errors.New("watchdog custody is unavailable")
	}
	leases, err := w.leases(ctx)
	if err != nil {
		w.ready = false
		return errors.New("watchdog lease store is unavailable")
	}
	lease, exists := leases[ack.Binding.RunID]
	if !exists || (lease.State != "armed" && lease.State != "active" && !(renew && lease.State == "reserved")) || !reflect.DeepEqual(lease.Ack, ack) || now >= lease.HeartbeatDeadlineNS || (lease.State != "active" && now >= lease.PreparationDeadlineNS) {
		return errors.New("watchdog custody expired or differs")
	}
	if lease.State == "active" && (lease.EffectiveDeadlineNS == 0 || now >= lease.EffectiveDeadlineNS) {
		return errors.New("watchdog effective grant cutoff is absent or expired")
	}
	if renew {
		revision := lease.Revision
		lease.Revision++
		limit := ack.Binding.DeadlineNS
		if lease.State == "active" {
			limit = lease.EffectiveDeadlineNS
		}
		lease.HeartbeatDeadlineNS = w.deadline(now, limit)
		if lease.State != "active" && lease.HeartbeatDeadlineNS > lease.PreparationDeadlineNS {
			lease.HeartbeatDeadlineNS = lease.PreparationDeadlineNS
		}
		if w.store.SaveWatchdog(ctx, lease, revision) != nil {
			w.ready = false
			return errors.New("watchdog heartbeat is not durable")
		}
	}
	return nil
}
func (w *IndependentWatchdog) Check(ctx context.Context, ack WatchdogAck, daemon DaemonIdentity) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.check(ctx, ack, daemon, false)
}
func (w *IndependentWatchdog) Heartbeat(ctx context.Context, ack WatchdogAck, daemon DaemonIdentity) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.check(ctx, ack, daemon, true)
}

// Sweep uses independently discovered bindings for every stop. Corrupt lease
// bytes never select a cgroup path. It keeps retrying unconfirmed termination.
func (w *IndependentWatchdog) Sweep(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	now, clockErr := w.clock.NowNS()
	domains, inventoryErr := w.stopper.ListOwnedDomains(ctx)
	var err error
	leases, loadErr := w.leases(ctx)
	failures := []error{}
	seen := map[string]bool{}
	for _, b := range domains {
		if b.validate(false) != nil || b.NodeID != w.config.Identity.NodeID || b.BootID != w.config.Identity.BootID {
			w.ready = false
			failures = append(failures, errors.New("watchdog domain inventory is invalid"))
			continue
		}
		seen[b.RunID] = true
		lease, exists := leases[b.RunID]
		reason := ""
		switch {
		case inventoryErr != nil:
			reason = "watchdog-inventory-unavailable"
		case clockErr != nil:
			reason = "watchdog-clock-unavailable"
		case loadErr != nil:
			reason = "watchdog-store-unavailable"
		case !exists:
			reason = "watchdog-lease-missing"
		case !watchdogLeaseMatches(lease, b):
			reason = "watchdog-binding-differs"
		case lease.State != "armed" && lease.State != "active" && lease.State != "reserved":
			reason = "watchdog-lease-stopped"
		case b.BootID != w.config.Identity.BootID || b.NodeID != w.config.Identity.NodeID:
			reason = "watchdog-boot-differs"
		case VerifyWatchdogAck(lease.Ack, lease.Ack.Binding, w.key.Public().(ed25519.PublicKey), now) != nil:
			reason = "watchdog-lease-invalid"
		case lease.Ack.WatchdogID != w.config.InstanceID || lease.Ack.ArtifactDigest != w.config.ArtifactDigest:
			reason = "watchdog-instance-differs"
		case now >= b.DeadlineNS:
			reason = "watchdog-grant-expired"
		case lease.State == "active" && lease.EffectiveDeadlineNS == 0:
			reason = "watchdog-effective-deadline-missing"
			w.ready = false
		case lease.State == "active" && now >= lease.EffectiveDeadlineNS:
			reason = "watchdog-grant-expired"
		case lease.State != "active" && now >= lease.PreparationDeadlineNS:
			reason = "watchdog-preparation-expired"
		case now >= lease.HeartbeatDeadlineNS:
			reason = "watchdog-heartbeat-expired"
		case w.monitor.Alive(ctx, lease.Ack.Daemon) != nil:
			reason = "watchdog-daemon-lost"
		}
		if reason == "" {
			continue
		}
		if err = w.stop(ctx, b, reason); err != nil {
			failures = append(failures, err)
			continue
		}
		if exists && watchdogLeaseMatches(lease, b) && loadErr == nil {
			expected := lease.Revision
			lease.Revision++
			lease.State = "stopped"
			if err = w.store.SaveWatchdog(ctx, lease, expected); err != nil {
				w.ready = false
				failures = append(failures, err)
			}
		}
	}
	for run, lease := range leases {
		if seen[run] {
			continue
		}
		if inventoryErr != nil && (lease.State == "armed" || lease.State == "active") {
			if err = w.stop(ctx, lease.Ack.Binding, "watchdog-inventory-unavailable"); err != nil {
				failures = append(failures, err)
				continue
			}
		}
		absent := lease.State == "armed" || lease.State == "active"
		expired := clockErr != nil || now >= lease.HeartbeatDeadlineNS || (lease.State != "active" && now >= lease.PreparationDeadlineNS) || w.monitor.Alive(ctx, lease.Ack.Daemon) != nil
		if absent || expired {
			expected := lease.Revision
			lease.Revision++
			lease.State = "stopped"
			if err = w.store.SaveWatchdog(ctx, lease, expected); err != nil {
				w.ready = false
				failures = append(failures, err)
			}
		}
	}
	if inventoryErr != nil || clockErr != nil || loadErr != nil {
		w.ready = false
		failures = append(failures, errors.New("watchdog inventory, clock or durable state is unavailable"))
	}
	return errors.Join(failures...)
}

// Watch must run in a separate trusted process. Cancellation stops all owned
// domains before it returns. An external supervisor must restart a crashed watcher.
func (w *IndependentWatchdog) Watch(ctx context.Context, interval time.Duration) error {
	if interval <= 0 || interval > 100*time.Millisecond {
		return errors.New("watchdog interval must be positive and at most one hundred milliseconds")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			err := w.Recover(context.WithoutCancel(ctx))
			w.mu.Lock()
			w.ready = false
			w.mu.Unlock()
			return err
		case <-ticker.C:
			_ = w.Sweep(ctx)
		}
	}
}

// Old boot IDs have no current domain identity. Verify the actual boot change
// before recording absence; never send a potentially reused ID to the stopper.
func (w *IndependentWatchdog) retireOldBoot(ctx context.Context, lease WatchdogLease) error {
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	b := lease.Ack.Binding
	if err != nil || strings.TrimSpace(string(raw)) != w.config.Identity.BootID || b.BootID == w.config.Identity.BootID || b.NodeID != w.config.Identity.NodeID || VerifyWatchdogAck(lease.Ack, b, w.key.Public().(ed25519.PublicKey), lease.Ack.IssuedNS) != nil {
		return errors.New("watchdog old boot retirement is unverified")
	}
	expected := lease.Revision
	lease.Revision++
	lease.State = "stopped"
	lease.NoDomain = true
	lease.RetiredBootID = w.config.Identity.BootID
	return w.store.SaveWatchdog(ctx, lease, expected)
}

// Activate removes only the preparation limit. The immutable grant deadline,
// heartbeat and daemon custody remain mandatory throughout execution.
func (w *IndependentWatchdog) Activate(ctx context.Context, ack WatchdogAck, daemon DaemonIdentity, effectiveDeadline uint64) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.check(ctx, ack, daemon, false); err != nil {
		return err
	}
	leases, err := w.leases(ctx)
	if err != nil {
		return err
	}
	lease, ok := leases[ack.Binding.RunID]
	if !ok || lease.State != "armed" {
		return errors.New("watchdog activation requires held preparation custody")
	}
	now, err := w.clock.NowNS()
	if err != nil || now >= lease.PreparationDeadlineNS || effectiveDeadline <= now || effectiveDeadline > ack.Binding.DeadlineNS {
		return errors.New("watchdog activation preparation expired")
	}
	expected := lease.Revision
	lease.Revision++
	lease.State = "active"
	lease.EffectiveDeadlineNS = effectiveDeadline
	lease.HeartbeatDeadlineNS = w.deadline(now, effectiveDeadline)
	if err = w.store.SaveWatchdog(ctx, lease, expected); err != nil {
		w.ready = false
		return errors.New("watchdog activation is not durable")
	}
	readback, err := w.leases(ctx)
	actual, ok := readback[ack.Binding.RunID]
	if err != nil || !ok || !reflect.DeepEqual(actual, lease) {
		w.ready = false
		return errors.New("watchdog activation readback differs")
	}
	return nil
}

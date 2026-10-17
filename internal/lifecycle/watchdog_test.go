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
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fixtureGuard struct {
	key               ed25519.PrivateKey
	clock             Clock
	err               error
	activation        func() error
	effectiveDeadline uint64
}

func (g *fixtureGuard) Reserve(context.Context, Binding, uint64) error { return g.err }
func (g *fixtureGuard) Arm(_ context.Context, b Binding) (WatchdogAck, error) {
	if g.err != nil {
		return WatchdogAck{}, g.err
	}
	now, _ := g.clock.NowNS()
	ack := WatchdogAck{Protocol: WatchdogAckProtocol, Binding: clone(b), Daemon: DaemonIdentity{1234, 900, "unit-daemon"}, WatchdogID: "unit-watchdog", ArtifactDigest: strings.Repeat("9", 64), IssuedNS: now}
	ack.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(g.key, watchdogAckBytes(ack)))
	return ack, nil
}
func (g *fixtureGuard) Activate(_ context.Context, _ WatchdogAck, deadline uint64) error {
	g.effectiveDeadline = deadline
	if g.activation != nil {
		return g.activation()
	}
	return g.err
}
func (g *fixtureGuard) Check(context.Context, WatchdogAck) error { return g.err }
func (g *fixtureGuard) Forget(Binding)                           {}

type monitorFixture struct{ lost bool }

func (m *monitorFixture) Alive(context.Context, DaemonIdentity) error {
	if m.lost {
		return errors.New("unit daemon lost")
	}
	return nil
}

type stopperFixture struct {
	domains       map[string]Binding
	stops         []WatchdogStopEvidence
	incomplete    bool
	inventoryErr  error
	hideInventory bool
	retired       bool
	retiredUnsafe bool
}

func (s *stopperFixture) ListOwnedDomains(context.Context) ([]Binding, error) {
	out := []Binding{}
	for _, b := range s.domains {
		out = append(out, clone(b))
	}
	if s.hideInventory {
		return nil, s.inventoryErr
	}
	return out, s.inventoryErr
}
func (s *stopperFixture) StopOwnedDomain(_ context.Context, b Binding, reason string) (WatchdogStopEvidence, error) {
	actual, exists := s.domains[b.RunID]
	if !exists || !actual.same(b) || b.CgroupID == 0 {
		return WatchdogStopEvidence{}, errors.New("unit protected ownership differs")
	}
	e := WatchdogStopEvidence{Binding: clone(b), Reason: reason, Terminated: true, Empty: !s.incomplete, PinsRetained: true, ReadbackDigest: strings.Repeat("8", 64)}
	if s.retired {
		e.Retired = true
		e.NoDomain = true
		e.RightsRemoved = !s.retiredUnsafe
		e.PinsRetained = false
		e.CountersAvailable = false
		e.CurrentRootProofDigest = strings.Repeat("6", 64)
		e.ReservationRootProofDigest = strings.Repeat("7", 64)
	}
	e.Digest = WatchdogStopDigest(e)
	s.stops = append(s.stops, e)
	if s.retired {
		return e, errors.New("unit counters unavailable after concurrent reconciliation")
	}
	return e, nil
}

type watcherFixture struct {
	core    *IndependentWatchdog
	store   *SQLiteJournal
	stopper *stopperFixture
	monitor *monitorFixture
	clock   *testClock
	key     ed25519.PrivateKey
	daemon  DaemonIdentity
	binding Binding
}

func watcher(t *testing.T) *watcherFixture {
	t.Helper()
	dir := journalFixture(t).path
	store, err := OpenWatchdogStore(filepath.Join(filepath.Dir(dir), "watchdog.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	clock := &testClock{now: 1}
	stopper := &stopperFixture{domains: map[string]Binding{}}
	monitor := &monitorFixture{}
	core, err := NewIndependentWatchdog(WatchdogConfig{Identity: Identity{"node-one", "boot-one"}, InstanceID: "watchdog-one", ArtifactDigest: strings.Repeat("9", 64), HeartbeatTimeout: time.Second, StopTimeout: 10 * time.Second}, key, store, stopper, monitor, clock)
	if err != nil {
		t.Fatal(err)
	}
	if err = core.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := fixtureBinding()
	b.DeadlineNS = uint64(60 * time.Second)
	return &watcherFixture{core, store, stopper, monitor, clock, key, DaemonIdentity{1234, 900, "node-daemon-one"}, b}
}
func (f *watcherFixture) arm(t *testing.T) WatchdogAck {
	t.Helper()
	ctx := context.Background()
	if err := f.core.Reserve(ctx, f.binding, f.daemon, uint64(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	f.binding.CgroupID = 100
	f.stopper.domains[f.binding.RunID] = clone(f.binding)
	// A protected domain can appear after reservation and before the Arm reply.
	if err := f.core.Sweep(ctx); err != nil || len(f.stopper.stops) != 0 {
		t.Fatal("reservation did not cover the held domain", err)
	}
	ack, err := f.core.Arm(ctx, f.binding, f.daemon)
	if err != nil {
		t.Fatal(err)
	}
	return ack
}
func TestIndependentWatchdogSignsDurableCustodyAndRejectsMutation(t *testing.T) {
	f := watcher(t)
	ack := f.arm(t)
	ctx := context.Background()
	if err := VerifyWatchdogAck(ack, f.binding, f.key.Public().(ed25519.PublicKey), f.clock.now); err != nil {
		t.Fatal(err)
	}
	leases, err := f.store.LoadWatchdog(ctx)
	if err != nil || len(leases) != 1 || leases[0].State != "armed" {
		t.Fatal("ack preceded durable custody", err)
	}
	artifact := clone(ack)
	artifact.ArtifactDigest = strings.Repeat("7", 64)
	artifact.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.key, watchdogAckBytes(artifact)))
	if VerifyWatchdogAck(artifact, f.binding, f.key.Public().(ed25519.PublicKey), f.clock.now) == nil {
		t.Fatal("a signed unbound watchdog artifact passed")
	}
	mutated := clone(ack)
	mutated.Binding.Generation++
	if err = VerifyWatchdogAck(mutated, mutated.Binding, f.key.Public().(ed25519.PublicKey), f.clock.now); err == nil {
		t.Fatal("modified binding passed signature")
	}
	if err = f.core.Check(ctx, ack, DaemonIdentity{1235, 900, "node-daemon-one"}); err == nil {
		t.Fatal("different daemon inherited custody")
	}
	if _, err = f.core.Arm(ctx, f.binding, f.daemon); err == nil {
		t.Fatal("an armed domain replayed")
	}
	f.clock.now = uint64(500 * time.Millisecond)
	if err = f.core.Heartbeat(ctx, ack, f.daemon); err != nil {
		t.Fatal(err)
	}
	f.clock.now = uint64(1100 * time.Millisecond)
	if err = f.core.Sweep(ctx); err != nil || len(f.stopper.stops) != 0 {
		t.Fatal("a valid heartbeat did not retain custody", err)
	}
}
func TestWatchdogStopsOnDaemonLossDeadlineMissingAndCorruptLease(t *testing.T) {
	for _, failure := range []string{"daemon", "deadline", "heartbeat", "missing", "corrupt", "binding"} {
		t.Run(failure, func(t *testing.T) {
			f := watcher(t)
			f.arm(t)
			ctx := context.Background()
			switch failure {
			case "daemon":
				f.monitor.lost = true
			case "deadline":
				f.clock.now = f.binding.DeadlineNS
			case "heartbeat":
				f.clock.now = uint64(time.Second) + 1
			case "missing":
				if _, err := f.store.db.Exec(`DELETE FROM watchdog_leases`); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if _, err := f.store.db.Exec(`UPDATE watchdog_leases SET record='corrupt'`); err != nil {
					t.Fatal(err)
				}
			case "binding":
				if _, err := f.store.db.Exec(`UPDATE watchdog_leases SET record=replace(record,'"cgroup_id":"100"','"cgroup_id":"1"')`); err != nil {
					t.Fatal(err)
				}
			}
			err := f.core.Sweep(ctx)
			if failure == "corrupt" && err == nil {
				t.Fatal("corrupt store did not close admission")
			}
			if len(f.stopper.stops) != 1 {
				t.Fatal("domain did not stop", err)
			}
			stopped := f.stopper.stops[0]
			if stopped.Binding.CgroupID != 100 || !stopped.Binding.same(f.binding) || !stopped.Empty || !stopped.PinsRetained {
				t.Fatal("lease bytes selected an unrelated domain")
			}
		})
	}
}
func TestWatchdogRestartStopsExistingDomainAndRetainsTerminalLease(t *testing.T) {
	f := watcher(t)
	ack := f.arm(t)
	ctx := context.Background()
	if err := f.core.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.stopper.stops) != 1 || f.stopper.stops[0].Reason != "watchdog-restart" {
		t.Fatal("restart retained a running domain")
	}
	if err := f.core.Check(ctx, ack, f.daemon); err == nil {
		t.Fatal("restart revived custody")
	}
	b := f.binding
	b.CgroupID = 0
	if err := f.core.Reserve(ctx, b, f.daemon, uint64(10*time.Second)); err == nil {
		t.Fatal("a terminal run replayed")
	}
}
func TestWatchdogRetriesUnconfirmedStopAndRejectsPreparationDrift(t *testing.T) {
	f := watcher(t)
	f.arm(t)
	f.monitor.lost = true
	f.stopper.incomplete = true
	if err := f.core.Sweep(context.Background()); err == nil {
		t.Fatal("nonempty domain passed")
	}
	f.stopper.incomplete = false
	if err := f.core.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.stopper.stops) != 2 {
		t.Fatal("unconfirmed termination did not retry")
	}
	g := watcher(t)
	if err := g.core.Reserve(context.Background(), g.binding, g.daemon, uint64(time.Second)); err != nil {
		t.Fatal(err)
	}
	g.binding.CgroupID = 100
	g.binding.Generation++
	g.stopper.domains[g.binding.RunID] = g.binding
	if err := g.core.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(g.stopper.stops) != 1 {
		t.Fatal("a changed reservation survived")
	}
}
func TestReleaseRequiresIndependentWatchdogCustody(t *testing.T) {
	for _, failure := range []string{"missing", "outage", "signature"} {
		t.Run(failure, func(t *testing.T) {
			m, b, _, _, _, r := installedFixture(t)
			switch failure {
			case "missing":
				m.guard = nil
			case "outage":
				m.guard.(*fixtureGuard).err = errors.New("unit watchdog outage")
			case "signature":
				m.watchdogKey = ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", 32))).Public().(ed25519.PublicKey)
			}
			if _, err := m.Release(context.Background(), r.Binding.RunID); err == nil {
				t.Fatal("release lacked independent custody")
			}
			for _, call := range b.calls {
				if call == "release" {
					t.Fatal("backend released without custody")
				}
			}
			stopped, _ := m.Record(r.Binding.RunID)
			if stopped.State != "stopped" {
				t.Fatal("failed custody left a domain")
			}
		})
	}
}
func TestLinuxDaemonMonitorRejectsExitedAndReusedIdentity(t *testing.T) {
	command := exec.Command("/bin/cat")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { input.Close(); command.Process.Kill(); command.Wait() })
	ticks, err := ProcessStartTime(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	identity := DaemonIdentity{command.Process.Pid, ticks, "unit-live-process"}
	monitor := LinuxDaemonMonitor{}
	if err = monitor.Alive(context.Background(), identity); err != nil {
		t.Fatal(err)
	}
	wrong := identity
	wrong.StartTimeTicks++
	if err = monitor.Alive(context.Background(), wrong); err == nil {
		t.Fatal("reused PID identity passed")
	}
	if err = command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	command.Wait()
	if err = monitor.Alive(context.Background(), identity); err == nil {
		t.Fatal("exited daemon passed")
	}
}

func TestWatchdogExpiresReservationWithoutSelectingCgroupZero(t *testing.T) {
	f := watcher(t)
	ctx := context.Background()
	if err := f.core.Reserve(ctx, f.binding, f.daemon, uint64(time.Second)); err != nil {
		t.Fatal(err)
	}
	f.clock.now = uint64(time.Second) + 1
	if err := f.core.Sweep(ctx); err != nil {
		t.Fatal(err)
	}
	active, err := f.store.LoadWatchdog(ctx)
	if err != nil || len(active) != 0 {
		t.Fatal("expired preparation remained active", err)
	}
	history, err := f.store.WatchdogHistory(ctx)
	if err != nil || len(history) != 1 || history[0].State != "stopped" {
		t.Fatal("expired preparation lost its replay floor", err)
	}
	if len(f.stopper.stops) != 0 {
		t.Fatal("a reservation selected cgroup zero")
	}
}

func TestWatchdogStopsSafePartialInventoryBeforeClosingAdmission(t *testing.T) {
	for _, operation := range []string{"recover", "sweep", "hidden-recover", "hidden-sweep"} {
		t.Run(operation, func(t *testing.T) {
			f := watcher(t)
			f.arm(t)
			f.stopper.inventoryErr = errors.New("unit partial inventory")
			var err error
			f.stopper.hideInventory = strings.HasPrefix(operation, "hidden-")
			if strings.HasSuffix(operation, "recover") {
				err = f.core.Recover(context.Background())
			} else {
				err = f.core.Sweep(context.Background())
			}
			if err == nil || len(f.stopper.stops) != 1 || f.core.ready {
				t.Fatal("partial inventory retained a known owned domain", err)
			}
		})
	}
}

func TestWatchdogRetiresOldBootWithoutStoppingAReusedID(t *testing.T) {
	for _, partial := range []bool{false, true} {
		t.Run(fmt.Sprint(partial), func(t *testing.T) {
			f := watcher(t)
			f.arm(t)
			currentRaw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
			if err != nil {
				t.Fatal(err)
			}
			current := strings.TrimSpace(string(currentRaw))
			f.core.config.Identity.BootID = current
			old := clone(f.binding)
			live := clone(old)
			live.BootID = current
			live.RunID = "current-run"
			f.stopper.domains = map[string]Binding{live.RunID: live}
			if partial {
				f.stopper.inventoryErr = errors.New("unit partial inventory")
			}
			err = f.core.Recover(context.Background())
			if (err != nil) != partial || len(f.stopper.stops) != 1 || !f.stopper.stops[0].Binding.same(live) {
				t.Fatal("recovery selected an old boot ID", err)
			}
			history, err := f.store.WatchdogHistory(context.Background())
			if err != nil || len(history) != 1 || !history[0].NoDomain || history[0].RetiredBootID != current || !history[0].Ack.Binding.same(old) {
				t.Fatal("old binding retirement lost custody", err)
			}
		})
	}
}
func TestWatchdogRejectsUnverifiedBootRetirement(t *testing.T) {
	f := watcher(t)
	f.arm(t)
	f.core.config.Identity.BootID = "unverified-new-boot"
	f.stopper.domains = map[string]Binding{}
	if err := f.core.Recover(context.Background()); err == nil {
		t.Fatal("an unverified boot retired a lease")
	}
	history, _ := f.store.WatchdogHistory(context.Background())
	if len(history) != 1 || history[0].State != "armed" || len(f.stopper.stops) != 0 {
		t.Fatal("unverified retirement changed custody")
	}
}

func TestArmedPreparationCannotRenewPastItsIndependentDeadline(t *testing.T) {
	f := watcher(t)
	ctx := context.Background()
	deadline := uint64(800 * time.Millisecond)
	if err := f.core.Reserve(ctx, f.binding, f.daemon, deadline); err != nil {
		t.Fatal(err)
	}
	f.binding.CgroupID = 100
	f.stopper.domains[f.binding.RunID] = clone(f.binding)
	ack, err := f.core.Arm(ctx, f.binding, f.daemon)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.now = uint64(500 * time.Millisecond)
	if err = f.core.Heartbeat(ctx, ack, f.daemon); err != nil {
		t.Fatal(err)
	}
	leases, _ := f.store.LoadWatchdog(ctx)
	if len(leases) != 1 || leases[0].HeartbeatDeadlineNS != deadline {
		t.Fatal("armed heartbeat extended preparation")
	}
	f.clock.now = deadline + 1
	if err = f.core.Activate(ctx, ack, f.daemon, f.binding.DeadlineNS); err == nil {
		t.Fatal("expired preparation activated")
	}
	if err = f.core.Sweep(ctx); err != nil || len(f.stopper.stops) != 1 {
		t.Fatal("lost prepare response retained a domain", err)
	}
}
func TestActivationRetainsHeartbeatAndImmutableGrantDeadline(t *testing.T) {
	f := watcher(t)
	ctx := context.Background()
	deadline := uint64(800 * time.Millisecond)
	if err := f.core.Reserve(ctx, f.binding, f.daemon, deadline); err != nil {
		t.Fatal(err)
	}
	f.binding.CgroupID = 100
	f.stopper.domains[f.binding.RunID] = clone(f.binding)
	ack, err := f.core.Arm(ctx, f.binding, f.daemon)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.now = uint64(500 * time.Millisecond)
	bad := clone(ack)
	bad.Binding.Generation++
	if f.core.Activate(ctx, bad, f.daemon, f.binding.DeadlineNS) == nil {
		t.Fatal("changed activation passed")
	}
	if err = f.core.Activate(ctx, ack, f.daemon, f.binding.DeadlineNS); err != nil {
		t.Fatal(err)
	}
	if f.core.Activate(ctx, ack, f.daemon, f.binding.DeadlineNS) == nil {
		t.Fatal("activation replay passed")
	}
	f.clock.now = deadline + 1
	if err = f.core.Heartbeat(ctx, ack, f.daemon); err != nil {
		t.Fatal(err)
	}
	if err = f.core.Sweep(ctx); err != nil || len(f.stopper.stops) != 0 {
		t.Fatal("active lease kept the preparation limit", err)
	}
	leases, _ := f.store.LoadWatchdog(ctx)
	if len(leases) != 1 || leases[0].State != "active" || !leases[0].Ack.Binding.same(f.binding) {
		t.Fatal("activation changed the binding")
	}
	f.monitor.lost = true
	if err = f.core.Sweep(ctx); err != nil || len(f.stopper.stops) != 1 {
		t.Fatal("activated domain survived daemon loss", err)
	}
}
func TestManagerActivatesOnlyAfterDurableReleaseIntent(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			m, b, _, _, _, r := installedFixture(t)
			called := false
			m.guard.(*fixtureGuard).activation = func() error {
				called = true
				record, ok := m.Record(r.Binding.RunID)
				if !ok || record.State != "release-pending" {
					t.Fatal("activation preceded durable release intent")
				}
				for _, call := range b.calls {
					if call == "release" {
						t.Fatal("backend release preceded activation")
					}
				}
				if failure {
					return errors.New("unit activation failure")
				}
				return nil
			}
			_, err := m.Release(context.Background(), r.Binding.RunID)
			if !called || (err != nil) != failure {
				t.Fatal("activation result did not control release", err)
			}
			released := false
			for _, call := range b.calls {
				released = released || call == "release"
			}
			if released == failure {
				t.Fatal("backend release crossed failed activation")
			}
		})
	}
}

func TestWatchdogRetiresAnIndependentlyConfirmedCompletionRace(t *testing.T) {
	f := watcher(t)
	f.arm(t)
	f.stopper.retired = true
	f.clock.now = uint64(time.Second) + 1
	if err := f.core.Sweep(context.Background()); err != nil {
		t.Fatal("a confirmed completion race closed watchdog readiness", err)
	}
	history, err := f.store.WatchdogHistory(context.Background())
	if err != nil || len(history) != 1 || history[0].State != "stopped" || !f.core.ready {
		t.Fatal("the retired lease stayed active", err)
	}
	if len(f.stopper.stops) != 1 || !f.stopper.stops[0].NoDomain || !f.stopper.stops[0].RightsRemoved || f.stopper.stops[0].CountersAvailable {
		t.Fatal("retirement invented counters or lost absence proof")
	}
}
func TestWatchdogRejectsUnconfirmedRetirement(t *testing.T) {
	f := watcher(t)
	f.arm(t)
	f.stopper.retired = true
	f.stopper.retiredUnsafe = true
	f.clock.now = uint64(time.Second) + 1
	if f.core.Sweep(context.Background()) == nil || f.core.ready {
		t.Fatal("an absent domain without confirmed rights cleanup retired")
	}
	history, _ := f.store.WatchdogHistory(context.Background())
	if len(history) != 1 || history[0].State != "armed" {
		t.Fatal("unconfirmed retirement lost its active lease")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/lifecycle"
)

func TestServiceLifecycleReadsTheOwnedActiveWatchdogLease(t *testing.T) {
	recipe := serviceLifecycleRecipeFixture(t)
	private := filepath.Join(recipe.Spec.OwnedRoot, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(private, "watchdog.db")
	store, err := lifecycle.OpenWatchdogStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	now := serviceMono()
	cutoff := now + uint64(5*time.Second)
	binding := recipe.Spec.Binding
	ack := lifecycle.WatchdogAck{Protocol: lifecycle.WatchdogAckProtocol, Binding: binding, Daemon: lifecycle.DaemonIdentity{PID: 42, StartTimeTicks: 42, InstanceID: "unit-node"}, WatchdogID: "watchdog-" + digestJSON(recipe.Spec)[:20], ArtifactDigest: binding.ArtifactDigests["watchdog"], IssuedNS: now}
	row := lifecycle.WatchdogLease{Ack: ack, PreparationDeadlineNS: now + uint64(10*time.Second), HeartbeatDeadlineNS: now + uint64(time.Second), Revision: 1, State: "reserved"}
	ctx := context.Background()
	if err = store.SaveWatchdog(ctx, row, 0); err != nil {
		t.Fatal(err)
	}
	row.Revision = 2
	row.State = "armed"
	row.Ack.Binding.CgroupID = 42
	signing, _ := json.Marshal(row.Ack)
	row.Ack.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte("agentgate-watchdog-custody-v1\n"), signing...)))
	if err = store.SaveWatchdog(ctx, row, 1); err != nil {
		t.Fatal(err)
	}
	row.Revision = 3
	row.State = "active"
	row.EffectiveDeadlineNS = cutoff
	if err = store.SaveWatchdog(ctx, row, 2); err != nil {
		t.Fatal(err)
	}
	scene := serviceLifecycleScene{Recipe: recipe, WatchdogPublic: key.Public().(ed25519.PublicKey), Calls: []serviceLifecycleHTTPCall{{Path: "/fixture/start", Status: 200, MonoNS: now}}}
	scene.NodeConfig.WatchdogStore = path
	scene.NodeSnapshot.PID, scene.NodeSnapshot.StartTimeTicks = 42, 42
	scene.Active.Record.Binding = row.Ack.Binding
	scene.Active.Record.Watchdog = &row.Ack
	scene.Prepared.Record.PreparationDeadlineNS = row.PreparationDeadlineNS
	readback, err := readServiceLifecycleWatchdog(ctx, scene)
	if err != nil || !reflect.DeepEqual(readback.Rows, []lifecycle.WatchdogLease{row}) {
		t.Fatal("the real database row differs", readback, err)
	}
	reader, err := openServiceLifecycleWatchdogDatabase(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reader.ExecContext(ctx, "DELETE FROM watchdog_leases"); err == nil {
		reader.Close()
		t.Fatal("the evidence reader can write the watchdog store")
	}
	if err = reader.Close(); err != nil {
		t.Fatal(err)
	}
	preserved, err := store.LoadWatchdog(ctx)
	if err != nil || !reflect.DeepEqual(preserved, []lifecycle.WatchdogLease{row}) {
		t.Fatal("the read-only handle changed the active lease", preserved, err)
	}
	scene.WatchdogState = &readback
	if err = verifyServiceLifecycleWatchdog(scene, cutoff); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*serviceLifecycleWatchdogReadback){
		"different inode": func(r *serviceLifecycleWatchdogReadback) { r.After.Inode++ },
		"untrusted owner": func(r *serviceLifecycleWatchdogReadback) { r.Before.UID = 65534 },
		"wider cutoff":    func(r *serviceLifecycleWatchdogReadback) { r.Rows[0].EffectiveDeadlineNS++ },
		"stopped lease":   func(r *serviceLifecycleWatchdogReadback) { r.Rows[0].State = "stopped" },
		"expired sample":  func(r *serviceLifecycleWatchdogReadback) { r.FinishedNS = cutoff },
		"missing row":     func(r *serviceLifecycleWatchdogReadback) { r.Rows = nil },
		"changed daemon":  func(r *serviceLifecycleWatchdogReadback) { r.Rows[0].Ack.Daemon.StartTimeTicks++ },
	} {
		t.Run(name, func(t *testing.T) {
			var changed serviceLifecycleWatchdogReadback
			if err := json.Unmarshal(serviceJSON(readback), &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed)
			substituted := scene
			substituted.WatchdogState = &changed
			if verifyServiceLifecycleWatchdog(substituted, cutoff) == nil {
				t.Fatal("a changed watchdog observation passed")
			}
		})
	}
	if err = os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(path+".original", path); err != nil {
		t.Fatal(err)
	}
	if _, err = readServiceLifecycleWatchdog(ctx, scene); err == nil {
		t.Fatal("a linked watchdog database passed")
	}
}

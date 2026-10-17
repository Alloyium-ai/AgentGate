// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestJournalRejectsStaleWritersBindingChangesAndGenerationReplay(t *testing.T) {
	journal := journalFixture(t)
	ctx := context.Background()
	r := Record{Binding: fixtureBinding(), State: "preparing", Revision: 1, Evidence: []Evidence{}}
	if err := journal.Save(ctx, r, 0); err != nil {
		t.Fatal(err)
	}
	stale := clone(r)
	stale.Revision = 2
	stale.State = "stop-pending"
	changed := clone(stale)
	changed.Binding.JobDigest = strings.Repeat("f", 64)
	if err := journal.Save(ctx, changed, 1); err == nil {
		t.Fatal("changed immutable job digest accepted")
	}
	if err := journal.Save(ctx, stale, 1); err != nil {
		t.Fatal(err)
	}
	if err := journal.Save(ctx, stale, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale writer accepted: %v", err)
	}
	replay := Record{Binding: fixtureBinding(), State: "preparing", Revision: 1, Evidence: []Evidence{}}
	replay.Binding.RunID = "run-two"
	replay.Binding.GrantID = "grant-two"
	if err := journal.Save(ctx, replay, 0); !errors.Is(err, ErrReplay) {
		t.Fatalf("reused generation accepted: %v", err)
	}
	replay.Binding.Generation = 2
	if err := journal.Save(ctx, replay, 0); err != nil {
		t.Fatal(err)
	}
}
func TestJournalDoesNotDiscardPriorEvidence(t *testing.T) {
	m, _, _, _, journal, r := installedFixture(t)
	_ = m
	next := clone(r)
	next.State = "stop-pending"
	next.Revision++
	next.Evidence = next.Evidence[1:]
	if err := journal.Save(context.Background(), next, r.Revision); err == nil {
		t.Fatal("prior evidence was removed")
	}
}
func TestCorruptJournalClosesAdmissionAndStopsOwnedDomains(t *testing.T) {
	m, b, _, _, journal, r := installedFixture(t)
	if _, err := journal.db.Exec(`UPDATE lifecycle_records SET record='invalid-json' WHERE run_id=?`, r.Binding.RunID); err != nil {
		t.Fatal(err)
	}
	if err := m.Recover(context.Background()); err == nil {
		t.Fatal("corrupt journal recovered")
	}
	if m.Ready() || len(b.domains) != 0 {
		t.Fatal("corrupt journal left admission open or owned domain live")
	}
}
func TestRecoveredStoppedRecordDoesNotAuthorizeReappearedDomain(t *testing.T) {
	m, b, _, _, _, r := installedFixture(t)
	ctx := context.Background()
	if _, err := m.Stop(ctx, r.Binding.RunID, "test-finish"); err != nil {
		t.Fatal(err)
	}
	b.domains[r.Binding.RunID] = r.Binding
	if err := m.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if len(b.domains) != 0 {
		t.Fatal("stopped journal record authorized a reappeared domain")
	}
}

func TestJournalReopenRetainsStateAndReplayGuard(t *testing.T) {
	journal := journalFixture(t)
	ctx := context.Background()
	record := Record{Binding: fixtureBinding(), State: "preparing", Revision: 1, Evidence: []Evidence{}}
	if err := journal.Save(ctx, record, 0); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournal(journal.path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	records, err := reopened.Load(ctx)
	if err != nil || len(records) != 1 || !records[0].Binding.same(record.Binding) {
		t.Fatal("durable record differs", err)
	}
	replay := clone(record)
	replay.Binding.RunID = "new-run"
	replay.Binding.GrantID = "new-grant"
	if err = reopened.Save(ctx, replay, 0); !errors.Is(err, ErrReplay) {
		t.Fatal("restart lost replay guard", err)
	}
}
func TestStopIgnoresCallerCancellationForBoundedCleanup(t *testing.T) {
	m, b, _, _, _, record := installedFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stopped, err := m.Stop(ctx, record.Binding.RunID, "request-cancelled")
	if err != nil || stopped.State != "stopped" || len(b.domains) != 0 {
		t.Fatal("caller cancellation bypassed whole-domain cleanup", err)
	}
}

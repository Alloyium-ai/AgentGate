// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

func outboxDirs(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(dir, "outbox"))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if jobIDPattern.MatchString(e.Name()) {
			out = append(out, e.Name())
		}
	}
	return out
}

// Regression for the second review's finding that H5 kept every completed
// job's outbox directory for the host's lifetime and loaded all of them at
// start. A completed job is compacted into the completed-id set after
// outboxCompactAfter; a re-delivered job is still answered by nothing,
// before and after a restart and after its ledger entry is pruned.
func TestCompactedJobsStayCompletedAcrossRestartAndPrune(t *testing.T) {
	h := newHarness(t)
	h.scripted("stopped", "exited", true)
	job := h.launchJob(specBytes("oneshot", 30, "{}"), nil, nil)
	h.service.send(t, job)
	h.cycle()
	if !h.daemon.Outbox.Completed(job.ID) || len(h.service.results(job.ID)) != 1 {
		t.Fatalf("the job did not complete: %v", h.service.kinds(job.ID))
	}
	events := len(h.service.kinds(job.ID))
	// Within the horizon nothing is compacted.
	h.clock.add(outboxCompactAfter - time.Minute)
	if err := h.daemon.Outbox.Compact(); err != nil {
		t.Fatal(err)
	}
	if dirs := outboxDirs(t, h.dir); len(dirs) != 1 {
		t.Fatalf("compacted within the horizon: %v", dirs)
	}
	h.clock.add(2 * time.Minute)
	if err := h.daemon.Outbox.Compact(); err != nil {
		t.Fatal(err)
	}
	if dirs := outboxDirs(t, h.dir); len(dirs) != 0 {
		t.Fatalf("a completed job's directory outlived the horizon: %v", dirs)
	}
	h.daemon.Outbox.mu.Lock()
	inMemory := len(h.daemon.Outbox.jobs)
	h.daemon.Outbox.mu.Unlock()
	if inMemory != 0 || !h.daemon.Outbox.Completed(job.ID) || !h.daemon.Outbox.Known(job.ID) {
		t.Fatalf("after compaction: %d in memory, completed %v", inMemory, h.daemon.Outbox.Completed(job.ID))
	}
	if _, err := h.daemon.Outbox.Append(job.ID, hostproto.Event{Kind: hostproto.EventProgress, Message: "late"}, false); !errors.Is(err, errJobComplete) {
		t.Fatalf("an event was queued for a compacted job: %v", err)
	}
	unchanged := func(when string) {
		t.Helper()
		if len(h.daemon.Outbox.Pending()) != 0 || len(h.service.kinds(job.ID)) != events || h.runtime.called("run") != 1 || len(outboxDirs(t, h.dir)) != 0 {
			t.Fatalf("%s: the compacted job was reopened: %v", when, h.service.kinds(job.ID))
		}
	}
	h.service.send(t, job)
	h.cycle()
	unchanged("re-delivered")
	h.open()
	h.daemon.Outbox.mu.Lock()
	inMemory = len(h.daemon.Outbox.jobs)
	h.daemon.Outbox.mu.Unlock()
	if inMemory != 0 || !h.daemon.Outbox.Completed(job.ID) {
		t.Fatal("a restart lost the compacted job or loaded it again")
	}
	h.service.send(t, job)
	h.cycle()
	unchanged("re-delivered after a restart")
	// The ledger prunes the entry; the id is still answered by nothing.
	h.clock.add(ledgerRetention + time.Hour)
	if err := h.daemon.Ledger.Prune(ledgerRetention, func(id string) bool { return h.daemon.Outbox.Known(id) && !h.daemon.Outbox.Completed(id) }); err != nil {
		t.Fatal(err)
	}
	if _, err := h.daemon.Ledger.Get(job.ID); err == nil {
		t.Fatal("the ledger kept the compacted job")
	}
	h.service.send(t, job)
	h.cycle()
	unchanged("re-delivered after the ledger prune")
	if _, err := h.daemon.Ledger.Get(job.ID); err == nil {
		t.Fatal("a compacted, pruned job gained a new ledger entry")
	}
	// An unfinished job is never compacted, however old.
	pendingID := fmt.Sprintf("%032x", 7)
	if _, err := h.daemon.Outbox.Append(pendingID, hostproto.Event{Kind: hostproto.EventProgress, Message: "queued"}, false); err != nil {
		t.Fatal(err)
	}
	h.clock.add(10 * outboxCompactAfter)
	if err := h.daemon.Outbox.Compact(); err != nil {
		t.Fatal(err)
	}
	if h.daemon.Outbox.Completed(pendingID) || len(h.daemon.Outbox.Pending()) != 1 {
		t.Fatal("an unacknowledged job was compacted")
	}
}

// completedDir writes a completed job directory as Ack leaves it.
func completedDir(t testing.TB, dir, id string, at time.Time) {
	path := filepath.Join(dir, "outbox", id)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"next": "3", "acked": "3", "completed": strconv.FormatInt(at.UnixMilli(), 10)} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func idBytes(id string) []byte {
	raw, _ := hex.DecodeString(id)
	return raw
}

// Each state a crash can leave a compaction in is repaired by the next open,
// and every job stays completed.
func TestACrashDuringCompactionKeepsEveryJobCompleted(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	old := now.Add(-outboxCompactAfter - time.Hour)
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "outbox"), 0o700); err != nil {
		t.Fatal(err)
	}
	setDir := filepath.Join(base, "outbox", completedIDsDir)
	if err := os.Mkdir(setDir, 0o700); err != nil {
		t.Fatal(err)
	}
	// a: appended and fsynced, the directory not yet removed.
	a := "ab" + fmt.Sprintf("%030x", 1)
	completedDir(t, base, a, old)
	// b: the append was cut short: a partial record ends the shard.
	b := "ab" + fmt.Sprintf("%030x", 2)
	completedDir(t, base, b, old)
	// c: in the set, its directory partly removed.
	c := "cd" + fmt.Sprintf("%030x", 3)
	if err := os.Mkdir(filepath.Join(base, "outbox", c), 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(base, "outbox", c, "acked"), []byte("3"), 0o600)
	// d: the crash came before anything was appended.
	d := "ef" + fmt.Sprintf("%030x", 4)
	completedDir(t, base, d, old)
	// e: completed recently, inside the horizon.
	e := "ef" + fmt.Sprintf("%030x", 5)
	completedDir(t, base, e, now.Add(-time.Hour))
	shardAB := append(append([]byte{}, idBytes(a)...), idBytes(b)[:7]...)
	if err := os.WriteFile(filepath.Join(setDir, "ab"), shardAB, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(setDir, "cd"), idBytes(c), 0o600); err != nil {
		t.Fatal(err)
	}
	// A read-only open (status) changes nothing.
	ro, err := openOutbox(base, clock, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(outboxDirs(t, base)) != 5 || !ro.Completed(a) || !ro.Completed(c) || !ro.Completed(b) || ro.Known(fmt.Sprintf("%032x", 9)) {
		t.Fatal("a read-only open changed the outbox or misread it")
	}
	o, err := openOutbox(base, clock, true)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{a, b, c, d, e} {
		if !o.Completed(id) {
			t.Errorf("%s is not completed after the repair", id)
		}
	}
	if dirs := outboxDirs(t, base); len(dirs) != 1 || dirs[0] != e {
		t.Fatalf("directories after the repair: %v", dirs)
	}
	if len(o.jobs) != 1 || o.jobs[e] == nil {
		t.Fatalf("in memory after the repair: %d", len(o.jobs))
	}
	raw, _ := os.ReadFile(filepath.Join(setDir, "ab"))
	if len(raw)%completedIDSize != 0 || len(raw) != 2*completedIDSize {
		t.Fatalf("the torn shard was not repaired: %d bytes", len(raw))
	}
	// A prefix of a torn record never matches another id.
	if o.Completed("ab" + fmt.Sprintf("%030x", 99)) {
		t.Fatal("an id never completed reads as completed")
	}
}

// Completed jobs leave no directory and no per-job memory, and take 16 bytes
// each on disk; a lookup reads one 1/256 shard. The directory part runs with
// 2000 jobs (AGENTGATE_OUTBOX_FULL=1: 100000, slow on a disk-backed
// temporary directory); the set then grows by 100000 folded ids.
func TestOutboxCompactionBoundsMemoryAndDisk(t *testing.T) {
	dirs := 2000
	if os.Getenv("AGENTGATE_OUTBOX_FULL") == "1" {
		dirs = 100000
	}
	const folded = 100000
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	old := now.Add(-outboxCompactAfter - time.Hour)
	base := t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "outbox"), 0o700); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, dirs+folded)
	for i := range ids {
		ids[i] = fmt.Sprintf("%08x%024x", uint32(i)*2654435761, i)
		if i < dirs {
			completedDir(t, base, ids[i], old)
		}
	}
	o, err := openOutbox(base, clock, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(o.jobs) != 0 || len(outboxDirs(t, base)) != 0 {
		t.Fatalf("%d jobs in memory, %d directories left", len(o.jobs), len(outboxDirs(t, base)))
	}
	o.mu.Lock()
	err = o.fold(append([]string(nil), ids[dirs:]...))
	o.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	again, err := openOutbox(base, clock, true)
	if err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); len(again.jobs) != 0 || grown > 256<<10 {
		t.Fatalf("an open with %d completed jobs keeps %d jobs and %d bytes of heap", len(ids), len(again.jobs), grown)
	}
	var size int64
	shards, _ := os.ReadDir(filepath.Join(base, "outbox", completedIDsDir))
	for _, s := range shards {
		info, _ := s.Info()
		size += info.Size()
	}
	if size != int64(len(ids)*completedIDSize) || len(shards) > 256 {
		t.Fatalf("the completed-id set takes %d bytes in %d shards for %d jobs", size, len(shards), len(ids))
	}
	for _, i := range []int{0, 1, dirs - 1, dirs, len(ids) / 2, len(ids) - 1} {
		if !again.Completed(ids[i]) {
			t.Fatalf("job %d is not completed", i)
		}
	}
	fresh := fmt.Sprintf("%032x", len(ids)+1)
	if again.Completed(fresh) || again.Known(fresh) {
		t.Fatal("a new job reads as completed")
	}
}

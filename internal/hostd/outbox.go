// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// Outbox bounds. Log events are dropped (and the drop recorded) before any
// state or result event could be: the last reservedEvents sequence numbers of
// a job and the space above logSoftLimit are kept for them.
const (
	reservedEvents     = 32
	logSoftLimit       = 128 << 20
	outboxHardLimit    = 512 << 20
	maxStoredEventSize = hostproto.MaxReceiptBytes + 16<<10
	// outboxCompactAfter is how long a completed job keeps its directory:
	// twice hostproto.MaxJobLifetime (50 hours) after the service
	// acknowledged it, so the job's own deadline, and with it every copy the
	// service could still deliver, has long passed. Its id then moves to the
	// completed-id set, which answers Completed for ever.
	outboxCompactAfter = 2 * hostproto.MaxJobLifetime
	// completedIDsDir holds the completed-id set: one append-only shard file
	// per first byte of the id (completed-ids/00 .. ff), each a sequence of
	// 16-byte binary job ids, fsynced before any job directory is removed.
	completedIDsDir = "completed-ids"
	completedIDSize = 16
)

// errJobComplete refuses an event for a job the service already holds whole.
var errJobComplete = errors.New("hostd: the service acknowledged this job as complete; nothing more is queued for it")

// Outbox holds every event until the service acknowledges it, on disk, so a
// receipt survives a daemon restart. Events of one job are numbered from 1
// without gaps, as the protocol requires. A completed job's directory is
// compacted into the completed-id set after outboxCompactAfter, so neither
// disk nor memory grows with every job the host ever ran: memory holds only
// unfinished and recently completed jobs, and a lookup reads one shard.
type Outbox struct {
	mu    sync.Mutex
	dir   string
	bytes int64
	jobs  map[string]*outboxJob
	now   func() time.Time
	// setErr is the last failure to read the completed-id set; while it is
	// set, an id that is not in memory counts as completed (fail closed:
	// never run or reopened) and Compact reports it.
	setErr error
}

type outboxJob struct {
	next, acked uint32
	completed   bool
	completedAt time.Time
	dropped     uint64
}

// openOutbox loads the outbox. Ids already in the completed-id set are not
// loaded; with compact set (the daemon, never a read-only status), a
// directory a crash left behind for such an id is removed, and completed jobs
// past outboxCompactAfter are folded into the set before anything else is
// loaded.
func openOutbox(stateDir string, now func() time.Time, compact bool) (*Outbox, error) {
	dir := filepath.Join(stateDir, "outbox")
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	o := &Outbox{dir: dir, jobs: map[string]*outboxJob{}, now: now}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var fold, leftovers []string
	for _, item := range entries {
		id := item.Name()
		if !jobIDPattern.MatchString(id) {
			continue
		}
		if err = checkPrivateDir(filepath.Join(dir, id)); err != nil {
			return nil, err
		}
		done, setErr := o.inSet(id)
		if setErr != nil {
			return nil, setErr
		}
		if done {
			leftovers = append(leftovers, id)
			continue
		}
		job, size, loadErr := o.loadJob(id)
		if loadErr != nil {
			return nil, loadErr
		}
		if compact && job.completed && now().Sub(job.completedAt) >= outboxCompactAfter {
			fold = append(fold, id)
			continue
		}
		o.jobs[id] = job
		o.bytes += size
	}
	if compact {
		if err := o.removeDirs(leftovers); err != nil {
			return nil, err
		}
		if err := o.fold(fold); err != nil {
			return nil, err
		}
	}
	return o, nil
}

func (o *Outbox) jobDir(id string) string { return filepath.Join(o.dir, id) }

func readCounter(path string) (uint32, error) {
	raw, err := readPrivateFile(path, 32)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
	if err != nil {
		return 0, fmt.Errorf("hostd: outbox counter %s is damaged", path)
	}
	return uint32(value), nil
}

func (o *Outbox) loadJob(id string) (*outboxJob, int64, error) {
	dir := o.jobDir(id)
	job := &outboxJob{}
	var err error
	if job.acked, err = readCounter(filepath.Join(dir, "acked")); err != nil {
		return nil, 0, err
	}
	if job.next, err = readCounter(filepath.Join(dir, "next")); err != nil {
		return nil, 0, err
	}
	if info, statErr := os.Lstat(filepath.Join(dir, "completed")); statErr == nil {
		job.completed, job.completedAt = true, info.ModTime()
		// The marker holds the acknowledgement time (Unix milliseconds);
		// an empty one, from before, is dated by its modification time.
		if raw, readErr := readPrivateFile(filepath.Join(dir, "completed"), 32); readErr == nil && len(raw) > 0 {
			if ms, parseErr := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); parseErr == nil {
				job.completedAt = time.UnixMilli(ms)
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, err
	}
	var size int64
	for _, item := range entries {
		seq, ok := eventSeq(item.Name())
		if !ok {
			continue
		}
		info, infoErr := item.Info()
		if infoErr == nil {
			size += info.Size()
		}
		// A crash between writing an event and its counter: the file wins.
		if seq > job.next {
			job.next = seq
		}
	}
	if job.next < job.acked {
		job.next = job.acked
	}
	return job, size, nil
}

func eventSeq(name string) (uint32, bool) {
	base, ok := strings.CutSuffix(name, ".json")
	if !ok || base == "" || strings.HasPrefix(base, "0") {
		return 0, false
	}
	value, err := strconv.ParseUint(base, 10, 32)
	return uint32(value), err == nil
}

// Append numbers and stores one event. A droppable (log) event is refused when
// the outbox or the job's event budget runs low; it returns false then.
func (o *Outbox) Append(jobID string, event hostproto.Event, droppable bool) (bool, error) {
	if !jobIDPattern.MatchString(jobID) {
		return false, errors.New("hostd: invalid job id")
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	job := o.jobs[jobID]
	if job != nil && job.completed {
		return false, errJobComplete
	}
	if job == nil {
		done, err := o.inSet(jobID)
		if err != nil {
			return false, err
		}
		if done {
			return false, errJobComplete
		}
		if err := ensurePrivateDir(o.jobDir(jobID)); err != nil {
			return false, err
		}
		job = &outboxJob{}
		o.jobs[jobID] = job
	}
	seq := job.next + 1
	if droppable && (o.bytes > logSoftLimit || seq > hostproto.MaxEventsPerJob-reservedEvents) {
		job.dropped++
		return false, nil
	}
	if seq > hostproto.MaxEventsPerJob {
		return false, errors.New("hostd: the job's event budget is exhausted")
	}
	event.Seq = seq
	raw, err := json.Marshal(event)
	if err != nil {
		return false, err
	}
	if len(raw) > maxStoredEventSize || o.bytes+int64(len(raw)) > outboxHardLimit {
		return false, errors.New("hostd: the event exceeds the outbox bounds")
	}
	if err = createFileExclusive(filepath.Join(o.jobDir(jobID), strconv.FormatUint(uint64(seq), 10)+".json"), raw); err != nil {
		return false, err
	}
	job.next = seq
	o.bytes += int64(len(raw))
	return true, writeFileAtomic(filepath.Join(o.jobDir(jobID), "next"), []byte(strconv.FormatUint(uint64(seq), 10)), 0o600)
}

// Dropped returns how many log events of a job were not stored.
func (o *Outbox) Dropped(jobID string) uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if job := o.jobs[jobID]; job != nil {
		return job.dropped
	}
	return 0
}

// Pending lists jobs with unacknowledged events, in a stable order.
func (o *Outbox) Pending() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var out []string
	for id, job := range o.jobs {
		if job.next > job.acked {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// Batch returns the next contiguous unacknowledged events of a job, bounded
// by the protocol's batch limits.
func (o *Outbox) Batch(jobID string) ([]hostproto.Event, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	job := o.jobs[jobID]
	if job == nil {
		return nil, nil
	}
	var out []hostproto.Event
	size := 2
	for seq := job.acked + 1; seq <= job.next && len(out) < hostproto.MaxEventsPerBatch; seq++ {
		raw, err := readPrivateFile(filepath.Join(o.jobDir(jobID), strconv.FormatUint(uint64(seq), 10)+".json"), maxStoredEventSize)
		if err != nil {
			return nil, fmt.Errorf("hostd: outbox event %s/%d: %w", jobID, seq, err)
		}
		var event hostproto.Event
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err = dec.Decode(&event); err != nil || event.Seq != seq {
			return nil, fmt.Errorf("hostd: outbox event %s/%d is damaged", jobID, seq)
		}
		if len(out) > 0 && size+len(raw)+1 > hostproto.MaxEventBatchBytes-1024 {
			break
		}
		size += len(raw) + 1
		out = append(out, event)
		if event.Kind == hostproto.EventResult {
			break // a result event ends its batch
		}
	}
	return out, nil
}

// Ack records the service's acknowledgement and deletes acknowledged events.
func (o *Outbox) Ack(jobID string, through uint32, completed bool) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	job := o.jobs[jobID]
	if job == nil {
		return nil
	}
	if through > job.next {
		return errors.New("hostd: the service acknowledged events this host never sent")
	}
	for seq := job.acked + 1; seq <= through; seq++ {
		path := filepath.Join(o.jobDir(jobID), strconv.FormatUint(uint64(seq), 10)+".json")
		if info, err := os.Stat(path); err == nil {
			o.bytes -= info.Size()
		}
		_ = os.Remove(path)
	}
	if through > job.acked {
		job.acked = through
		if err := writeFileAtomic(filepath.Join(o.jobDir(jobID), "acked"), []byte(strconv.FormatUint(uint64(through), 10)), 0o600); err != nil {
			return err
		}
	}
	if completed && !job.completed && job.acked == job.next {
		job.completed, job.completedAt = true, o.now()
		return createFileExclusive(filepath.Join(o.jobDir(jobID), "completed"), []byte(strconv.FormatInt(job.completedAt.UnixMilli(), 10)))
	}
	return nil
}

// Completed reports whether the service holds every event of a job: a job in
// memory marked completed, or an id in the completed-id set.
func (o *Outbox) Completed(jobID string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if job := o.jobs[jobID]; job != nil {
		return job.completed
	}
	return o.inSetFailClosed(jobID)
}

// Known reports whether a job has any outbox state, including a compacted id.
func (o *Outbox) Known(jobID string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.jobs[jobID] != nil || o.inSetFailClosed(jobID)
}

func (o *Outbox) inSetFailClosed(jobID string) bool {
	done, err := o.inSet(jobID)
	if err != nil {
		o.setErr = err
		return true
	}
	return done
}

func (o *Outbox) shardPath(jobID string) string {
	return filepath.Join(o.dir, completedIDsDir, jobID[:2])
}

// inSet looks jobID up in its shard of the completed-id set. A partial
// record at the end (an append a crash cut short) is ignored; the next fold
// into that shard truncates it.
func (o *Outbox) inSet(jobID string) (bool, error) {
	want, err := hex.DecodeString(jobID)
	if err != nil || len(want) != completedIDSize {
		return false, errors.New("hostd: invalid job id")
	}
	raw, err := readPrivateFile(o.shardPath(jobID), 1<<30)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("hostd: the completed-job set is unreadable: %w", err)
	}
	for i := 0; i+completedIDSize <= len(raw); i += completedIDSize {
		if bytes.Equal(raw[i:i+completedIDSize], want) {
			return true, nil
		}
	}
	return false, nil
}

// Compact folds every completed job older than outboxCompactAfter into the
// completed-id set and removes its directory. It reports a set that could
// not be read since the last call.
func (o *Outbox) Compact() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	setErr := o.setErr
	o.setErr = nil
	now := o.now()
	var fold []string
	for id, job := range o.jobs {
		if job.completed && now.Sub(job.completedAt) >= outboxCompactAfter {
			fold = append(fold, id)
		}
	}
	return errors.Join(setErr, o.fold(fold))
}

// fold appends ids to the completed-id set, fsyncs each shard and the set's
// directory, and only then removes the jobs' directories. A crash before the
// fsync leaves the directories, which the next fold handles again; a crash
// after it leaves directories whose ids are in the set, which the next open
// removes. Either way the job stays completed.
func (o *Outbox) fold(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	setDir := filepath.Join(o.dir, completedIDsDir)
	if err := ensurePrivateDir(setDir); err != nil {
		return err
	}
	sort.Strings(ids)
	shards := map[string][]byte{}
	for _, id := range ids {
		raw, err := hex.DecodeString(id)
		if err != nil || len(raw) != completedIDSize {
			return errors.New("hostd: invalid job id")
		}
		shards[id[:2]] = append(shards[id[:2]], raw...)
	}
	names := make([]string, 0, len(shards))
	for name := range shards {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := appendShard(filepath.Join(setDir, name), shards[name]); err != nil {
			return err
		}
	}
	if err := syncDir(setDir); err != nil {
		return err
	}
	return o.removeDirs(ids)
}

// appendShard appends whole records to one shard: a regular file owned by
// this user, mode 0600, truncated first to a whole number of records.
func appendShard(path string, records []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !ok || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("hostd: the completed-job shard %s is not a private regular file", path)
	}
	if tail := info.Size() % completedIDSize; tail != 0 {
		if err := file.Truncate(info.Size() - tail); err != nil {
			return err
		}
	}
	if _, err := file.Write(records); err != nil {
		return err
	}
	return file.Sync()
}

// removeDirs removes compacted jobs' directories and forgets them.
func (o *Outbox) removeDirs(ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	for _, id := range ids {
		if err := os.RemoveAll(o.jobDir(id)); err != nil {
			return err
		}
		delete(o.jobs, id)
	}
	return syncDir(o.dir)
}

// Bytes is the stored event volume.
func (o *Outbox) Bytes() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.bytes
}

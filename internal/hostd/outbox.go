// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

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
)

// Outbox holds every event until the service acknowledges it, on disk, so a
// receipt survives a daemon restart. Events of one job are numbered from 1
// without gaps, as the protocol requires.
type Outbox struct {
	mu    sync.Mutex
	dir   string
	bytes int64
	jobs  map[string]*outboxJob
}

type outboxJob struct {
	next, acked uint32
	completed   bool
	dropped     uint64
}

func openOutbox(stateDir string) (*Outbox, error) {
	dir := filepath.Join(stateDir, "outbox")
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	o := &Outbox{dir: dir, jobs: map[string]*outboxJob{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, item := range entries {
		if !jobIDPattern.MatchString(item.Name()) {
			continue
		}
		if err = checkPrivateDir(filepath.Join(dir, item.Name())); err != nil {
			return nil, err
		}
		job, size, loadErr := o.loadJob(item.Name())
		if loadErr != nil {
			return nil, loadErr
		}
		o.jobs[item.Name()] = job
		o.bytes += size
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
	_, statErr := os.Stat(filepath.Join(dir, "completed"))
	job.completed = statErr == nil
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
	if job == nil {
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
		job.completed = true
		return createFileExclusive(filepath.Join(o.jobDir(jobID), "completed"), nil)
	}
	return nil
}

// Completed reports whether the service holds every event of a job.
func (o *Outbox) Completed(jobID string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	job := o.jobs[jobID]
	return job != nil && job.completed
}

// Known reports whether a job has any outbox state.
func (o *Outbox) Known(jobID string) bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.jobs[jobID] != nil
}

// Bytes is the stored event volume.
func (o *Outbox) Bytes() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.bytes
}

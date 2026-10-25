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
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// Ledger states of one job on this host.
const (
	JobAccepted = "accepted" // recorded durably before anything ran
	JobRunning  = "running"
	JobDone     = "done"
)

var jobIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// LedgerEntry is the durable record of one job id. A job id runs at most once:
// the entry exists before execution starts, and a repeat returns the result.
type LedgerEntry struct {
	JobID        string               `json:"job_id"`
	Type         string               `json:"type"`
	LaunchID     string               `json:"launch_id,omitempty"`
	SpecDigest   string               `json:"spec_digest,omitempty"`
	PolicyDigest string               `json:"policy_digest,omitempty"`
	State        string               `json:"state"`
	DeadlineMS   int64                `json:"deadline_ms"`
	AcceptedAtMS int64                `json:"accepted_at_ms"`
	UpdatedAtMS  int64                `json:"updated_at_ms"`
	Result       *hostproto.JobResult `json:"result,omitempty"`
}

// Ledger stores one file per job id.
type Ledger struct {
	mu  sync.Mutex
	dir string
	now func() time.Time
}

func openLedger(stateDir string, now func() time.Time) (*Ledger, error) {
	dir := filepath.Join(stateDir, "ledger")
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	return &Ledger{dir: dir, now: now}, nil
}

func (l *Ledger) path(id string) string { return filepath.Join(l.dir, id+".json") }

// Begin records a new job. It returns the existing entry and false for a job
// id this host has seen before.
func (l *Ledger) Begin(entry LedgerEntry) (LedgerEntry, bool, error) {
	if !jobIDPattern.MatchString(entry.JobID) {
		return entry, false, errors.New("hostd: invalid job id")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	entry.State = JobAccepted
	entry.AcceptedAtMS = l.now().UnixMilli()
	entry.UpdatedAtMS = entry.AcceptedAtMS
	raw, err := json.Marshal(entry)
	if err != nil {
		return entry, false, err
	}
	err = createFileExclusive(l.path(entry.JobID), raw)
	if errors.Is(err, os.ErrExist) {
		existing, loadErr := l.load(entry.JobID)
		return existing, false, loadErr
	}
	return entry, err == nil, err
}

func (l *Ledger) load(id string) (LedgerEntry, error) {
	var entry LedgerEntry
	raw, err := readPrivateFile(l.path(id), 1<<20)
	if err != nil {
		return entry, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&entry); err != nil || entry.JobID != id {
		return entry, fmt.Errorf("hostd: ledger entry %s is damaged", id)
	}
	return entry, nil
}

// Get returns one entry.
func (l *Ledger) Get(id string) (LedgerEntry, error) {
	if !jobIDPattern.MatchString(id) {
		return LedgerEntry{}, errors.New("hostd: invalid job id")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.load(id)
}

// Update changes the state and, for done, the result.
func (l *Ledger) Update(id, state string, result *hostproto.JobResult) (LedgerEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, err := l.load(id)
	if err != nil {
		return entry, err
	}
	if entry.State == JobDone {
		return entry, errors.New("hostd: a finished job never changes")
	}
	entry.State, entry.Result, entry.UpdatedAtMS = state, result, l.now().UnixMilli()
	raw, err := json.Marshal(entry)
	if err != nil {
		return entry, err
	}
	return entry, writeFileAtomic(l.path(id), raw, 0o600)
}

// Unfinished lists entries that were accepted or running when the host stopped.
func (l *Ledger) Unfinished() ([]LedgerEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	names, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, err
	}
	var out []LedgerEntry
	for _, item := range names {
		id, ok := strings.CutSuffix(item.Name(), ".json")
		if !ok || !jobIDPattern.MatchString(id) {
			continue
		}
		entry, loadErr := l.load(id)
		if loadErr != nil {
			return nil, loadErr
		}
		if entry.State != JobDone {
			out = append(out, entry)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AcceptedAtMS < out[j].AcceptedAtMS })
	return out, nil
}

// LaunchResult returns the latest finished result for a launch id, if any.
func (l *Ledger) LaunchResult(launchID string) (*LedgerEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	names, err := os.ReadDir(l.dir)
	if err != nil {
		return nil, err
	}
	var best *LedgerEntry
	for _, item := range names {
		id, ok := strings.CutSuffix(item.Name(), ".json")
		if !ok || !jobIDPattern.MatchString(id) {
			continue
		}
		entry, loadErr := l.load(id)
		if loadErr != nil || entry.LaunchID != launchID || entry.Type != hostproto.JobLaunch {
			continue
		}
		if best == nil || entry.UpdatedAtMS > best.UpdatedAtMS {
			found := entry
			best = &found
		}
	}
	return best, nil
}

// Prune removes finished entries whose deadline passed more than retain ago:
// a replay of such a job fails its deadline check anyway.
func (l *Ledger) Prune(retain time.Duration, keep func(string) bool) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	names, err := os.ReadDir(l.dir)
	if err != nil {
		return err
	}
	cutoff := l.now().Add(-retain).UnixMilli()
	for _, item := range names {
		id, ok := strings.CutSuffix(item.Name(), ".json")
		if !ok || !jobIDPattern.MatchString(id) {
			continue
		}
		entry, loadErr := l.load(id)
		if loadErr == nil && entry.State == JobDone && entry.DeadlineMS < cutoff && !keep(id) {
			_ = os.Remove(l.path(id))
		}
	}
	return nil
}

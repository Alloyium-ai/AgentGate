// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/kernel"
	"context"
	"errors"
	"testing"
)

func TestFinalCountersSurviveCleanupAndPersistenceRetry(t *testing.T) {
	s := collector{name: "files", order: orderedStream{next: 2}}
	reads, writes := 0, 0
	closed := false
	read := func() (kernel.Counters, error) {
		reads++
		if closed {
			return kernel.Counters{}, errors.New("removed map")
		}
		return kernel.Counters{Decisions: 1}, nil
	}
	persist := func(_ context.Context, name string, v jobaudit.FinalCounters) error {
		writes++
		if name != "files" || !v.Available || v.Sequence != 1 || v.Decisions != 1 {
			t.Fatal(name, v)
		}
		if writes == 1 {
			return context.DeadlineExceeded
		}
		return nil
	}
	first, err := s.finish(context.Background(), read, persist)
	if !errors.Is(err, context.DeadlineExceeded) || first == nil {
		t.Fatal(first, err)
	}
	closed = true
	first.Sequence = 99
	for i := 0; i < 2; i++ {
		v, e := s.finish(context.Background(), read, persist)
		if e != nil || v.Sequence != 1 {
			t.Fatal(v, e)
		}
	}
	if reads != 1 || writes != 2 {
		t.Fatal("cleanup retry reread a removed map or repeated final persistence", reads, writes)
	}
}

func TestFinalLossStaysIncompleteOnCleanupRetry(t *testing.T) {
	s := collector{name: "syscalls", order: orderedStream{next: 2}}
	reads, writes := 0, 0
	read := func() (kernel.Counters, error) { reads++; return kernel.Counters{Decisions: 2, Lost: 1}, nil }
	persist := func(_ context.Context, _ string, v jobaudit.FinalCounters) error {
		writes++
		if v.Decisions != 0 || v.Sequence != 2 || v.Lost != 1 {
			t.Fatal(v)
		}
		return jobaudit.ErrIncomplete
	}
	for i := 0; i < 2; i++ {
		v, err := s.finish(context.Background(), read, persist)
		if v == nil || !errors.Is(err, jobaudit.ErrIncomplete) {
			t.Fatal(v, err)
		}
	}
	if reads != 1 || writes != 1 {
		t.Fatal(reads, writes)
	}
}

func TestMissingFinalCountersStayUnavailable(t *testing.T) {
	s := collector{name: "files"}
	read := func() (kernel.Counters, error) { return kernel.Counters{}, errors.New("closed runtime") }
	persist := func(context.Context, string, jobaudit.FinalCounters) error {
		t.Fatal("missing counters were persisted as available")
		return nil
	}
	if v, err := s.finish(context.Background(), read, persist); v != nil || err == nil || s.final != nil {
		t.Fatal(v, err)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"errors"
	"testing"
)

type fixtureExit int

func (e fixtureExit) Error() string { return "owned helper exit" }
func (e fixtureExit) ExitCode() int { return int(e) }
func TestBrokerExitRequiresAProvedDeadHelper(t *testing.T) {
	for _, dead := range []bool{false, true} {
		done := make(chan error, 1)
		done <- fixtureExit(9)
		err, reaped := brokerExitResult(context.Background(), func() (bool, error) { return dead, nil }, done)
		if reaped != dead {
			t.Fatal("the broker exit changed helper custody", dead, reaped)
		}
		if dead && childExitCode(err) != 9 {
			t.Fatal("the actual helper exit code disappeared", err)
		}
		if !dead && err == nil {
			t.Fatal("a dead broker left a live helper")
		}
	}
	done := make(chan error, 1)
	done <- nil
	failure := errors.New("PIDFD verification failed")
	if err, reaped := brokerExitResult(context.Background(), func() (bool, error) { return false, failure }, done); reaped || !errors.Is(err, failure) {
		t.Fatal("unverified helper exit passed", err)
	}
}
func TestBrokerExitKeepsReapingBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err, reaped := brokerExitResult(ctx, func() (bool, error) { return true, nil }, make(chan error))
	if reaped || !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost its bounded wait", err)
	}
}
func TestLateReapingPreservesTheDurableStop(t *testing.T) {
	r := &run{exitCode: -1}
	if saveChildExit(r, fixtureExit(9)) != 9 || r.exitCode != 9 {
		t.Fatal("the helper status was not retained")
	}
	r.stopped = &lifecycle.Evidence{}
	if saveChildExit(r, nil) != 0 || r.exitCode != 9 {
		t.Fatal("late status changed a stopped record")
	}
}

func TestIndependentStopEvictionKeepsTheDurableTerminalPath(t *testing.T) {
	for _, test := range []struct {
		contextErr, waitErr error
		r                   *run
		want                string
	}{
		{nil, kernelExpired{}, nil, "grant-expired"},
		{nil, errors.New("a stopped broker"), nil, "runtime-monitor-failed"},
		{nil, fixtureExit(9), &run{exitCode: 9}, "completed"},
		{nil, nil, nil, "completed"},
		{context.Canceled, kernelExpired{}, nil, "cancelled"},
	} {
		if got := stopReasonAfterWait(test.contextErr, test.waitErr, test.r); got != test.want {
			t.Fatal(got, test.want)
		}
	}
}

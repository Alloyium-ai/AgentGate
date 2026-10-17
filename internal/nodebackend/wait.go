// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"errors"
	"time"
)

func stopReasonAfterWait(contextErr, waitErr error, r *run) string {
	if contextErr != nil {
		return "cancelled"
	}
	if waitErr == nil {
		return "completed"
	}
	var cause lifecycle.LifecycleStopReason
	if errors.As(waitErr, &cause) && cause.LifecycleStopReason() == lifecycle.GrantExpired {
		return string(lifecycle.GrantExpired)
	}
	if r != nil {
		r.mu.Lock()
		exited := r.exitCode >= 0
		r.mu.Unlock()
		if exited {
			return "completed"
		}
	}
	return "runtime-monitor-failed"
}

// brokerExitResult accepts a closed broker only after the exact helper PIDFD
// confirms exit. It gives the supervisor a bounded interval to publish wait status.
func brokerExitResult(ctx context.Context, exited func() (bool, error), done <-chan error) (error, bool) {
	dead, err := exited()
	if err != nil || !dead {
		return errors.Join(errors.New("the exec broker stopped while the helper remained active or unverified"), err), false
	}
	limit := time.NewTimer(time.Second)
	defer limit.Stop()
	select {
	case result := <-done:
		return result, true
	case <-ctx.Done():
		return ctx.Err(), false
	case <-limit.C:
		return errors.New("the exited helper wait status is unavailable"), false
	}
}
func childExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exit interface{ ExitCode() int }
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return 1
}
func saveChildExit(r *run, err error) int {
	code := childExitCode(err)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped == nil {
		r.exitCode = code
	}
	return code
}

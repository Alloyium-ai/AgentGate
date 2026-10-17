// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package execbroker

import (
	"alloyium.local/kernel-poc/internal/fsrules"
	"errors"
	"golang.org/x/sys/unix"
	"testing"
)

func TestDurableWriteCannotExtendHeapCutoff(t *testing.T) {
	for _, change := range []string{"deadline", "policy", "membership", "clock", "writer", "policy-delay"} {
		t.Run(change, func(t *testing.T) {
			c := Config{DeadlineNS: 100, Files: fsrules.State{Memory: 32}}
			n := Notification{ID: 1, PID: 42, Data: Data{Number: unix.SYS_BRK, Architecture: unix.AUDIT_ARCH_X86_64}}
			now := uint64(99)
			changed := false
			var records []Decision
			clock := func() (uint64, error) {
				if changed && change == "clock" {
					return 0, errors.New("clock unavailable")
				}
				return now, nil
			}
			member := func(int) error {
				if changed && change == "membership" {
					return errors.New("foreign task")
				}
				return nil
			}
			installed := func() error {
				if changed && change == "policy-delay" {
					now = 100
				}
				if changed && change == "policy" {
					return errors.New("missing map")
				}
				return nil
			}
			emit := func(d Decision) error {
				records = append(records, d)
				changed = true
				if change == "deadline" {
					now = 100
				}
				if change == "writer" {
					return errors.New("disk failure")
				}
				return nil
			}
			response, err := responseFor(c, n, clock, member, installed, emit)
			if response.Flags != 0 || response.Error != -int32(unix.EPERM) {
				t.Fatal("a changed live binding continued")
			}
			if (change == "clock" || change == "writer") && err == nil {
				t.Fatal("a failed custody check was hidden")
			}
			if err == nil && (len(records) != 2 || records[1].Continued) {
				t.Fatal("the final denial was not durable")
			}
		})
	}
}
func TestLiveHeapResponseRetainsContinuation(t *testing.T) {
	c := Config{DeadlineNS: 100, Files: fsrules.State{Memory: 32}}
	n := Notification{ID: 1, PID: 42, Data: Data{Number: unix.SYS_BRK, Architecture: unix.AUDIT_ARCH_X86_64}}
	calls := 0
	response, err := responseFor(c, n, func() (uint64, error) { return 99, nil }, func(int) error { return nil }, func() error { return nil }, func(d Decision) error {
		calls++
		if d.Reason != "continue-live-heap" {
			t.Fatal(d)
		}
		return nil
	})
	if err != nil || response.Flags != unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE || response.Error != 0 || calls != 1 {
		t.Fatal(response, err, calls)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestStopRetryKeepsTheDurableCause(t *testing.T) {
	for _, reason := range []string{"grant-expired", "revoked", "client-stop", "completed"} {
		t.Run(reason, func(t *testing.T) {
			m, b, _, _, journal, r := installedFixture(t)
			ctx := context.Background()
			if _, err := m.Release(ctx, r.Binding.RunID); err != nil {
				t.Fatal(err)
			}
			actual := &reasonBackend{testBackend: b}
			m.backend = actual
			m.journal = delayedStopJournal{Journal: journal, stopError: context.DeadlineExceeded}
			if _, err := m.Stop(ctx, r.Binding.RunID, reason); !errors.Is(err, context.DeadlineExceeded) {
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
			pending, err := reopened.Lookup(ctx, r.Binding.RunID)
			if err != nil || pending.State != "stop-pending" || pending.StopReason != reason {
				t.Fatal(pending, err)
			}
			m.journal = reopened
			stopped, err := m.Stop(ctx, r.Binding.RunID, "termination-retry")
			if err != nil || stopped.State != "stopped" || stopped.StopReason != reason || !reflect.DeepEqual(actual.reasons, []string{reason, reason}) {
				t.Fatal(stopped, actual.reasons, err)
			}
		})
	}
}

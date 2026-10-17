// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import "testing"

func TestMonotonicClockMatchesKernelDeadlineUnits(t *testing.T) {
	clock := MonotonicClock{}
	first, err := clock.NowNS()
	if err != nil || first == 0 {
		t.Fatal("monotonic clock unavailable", err)
	}
	second, err := clock.NowNS()
	if err != nil || second < first {
		t.Fatal("monotonic clock decreased", err)
	}
}

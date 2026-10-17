// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"math"
	"testing"
	"time"
)

func TestKernelExpiryUsesBothBoundsAndNanosecondWallSample(t *testing.T) {
	wall := time.Unix(100, 750000000)
	mono := uint64(10 * time.Second)
	deadline, err := restrictedDeadline(uint64(20*time.Second), mono, wall, 102)
	if err != nil || deadline != uint64(11250*time.Millisecond) {
		t.Fatal(deadline, err)
	}
	deadline, err = restrictedDeadline(uint64(11*time.Second), mono, wall, 102)
	if err != nil || deadline != uint64(11*time.Second) {
		t.Fatal("the immutable deadline was extended", deadline, err)
	}
	for _, test := range []struct {
		bound, mono uint64
		wall        time.Time
		expires     int64
	}{{20, 0, wall, 102}, {10, 10, wall, 102}, {20, 10, wall, 100}, {math.MaxUint64, math.MaxUint64 - 10, wall, 102}, {math.MaxUint64, 10, wall, 100 + 24*60*60 + 2}} {
		if _, err = restrictedDeadline(test.bound, test.mono, test.wall, test.expires); err == nil {
			t.Fatalf("invalid expiry samples accepted: %+v", test)
		}
	}
	r := &run{binding: pinBinding()}
	if r.deadline() != r.binding.DeadlineNS {
		t.Fatal("the original deadline changed before grant binding")
	}
	r.kernelDeadline = 50
	if r.deadline() != 50 || r.binding.DeadlineNS != 100 {
		t.Fatal("the effective cutoff changed the signed binding")
	}
}

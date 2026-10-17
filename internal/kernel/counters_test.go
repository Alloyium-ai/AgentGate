// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package kernel

import (
	"github.com/cilium/ebpf"
	"testing"
)

func TestUnavailableCountersReturnAnError(t *testing.T) {
	for _, r := range []*Runtime{nil, {}, {Collection: &ebpf.Collection{Maps: map[string]*ebpf.Map{}}}} {
		value, err := r.Counters()
		if err == nil || value != (Counters{}) {
			t.Fatal("unavailable counters acquired a value", value, err)
		}
	}
}

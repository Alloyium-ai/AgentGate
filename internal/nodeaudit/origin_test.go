// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeaudit

import "testing"

func TestCorrelatedOriginKeepsRawNumberAndNoPolicyDecision(t *testing.T) {
	raw := fixture("syscalls/syscalls128.v2")
	put64(raw, 48, ^uint64(0))
	put32(raw, 92, 1)
	put64(raw, 104, 15)
	put64(raw, 112, 900)
	put32(raw, 124, 2)
	out, err := Registry()["syscalls/syscalls128.v2"](raw)
	if err != nil || out.Decision != nil {
		t.Fatal("valid origin acquired a decision or failed", err)
	}
	if u64(raw, 48) != ^uint64(0) {
		t.Fatal("raw number was rewritten")
	}
	if _, err = Registry()["syscalls/syscalls104.v1"](raw); err == nil {
		t.Fatal("new bytes acquired a legacy stream identity")
	}
	put32(raw, 124, 0)
	if _, err = Registry()["syscalls/syscalls128.v2"](raw); err == nil {
		t.Fatal("missing origin completed")
	}
}

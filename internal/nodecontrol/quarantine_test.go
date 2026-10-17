// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodecontrol

import (
	"alloyium.local/kernel-poc/internal/enforcement"
	"fmt"
	"strings"
	"testing"
)

func TestQuarantineControlRequiresExactZeroTables(t *testing.T) {
	binding, _ := boundFixture()
	for i := 0; i < 63; i++ {
		binding.ArtifactDigests[strings.Repeat("a", 120)+fmt.Sprintf("%07d", i)] = strings.Repeat("a", 64)
	}
	q := enforcement.QuarantineReadback{Domain: binding.CgroupID, MapIDs: map[string]uint32{}, Markers: map[string]uint32{}}
	for i, name := range []string{"files/policies", "files/owned", "peers/net_policies", "sockets/sock_policies", "sockets/sock_managed", "custody/cust_bindings", "custody/cust_managed", "process/proc_policies", "process/proc_managed"} {
		q.MapIDs[name] = uint32(i + 1)
	}
	for _, name := range []string{"files/owned", "sockets/sock_managed", "custody/cust_managed", "process/proc_managed"} {
		q.Markers[name] = 1
	}
	wire, err := q.Wire()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Encode(binding, "quarantine_readback", wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 65536 {
		t.Fatalf("the baseline exceeds the actual audit bound: %d", len(raw))
	}
	if result, err := Decoder(binding)(raw); err != nil || result.ControlPhase != "quarantine_readback" {
		t.Fatal(result, err)
	}
	q.Files.Memory = 32
	wire, err = q.Wire()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Encode(binding, "quarantine_readback", wire); err == nil {
		t.Fatal("a heap allowance masqueraded as the baseline")
	}
}

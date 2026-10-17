// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodecontrol

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func boundFixture() (lifecycle.Binding, jobaudit.GrantExpiry) {
	b := lifecycle.Binding{AgentID: "agent-one", AgentKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), JobDigest: strings.Repeat("a", 64), GrantID: "grant-one", RunID: "run-one", NodeID: "node-one", BootID: "boot-one", PolicyDigest: strings.Repeat("b", 64), SchemaDigest: strings.Repeat("c", 64), CompilerDigest: strings.Repeat("d", 64), ArtifactDigests: map[string]string{"kernel": strings.Repeat("e", 64)}, CgroupID: 100, Generation: 1, DeadlineNS: 10000000000}
	return b, jobaudit.GrantExpiry{ExpiresAt: 20, WallSampleUnixNS: 19000000000, MonoSampleNS: 100, MonoAfterNS: 200, KernelDeadlineNS: 1000000100}
}
func TestExpiryControlRetainsExactSignedClockFacts(t *testing.T) {
	b, g := boundFixture()
	raw, err := Encode(b, "grant_expiry_bound", g)
	if err != nil {
		t.Fatal(err)
	}
	o, err := Decoder(b)(raw)
	if err != nil || o.ControlPhase != "grant_expiry_bound" || o.GrantExpiry == nil || *o.GrantExpiry != g || o.Decision != nil || o.CgroupID != b.CgroupID || o.Generation != b.Generation {
		t.Fatal("the expiry facts changed", err)
	}
	raw, err = Encode(b, "prepared", g)
	if err != nil {
		t.Fatal(err)
	}
	o, err = Decoder(b)(raw)
	if err != nil || o.GrantExpiry != nil {
		t.Fatal("an unrelated control became expiry evidence", err)
	}
}
func TestExpiryControlRejectsAmbiguousNumbersAndClockShape(t *testing.T) {
	b, g := boundFixture()
	raw, _ := Encode(b, "grant_expiry_bound", g)
	for _, name := range []string{"number", "alias", "duplicate", "unknown", "wrong-cutoff", "binding"} {
		t.Run(name, func(t *testing.T) {
			wire := string(raw)
			switch name {
			case "number":
				wire = strings.Replace(wire, `"mono_sample_ns":"100"`, `"mono_sample_ns":100`, 1)
			case "alias":
				wire = strings.Replace(wire, `"mono_sample_ns"`, `"Mono_Sample_NS"`, 1)
			case "duplicate":
				wire = strings.Replace(wire, `"mono_sample_ns":"100"`, `"mono_sample_ns":"100","mono_sample_ns":"101"`, 1)
			case "unknown":
				wire = strings.Replace(wire, `"expires_at":20`, `"expires_at":20,"other":1`, 1)
			case "wrong-cutoff":
				wire = strings.Replace(wire, `"kernel_deadline_ns":"1000000100"`, `"kernel_deadline_ns":"1000000101"`, 1)
			case "binding":
				var record Record
				json.Unmarshal(raw, &record)
				record.Binding.Generation++
				changed, _ := json.Marshal(record)
				wire = string(changed)
			}
			if wire == string(raw) {
				t.Fatal("the negative fixture did not change")
			}
			if _, err := Decoder(b)([]byte(wire)); err == nil {
				t.Fatal("the invalid expiry control passed")
			}
		})
	}
}

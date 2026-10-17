// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"encoding/json"
	"strings"
	"testing"
)

func TestControlDecoderKeepsTheExactBinding(t *testing.T) {
	c := nodecontrol.Record{Protocol: nodecontrol.Protocol, Binding: pinBinding(), Phase: "installed", Payload: json.RawMessage(`{"plan":"measured"}`)}
	decode := nodecontrol.Decoder(c.Binding)
	raw, _ := json.Marshal(c)
	got, err := decode(raw)
	if err != nil || got.CgroupID != 42 || got.Generation != 1 || got.Decision != nil || got.Sequence != 0 {
		t.Fatal(got, err)
	}
	bad := strings.TrimSuffix(string(raw), "}") + `,"phase":"released"}`
	if _, err = decode([]byte(bad)); err == nil {
		t.Fatal("a duplicate control field was accepted")
	}
	raw, _ = json.Marshal(map[string]any{"protocol": c.Protocol, "binding": c.Binding, "phase": c.Phase, "payload": map[string]int{}, "allowed": true})
	if _, err = decode(raw); err == nil {
		t.Fatal("an unknown permission claim was accepted")
	}
	c.Binding.AgentID = "other"
	raw, _ = json.Marshal(c)
	if _, err = decode(raw); err == nil {
		t.Fatal("a foreign full binding was accepted")
	}
}

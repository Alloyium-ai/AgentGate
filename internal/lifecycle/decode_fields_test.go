// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestTransportRejectsCaseFoldedFieldsAtEveryTypedDepth(t *testing.T) {
	type Item struct {
		AgentID string `json:"agent_id"`
	}
	type DTO struct {
		Protocol string          `json:"protocol"`
		Binding  Item            `json:"binding"`
		Items    []Item          `json:"items"`
		Registry map[string]Item `json:"registry"`
	}
	for _, raw := range []string{
		`{"Protocol":"one"}`, `{"protocol":"one","Protocol":"two"}`, `{"binding":{"Agent_ID":"one"}}`, `{"binding":{"agent_id":"one","Agent_ID":"two"}}`, `{"items":[{"Agent_ID":"one"}]}`, `{"registry":{"FreeKey":{"Agent_ID":"one"}}}`,
	} {
		var value DTO
		if DecodeTransport(strings.NewReader(raw), &value) == nil {
			t.Fatal("a case-folded field alias passed", raw)
		}
	}
	var valid DTO
	if err := DecodeTransport(strings.NewReader(`{"protocol":"one","binding":{"agent_id":"agent"},"items":[{"agent_id":"child"}],"registry":{"FreeKey":{"agent_id":"one"},"freekey":{"agent_id":"two"}}}`), &valid); err != nil {
		t.Fatal(err)
	}
	if len(valid.Registry) != 2 || valid.Registry["FreeKey"].AgentID != "one" || valid.Registry["freekey"].AgentID != "two" {
		t.Fatal("free map keys were normalized")
	}
}
func TestTransportLeavesOpaqueRawMessagesToTheirSchema(t *testing.T) {
	type DTO struct {
		Raw   json.RawMessage   `json:"raw"`
		Keys  map[string]string `json:"keys"`
		Bytes []byte            `json:"bytes"`
	}
	var value DTO
	if err := DecodeTransport(strings.NewReader(`{"raw":{"Agent_ID":"one","agent_id":"two"},"keys":{"Agent_ID":"one","agent_id":"two"},"bytes":"AQI="}`), &value); err != nil {
		t.Fatal(err)
	}
	if len(value.Keys) != 2 || len(value.Bytes) != 2 || string(value.Raw) != `{"Agent_ID":"one","agent_id":"two"}` {
		t.Fatal("opaque data changed")
	}
	if DecodeTransport(strings.NewReader(`{"raw":{"same":1,"same":2}}`), &value) == nil {
		t.Fatal("opaque values bypassed duplicate-key rejection")
	}
}
func TestTransportExactNamesFollowEmbeddedAndTaggedStructs(t *testing.T) {
	type Inner struct{ ExactName string }
	type DTO struct {
		Inner
		Tagged *Inner `json:"tagged"`
		Hidden string `json:"-"`
	}
	var value DTO
	if err := DecodeTransport(strings.NewReader(`{"ExactName":"one","tagged":{"ExactName":"two"}}`), &value); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"exactname":"one"}`, `{"tagged":{"exactname":"two"}}`, `{"Hidden":"hidden"}`} {
		if DecodeTransport(strings.NewReader(raw), &value) == nil {
			t.Fatal("an undeclared exact field passed")
		}
	}
}

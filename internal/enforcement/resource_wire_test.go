// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestResourceWireRetainsExactTablesWithinAuditBound(t *testing.T) {
	q := quarantineFixture()
	wire, err := q.Wire()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 50000 {
		t.Fatalf("the table readback leaves insufficient room for the binding: %d", len(raw))
	}
	got, err := wire.Tables()
	if err != nil || !reflect.DeepEqual(q, got) || wire.Validate() != nil {
		t.Fatal("the table readback changed", err)
	}
	wire.MapIDs["files/policies"]++
	if q.MapIDs["files/policies"] == wire.MapIDs["files/policies"] {
		t.Fatal("the wire aliases mutable source maps")
	}
	wire.Files = wire.Files[:543]
	if wire.Validate() == nil {
		t.Fatal("a truncated map value passed")
	}
}

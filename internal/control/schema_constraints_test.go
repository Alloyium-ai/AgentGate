// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func parseSchemaFixture(t *testing.T, raw string) any {
	t.Helper()
	var value any
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSchemaConstraintBoundaries(t *testing.T) {
	schema := parseSchemaFixture(t, `{"type":"object","required":["rights"],"additionalProperties":false,"properties":{"description":{"type":"string","minLength":2,"maxLength":5,"pattern":"^[a-z]+$"},"scopes":{"type":"array","minItems":1,"maxItems":2,"uniqueItems":true,"items":{"type":"string","enum":["read","write"]}},"rights":{"$ref":"#/components/schemas/Rights"},"limit":{"type":"integer","minimum":1,"maximum":3}}}`).(map[string]any)
	refs := map[string]any{"Rights": parseSchemaFixture(t, `{"type":"object","required":["enabled"],"additionalProperties":false,"properties":{"enabled":{"type":"boolean"}}}`)}
	valid := []string{`{"rights":{"enabled":false}}`, `{"rights":{"enabled":true},"description":"aa","scopes":["read"],"limit":1}`, `{"rights":{"enabled":false},"description":"abcde","scopes":["read","write"],"limit":3}`}
	for _, data := range valid {
		if err := validateSchemaValue(parseSchemaFixture(t, data), schema, refs, 0); err != nil {
			t.Fatalf("valid boundary %s: %v", data, err)
		}
	}
	bad := []string{
		`{"rights":{"enabled":false},"description":null}`, `{"rights":{"enabled":false},"description":7}`,
		`{"rights":{"enabled":false},"description":"a"}`, `{"rights":{"enabled":false},"description":"abcdef"}`, `{"rights":{"enabled":false},"description":"AA"}`,
		`{"rights":{"enabled":false},"scopes":null}`, `{"rights":{"enabled":false},"scopes":[]}`, `{"rights":{"enabled":false},"scopes":["read","write","read"]}`,
		`{"rights":{"enabled":false},"scopes":["read",false]}`, `{"rights":{"enabled":false},"scopes":["admin"]}`, `{"rights":{"enabled":false},"scopes":["read","read"]}`,
		`{"rights":null}`, `{"rights":[]}`, `{"rights":{"enabled":"false"}}`, `{"rights":{"enabled":false,"extra":1}}`,
		`{"rights":{"enabled":false},"limit":0}`, `{"rights":{"enabled":false},"limit":4}`, `{"rights":{"enabled":false},"limit":1.5}`, `{"rights":{"enabled":false},"extra":1}`,
	}
	for _, data := range bad {
		if err := validateSchemaValue(parseSchemaFixture(t, data), schema, refs, 0); err == nil {
			t.Errorf("accepted invalid constraint: %s", data)
		}
	}
}

func TestRuntimeSchemaSuppliedValues(t *testing.T) {
	base := []byte(`{"name":"Schema fixture","description":"valid","rights":{"workspace_write":false,"tcp_address":"127.0.0.1","tcp_port":18081},"reason":"Test runtime schema values"}`)
	for _, oldNew := range [][2]string{{`"valid"`, `null`}, {`"workspace_write":false`, `"workspace_write":"false"`}, {`"tcp_address":"127.0.0.1"`, `"tcp_address":"0.0.0.0"`}, {`"tcp_port":18081`, `"tcp_port":18083`}} {
		data := bytes.Replace(base, []byte(oldNew[0]), []byte(oldNew[1]), 1)
		if err := decodeBody(data, &CreatePolicy{}); err == nil {
			t.Errorf("accepted %s", data)
		}
	}
	for _, count := range []int{0, 16, 17} {
		scopes := make([]string, count)
		for i := range scopes {
			scopes[i] = "policy:read"
		}
		data, _ := json.Marshal(Service{Subject: "schema-agent", Kind: "agent", PublicKey: "public", Scopes: scopes})
		err := decodeBody(data, &Service{})
		if count <= 16 && err != nil || count > 16 && err == nil {
			t.Errorf("scope count %d: %v", count, err)
		}
	}
	if err := decodeBody([]byte(`{"enabled":false,"reason":"An explicit false remains valid"}`), &ServiceStatus{}); err != nil {
		t.Fatal(err)
	}
}

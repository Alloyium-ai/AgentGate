// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package control

import (
	"encoding/json"
	"testing"
)

func TestRequiredOpenAPIFieldsMatchRuntime(t *testing.T) {
	cases := []struct {
		name   string
		value  any
		newDTO func() any
	}{
		{"CreatePolicy", CreatePolicy{"Valid policy", "", Rights{true, "127.0.0.1", 18081}, "Test required policy fields"}, func() any { return &CreatePolicy{} }},
		{"EditVersion", EditVersion{"parent", Rights{false, "127.0.0.1", 18082}, "Test required edit fields"}, func() any { return &EditVersion{} }},
		{"Decision", Decision{State: "approved", Reason: "Test a required decision"}, func() any { return &Decision{} }},
		{"PolicyRequest", RequestPolicy{VersionID: "version", Reason: "Test a required request"}, func() any { return &RequestPolicy{} }},
		{"Admission", AdmitInput{"request", "run", "node", "boot", "42", "/var/lib/workspace/", "9007199254740993", "Test required enrollment"}, func() any { return &AdmitInput{} }},
		{"Activation", ActivateInput{"version", "digest", "bpf", "Test required activation"}, func() any { return &ActivateInput{} }},
		{"Service", Service{Subject: "node", Kind: "service", PublicKey: "public", Scopes: []string{}, Node: "node"}, func() any { return &Service{} }},
		{"ServiceStatus", ServiceStatus{false, "Explicitly disable an identity"}, func() any { return &ServiceStatus{} }},
		{"Ingest", IngestInput{AdmissionID: "admission", Evidence: Evidence{Grant: "token", Events: "", Terminal: nil}, Reason: "Test required evidence"}, func() any { return &IngestInput{} }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data, _ := json.Marshal(c.value)
			if err := decodeBody(data, c.newDTO()); err != nil {
				t.Fatal(err)
			}
			schema := apiSchemas()[c.name].(map[string]any)
			for _, name := range schema["required"].([]string) {
				for _, mode := range []string{"absent", "null"} {
					var fields map[string]json.RawMessage
					json.Unmarshal(data, &fields)
					if mode == "absent" {
						delete(fields, name)
					} else {
						fields[name] = json.RawMessage("null")
					}
					bad, _ := json.Marshal(fields)
					if err := decodeBody(bad, c.newDTO()); err == nil {
						t.Fatalf("accepted %s %s", mode, name)
					}
				}
			}
		})
	}
	for _, name := range []string{"workspace_write", "tcp_address", "tcp_port"} {
		data := []byte(`{"name":"Valid policy","rights":{"workspace_write":false,"tcp_address":"127.0.0.1","tcp_port":18081},"reason":"Check nested required fields"}`)
		var top map[string]any
		json.Unmarshal(data, &top)
		delete(top["rights"].(map[string]any), name)
		bad, _ := json.Marshal(top)
		if err := decodeBody(bad, &CreatePolicy{}); err == nil {
			t.Fatalf("accepted absent nested %s", name)
		}
	}
}

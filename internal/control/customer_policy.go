// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"alloyium.local/kernel-poc/internal/policy"
	"bytes"
	"encoding/json"
	"reflect"
)

func (s *Store) customerEnforcementReady() error {
	if s.CustomerPolicy {
		return fail(422, "deny_all_profile_unqualified", "The compatibility profile cannot enforce deny-all reads and runtime controls. Workload admission is unavailable.")
	}
	return nil
}

func (s *Store) validateRights(rights Rights) error {
	if !s.CustomerPolicy {
		return rights.Validate()
	}
	document := policy.NewSelected(policy.Selected{WorkspaceWrite: rights.WorkspaceWrite, TCPAddress: rights.TCPAddress, TCPPort: rights.TCPPort})
	if err := document.Validate(); err != nil {
		return fail(422, "unsupported_rights", "Use one canonical IPv4 unicast address and a TCP port from 1 through 65535.")
	}
	return document.CheckDeclaredRequirements()
}
func CommunityOpenAPI() (map[string]any, error) {
	rights, err := policy.SelectedSchema()
	if err != nil {
		return nil, err
	}
	api := OpenAPI()
	api["components"].(map[string]any)["schemas"].(map[string]any)["Rights"] = rights
	api["components"].(map[string]any)["schemas"].(map[string]any)["WorkloadAdmission"] = workloadAdmissionSchema()
	api["paths"].(map[string]any)["/api/v1/admissions"].(map[string]any)["post"].(map[string]any)["requestBody"] = map[string]any{"required": true, "content": map[string]any{"application/json": map[string]any{"schema": map[string]any{"$ref": "#/components/schemas/WorkloadAdmission"}}}}
	for _, op := range []apiOperation{
		{path: "target-challenges", method: "post", scope: "target:write", body: "TargetChallengeInput"},
		{path: "target-reports", method: "post", scope: "target:write", body: "TargetReportInput"},
		{path: "target-reports/{id}", method: "get", scope: "target:read"},
		{path: "policy-documents", method: "post", scope: "policy:write", body: "CreatePolicyDocument"},
		{path: "policy-documents/{id}", method: "get", scope: "policy:read"},
		{path: "policy-preview", method: "post", scope: "policy:read", body: "PolicyPreviewInput"},
	} {
		api["paths"].(map[string]any)["/api/v1/"+op.path] = map[string]any{op.method: apiDescription(op)}
	}
	api["paths"].(map[string]any)["/api/v1/policy-schema"] = map[string]any{"get": apiDescription(apiOperation{path: "policy-schema", method: "get", scope: "policy:read"})}
	validation := apiDescription(apiOperation{path: "policy-validate", method: "post", scope: "policy:read", body: "PolicyValidateInput"})
	validation["summary"] = "Validate a JSON or YAML policy document without installation"
	api["paths"].(map[string]any)["/api/v1/policy-validate"] = map[string]any{"post": validation}
	return api, nil
}
func workloadAdmissionSchema() map[string]any {
	schema := apiSchemas()["Admission"].(map[string]any)
	schema["required"] = append(schema["required"].([]string), "job_digest")
	schema["properties"].(map[string]any)["job_digest"] = map[string]any{"type": "string", "pattern": "^[a-f0-9]{64}$"}
	return schema
}
func decodeCustomerBody(data []byte, dst any) error {
	name := reflect.TypeOf(dst).Elem().Name()
	if name != "CreatePolicy" && name != "EditVersion" && name != "WorkloadAdmission" {
		return decodeBody(data, dst)
	}
	schemas := apiSchemas()
	rights, err := policy.SelectedSchema()
	if err != nil {
		return err
	}
	schemas["Rights"] = rights
	schemas["WorkloadAdmission"] = workloadAdmissionSchema()
	raw, _ := json.Marshal(schemas)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var values map[string]any
	if err := decoder.Decode(&values); err != nil {
		return err
	}
	input, err := policy.ReadJSON(data)
	if err != nil {
		return fail(422, "invalid_json", "Supply one JSON policy object.")
	}
	if err := validateSchemaValue(input, values[name].(map[string]any), values, 0); err != nil {
		return err
	}
	// The ordinary decoder retains unknown-field and trailing-object rejection.
	return decodeBodyUnchecked(data, dst)
}

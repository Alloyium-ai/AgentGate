// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"alloyium.local/kernel-poc/internal/policy"
	"bytes"
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
)

func TestCommunitySchemaAPIRequiresAuthenticationAndSharesRightsContract(t *testing.T) {
	fixture := authTestFixture(t)
	fixture.Store.CustomerPolicy = true
	response, err := fixture.Client.Get(fixture.App.URL + "/api/v1/policy-schema")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatalf("anonymous schema status%d", response.StatusCode)
	}
	response, _ = loginFlow(t, fixture, "viewer")
	response.Body.Close()
	response, err = fixture.Client.Get(fixture.App.URL + "/api/v1/policy-schema")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("viewer schema status%d", response.StatusCode)
	}
	var contract struct {
		Schema          map[string]any `json:"schema"`
		SchemaDigest    string         `json:"schema_digest"`
		SelectedProfile string         `json:"selected_profile"`
	}
	if err = json.NewDecoder(response.Body).Decode(&contract); err != nil {
		t.Fatal(err)
	}
	if contract.SchemaDigest != policy.SchemaDigest() || contract.SelectedProfile != policy.SelectedProfile {
		t.Fatal("API schema identity differs from the compiler")
	}
	openapi, err := CommunityOpenAPI()
	if err != nil {
		t.Fatal(err)
	}
	rights := openapi["components"].(map[string]any)["schemas"].(map[string]any)["Rights"]
	selected := contract.Schema["$defs"].(map[string]any)["selected"]
	if !reflect.DeepEqual(rights, selected) {
		t.Fatal("OpenAPI rights differ from the shared policy schema")
	}
}
func TestAdvancedPolicyValidationPreservesFieldsAndDoesNotPublish(t *testing.T) {
	fixture := authTestFixture(t)
	fixture.Store.CustomerPolicy = true
	response, _ := loginFlow(t, fixture, "viewer")
	response.Body.Close()
	session := readSession(t, fixture)
	document := policy.NewSelected(policy.Selected{true, "192.0.2.255", 8443})
	source, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	input := PolicyValidateInput{"json", string(source), policy.SchemaDigest(), "Validate the current selected fields"}
	send := func(input PolicyValidateInput) *http.Response {
		t.Helper()
		raw, _ := json.Marshal(input)
		request, _ := http.NewRequest("POST", fixture.App.URL+"/api/v1/policy-validate", bytes.NewReader(raw))
		request.Header.Set("Origin", fixture.App.URL)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", session.CSRF)
		response, err := fixture.Client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	response = send(input)
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("valid editor response%d", response.StatusCode)
	}
	var result struct {
		Purpose  string          `json:"purpose"`
		Document policy.Document `json:"document"`
	}
	if err = json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Purpose != "document-validation" || !reflect.DeepEqual(result.Document, document) {
		t.Fatal("the editor changed or published validated fields")
	}
	var count int
	if err = fixture.Store.DB.QueryRow("SELECT count(*) FROM versions").Scan(&count); err != nil || count != 0 {
		t.Fatal("validation created a policy version")
	}
	input.SchemaDigest = "stale"
	response = send(input)
	response.Body.Close()
	if response.StatusCode != 422 {
		t.Fatalf("invalid schema hash response%d", response.StatusCode)
	}
	input.SchemaDigest = policy.SchemaDigest()
	input.Source = string(bytes.Replace(source, []byte(`"tcp_port":8443`), []byte(`"tcp_port":8443,"udp_port":53`), 1))
	response = send(input)
	response.Body.Close()
	if response.StatusCode != 422 {
		t.Fatal("the advanced API ignored an unenforced UDP field")
	}
}
func TestCustomerPolicyDecoderRejectsDuplicateAndAmbiguousRights(t *testing.T) {
	for _, raw := range []string{
		`{"name":"Duplicate target","rights":{"workspace_write":true,"tcp_address":"127.0.0.1","tcp_port":19081,"tcp_port":19082},"reason":"Reject a duplicate selected target"}`,
		`{"name":"Fractional target","rights":{"workspace_write":true,"tcp_address":"127.0.0.1","tcp_port":19081.0},"reason":"Require a decimal integer literal"}`,
		`{"name":"Unknown operation","rights":{"workspace_write":true,"tcp_address":"127.0.0.1","tcp_port":19081,"exec":true},"reason":"Reject an unenforced field"}`,
	} {
		if err := decodeCustomerBody([]byte(raw), &CreatePolicy{}); err == nil {
			t.Fatal("ambiguous or unenforced policy rights decoded")
		}
	}
}

func TestFullPolicyValidationChecksContractWithoutAdmissionOrPublication(t *testing.T) {
	s := storeFixture(t)
	s.CustomerPolicy = true
	document := fullDocumentFixture()
	source, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	in := PolicyValidateInput{"json", string(source), policy.SchemaDigest(), "Validate the full draft without admission"}
	value, err := s.ValidatePolicyDocument(humanOp(), in)
	if err != nil {
		t.Fatal(err)
	}
	result := value.(map[string]any)
	if result["purpose"] != "contract-validation" || result["admission_available"] != false || !reflect.DeepEqual(result["document"], document) {
		t.Fatal("full validation changed the draft or enabled admission")
	}
	for _, table := range []string{"versions", "policy_documents", "admissions"} {
		var count int
		if err = s.DB.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("validation changed %s: count=%d error=%v", table, count, err)
		}
	}
	document.RequiredCapabilities = []string{}
	source, _ = json.Marshal(document)
	in.Source = string(source)
	if _, err = s.ValidatePolicyDocument(humanOp(), in); err == nil {
		t.Fatal("full validation ignored missing declared controls")
	}
}

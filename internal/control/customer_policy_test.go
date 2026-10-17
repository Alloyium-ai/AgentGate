// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"strings"
	"testing"
)

func TestCustomerLiteralPolicyAndFixtureCeiling(t *testing.T) {
	body := []byte(`{"name":"Customer service","rights":{"workspace_write":false,"tcp_address":"192.0.2.20","tcp_port":8443},"reason":"Permit the selected customer service"}`)
	var in CreatePolicy
	if err := decodeCustomerBody(body, &in); err != nil {
		t.Fatal(err)
	}
	s := storeFixture(t)
	if _, err := s.CreatePolicy(humanOp(), in); err == nil {
		t.Fatal("the fixture server admitted a customer endpoint")
	}
	s.CustomerPolicy = true
	if _, err := s.CreatePolicy(humanOp(), in); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"host.example.test", "0.0.0.0", "::1", "127.000.0.1", "224.0.0.1"} {
		if s.validateRights(Rights{true, address, 8443}) == nil {
			t.Fatalf("accepted unsupported address %s", address)
		}
	}
	for _, port := range []int{0, 65536} {
		if s.validateRights(Rights{true, "192.0.2.20", port}) == nil {
			t.Fatal("accepted invalid TCP port")
		}
	}
	for _, bad := range [][]byte{[]byte(`{"name":"Missing rights","rights":{"tcp_address":"192.0.2.20","tcp_port":8443},"reason":"Reject missing fields"}`), []byte(`{"name":"Null rights","rights":null,"reason":"Reject null rights"}`)} {
		if decodeCustomerBody(bad, &in) == nil {
			t.Fatal("customer decoder lost required field checks")
		}
	}
}

func TestCustomerAdmissionRejectsInspectionProfile(t *testing.T) {
	s := storeFixture(t)
	s.CustomerPolicy = true
	v := publish(t, s, createVersion(t, s))
	agent, _ := enroll(t, s, "synthetic-agent", "agent", []string{"request:create", "policy:read"})
	node, _ := enroll(t, s, "synthetic-node", "service", []string{"admission:write"})
	value, err := s.RequestPolicy(Operation{Actor: agent, RequestID: newID()}, RequestPolicy{VersionID: v.ID, Reason: "Request the customer workload policy"})
	if err != nil {
		t.Fatal(err)
	}
	request := value.(PolicyRequest)
	value, err = s.DecideRequest(humanOp(), request.ID, etag(request.Revision), Decision{State: "approved", Reason: "Approve the exact customer version"})
	if err != nil {
		t.Fatal(err)
	}
	request = value.(PolicyRequest)
	input := AdmitInput{RequestID: request.ID, RunID: "synthetic-workload", Node: "synthetic-node", Boot: "synthetic-boot", Domain: "42", Workspace: "/var/lib/customer-workspace/", DeadlineNS: "9007199254740993", Reason: "Admit the declared customer workload"}
	if _, err = s.Admit(Operation{Actor: node, RequestID: newID()}, input); err == nil {
		t.Fatal("the customer grant omitted its workload digest")
	}
	digest := strings.Repeat("a", 64)
	if _, err = s.AdmitWorkload(Operation{Actor: node, RequestID: newID()}, WorkloadAdmission{input, digest}); err == nil {
		t.Fatal("an inspection profile admitted implicit reads or runtime access")
	}
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM admissions").Scan(&count); err != nil || count != 0 {
		t.Fatal("inspection admission issued a grant")
	}
}
func TestCustomerActivationRejectsUnqualifiedDenyAll(t *testing.T) {
	s := storeFixture(t)
	s.CustomerPolicy = true
	node, _ := enroll(t, s, "synthetic-deny-node", "service", []string{"admission:write"})
	if _, err := s.Activate(Operation{Actor: node, RequestID: newID()}, "unissued", ActivateInput{Reason: "Require a qualified deny-all profile"}); err == nil {
		t.Fatal("unqualified activation admitted a workload")
	}
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM activations").Scan(&count); err != nil || count != 0 {
		t.Fatal("unqualified activation installed rights")
	}
}

func TestCustomerPolicyCreateAndEditRejectLimitedBroadcast(t *testing.T) {
	s := storeFixture(t)
	s.CustomerPolicy = true
	rights := Rights{true, "255.255.255.255", 8443}
	if _, err := s.CreatePolicy(humanOp(), CreatePolicy{Name: "Rejected broadcast", Rights: rights, Reason: "Reject limited broadcast at policy creation"}); err == nil {
		t.Fatal("policy creation accepted limited broadcast")
	}
	v := createVersion(t, s)
	if _, err := s.EditVersion(humanOp(), v.PolicyID, EditVersion{ParentID: v.ID, Rights: rights, Reason: "Reject limited broadcast at policy editing"}); err == nil {
		t.Fatal("policy editing accepted limited broadcast")
	}
	for _, address := range []string{"127.0.0.1", "192.0.2.255"} {
		rights.TCPAddress = address
		if _, err := s.EditVersion(humanOp(), v.PolicyID, EditVersion{ParentID: v.ID, Rights: rights, Reason: "Keep a canonical unicast address valid"}); err != nil {
			t.Fatalf("unicast edit rejected: %s %v", address, err)
		}
	}
}

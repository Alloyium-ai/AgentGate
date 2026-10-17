// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualification

import (
	"alloyium.local/kernel-poc/internal/policy"
	_ "embed"
	"encoding/json"
	"testing"
)

//go:embed testdata/startup-policy.json
var startupPolicyFixture []byte

func candidate(t *testing.T) policy.Document {
	t.Helper()
	d, err := policy.Parse(startupPolicyFixture, "json")
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func TestCandidateRequiresAllTwentySixContracts(t *testing.T) {
	d := candidate(t)
	contracts, err := Contracts(d)
	if err != nil {
		t.Fatal(err)
	}
	if len(contracts) != 26 {
		t.Fatalf("contracts=%d", len(contracts))
	}
	for i, c := range contracts {
		if c.CapabilityID != d.RequiredCapabilities[i] || c.Version != ContractVersion || len(c.Cases) == 0 || len(c.Mechanisms) == 0 || len(c.ArtifactNames) == 0 {
			t.Fatalf("incomplete contract %+v", c)
		}
		for j, name := range c.Cases {
			if name == "" || j > 0 && c.Cases[j-1] >= name {
				t.Fatalf("case is empty, repeated or unsorted: %+v", c)
			}
		}
	}
}
func TestEveryExplicitFileAllowanceChangesItsBehaviorContract(t *testing.T) {
	d := candidate(t)
	a, err := Contracts(d)
	if err != nil {
		t.Fatal(err)
	}
	d.Files.Rules[0].Selector.Path = "/opt/agent/substituted/codex"
	b, err := Contracts(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"fs.read.v1", "fs.mmap.v1", "fs.map-execute.v1", "fs.mprotect.v1"} {
		var first, second []byte
		for _, c := range a {
			if c.CapabilityID == id {
				first, _ = json.Marshal(c.Cases)
			}
		}
		for _, c := range b {
			if c.CapabilityID == id {
				second, _ = json.Marshal(c.Cases)
			}
		}
		if string(first) == string(second) {
			t.Fatalf("%s borrowed an allowance for another path", id)
		}
	}
}
func TestAbsentContractRejectsBroaderRequestedControl(t *testing.T) {
	d := candidate(t)
	d.Files.Rules[0].Operations = append(d.Files.Rules[0].Operations, "create")
	d.RequiredCapabilities, _ = policy.Requirements(d)
	if _, err := Contracts(d); err == nil {
		t.Fatal("create inherited read qualification")
	}
}
func TestContractsReturnOwnedCopies(t *testing.T) {
	d := candidate(t)
	a, err := Contracts(d)
	if err != nil {
		t.Fatal(err)
	}
	a[0].Cases[0] = "changed"
	a[0].ArtifactNames[0] = "changed"
	a[0].Mechanisms[0] = "changed"
	b, err := Contracts(d)
	if err != nil {
		t.Fatal(err)
	}
	if b[0].Cases[0] == "changed" || b[0].ArtifactNames[0] == "changed" || b[0].Mechanisms[0] == "changed" {
		t.Fatal("catalog leaked mutable storage")
	}
}

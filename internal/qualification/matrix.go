// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualification

import (
	"alloyium.local/kernel-poc/internal/policy"
	"reflect"
)

// buildCaseMatrix retains all obligations, including gaps. A verified adapter
// observation remains distinct from the report's enforced capability state.
func buildCaseMatrix(requests []Request, records []EvidenceRecord, report policy.CapabilityReport) []CapabilityCases {
	type key struct{ policy, capability, name string }
	references := map[key][]CaseEvidence{}
	expected := map[string]Binding{}
	for _, request := range requests {
		expected[request.Binding.PolicyDigest] = request.Binding
	}
	for index, record := range records {
		if record.Failure != "" || !reflect.DeepEqual(record.Binding, record.Request.Binding) ||
			!reflect.DeepEqual(record.Binding, expected[record.Binding.PolicyDigest]) {
			continue
		}
		rawDigest := digestBytes(record.Raw)
		for _, coverage := range record.Coverage {
			if coverage.ReceiptSHA256 != rawDigest {
				continue
			}
			for _, name := range coverage.Cases {
				item := key{record.Binding.PolicyDigest, coverage.CapabilityID, name}
				references[item] = append(references[item], CaseEvidence{index, record.AdapterID, rawDigest})
			}
		}
	}
	matrix := make([]CapabilityCases, 0)
	for _, request := range requests {
		for _, contract := range request.Contracts {
			entry := CapabilityCases{PolicyDigest: request.Binding.PolicyDigest, CapabilityID: contract.CapabilityID,
				CapabilityState: report.Capabilities[contract.CapabilityID].State, Cases: make([]CaseStatus, 0, len(contract.Cases))}
			for _, name := range contract.Cases {
				evidence := references[key{request.Binding.PolicyDigest, contract.CapabilityID, name}]
				status := "unqualified"
				if len(evidence) != 0 {
					status = "verified_observation"
				} else {
					evidence = []CaseEvidence{}
				}
				entry.Cases = append(entry.Cases, CaseStatus{Name: name, Status: status, Evidence: evidence})
			}
			matrix = append(matrix, entry)
		}
	}
	return matrix
}

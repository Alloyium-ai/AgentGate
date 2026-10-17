// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"alloyium.local/kernel-poc/internal/policy"
	"database/sql"
)

type PolicyValidateInput struct {
	Format       string `json:"format"`
	Source       string `json:"source"`
	SchemaDigest string `json:"schema_digest"`
	Reason       string `json:"reason"`
}

func decodePolicyValidate(data []byte, in *PolicyValidateInput) error {
	if _, err := policy.ReadJSON(data); err != nil {
		return fail(422, "invalid_json", "Supply one policy validation request with unique fields.")
	}
	return decodeBody(data, in)
}
func (s *Store) ValidatePolicyDocument(op Operation, in PolicyValidateInput) (any, error) {
	op.Action = "policy.document.validated"
	op.Resource = "policy-document"
	op.Reason = safeReason(in.Reason)
	return s.Mutation(op, "policy:read", false, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if !s.CustomerPolicy {
			return nil, fail(404, "not_found", "The Community policy editor is unavailable in fixture mode.")
		}
		if in.SchemaDigest != policy.SchemaDigest() {
			return nil, fail(409, "policy_schema_changed", "Refresh the current policy schema before validation.")
		}
		document, err := policy.Parse([]byte(in.Source), in.Format)
		if err != nil {
			return nil, fail(422, "invalid_policy_document", err.Error())
		}
		if err = document.CheckDeclaredRequirements(); err != nil {
			return nil, fail(422, "invalid_capabilities", err.Error())
		}
		purpose := "document-validation"
		if document.Profile == policy.KernelProfile {
			purpose = "contract-validation"
		}
		op.After = map[string]any{"schema_digest": policy.SchemaDigest(), "profile": document.Profile, "document_digest": digest([]byte(jsonText(document)))}
		return map[string]any{"purpose": purpose, "document": document, "schema_digest": policy.SchemaDigest(), "admission_available": false}, nil
	})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/policy"
	"errors"
	"net/http"
)

func (s *Server) state(w http.ResponseWriter, r *http.Request, subject string) {
	values := r.URL.Query()
	id := values.Get("grant_id")
	if len(values) != 1 || len(values["grant_id"]) != 1 || !identifier.MatchString(id) || r.URL.RawQuery != "grant_id="+id {
		problem(w, 422, "authority_state_invalid")
		return
	}
	a, revoked, e := s.config.Store.Grant(r.Context(), id)
	if errors.Is(e, ErrUnknown) {
		response(w, StateResponse{Protocol: StateProtocol, GrantID: id})
		return
	}
	if e != nil {
		problem(w, 503, "authority_state_unavailable")
		return
	}
	if a.Binding.NodeID != subject || s.config.Enrollment.VerifyEnrollment(r.Context(), a.Binding) != nil {
		problem(w, 403, "authority_node_rejected")
		return
	}
	response(w, StateResponse{StateProtocol, id, true, revoked})
}
func (s *Server) receipt(w http.ResponseWriter, r *http.Request, subject string, body []byte) {
	var bundle jobaudit.Bundle
	if decodeAudit(body, &bundle) != nil || bundle.Grant == nil || bundle.Seal == nil || bundle.Authority != nil || bundle.Header.FixturePurpose != "" {
		problem(w, 422, "authority_receipt_invalid")
		return
	}
	b := bundle.Header.Binding
	if b.NodeID != subject || s.config.Enrollment.VerifyEnrollment(r.Context(), b) != nil {
		problem(w, 403, "authority_node_rejected")
		return
	}
	a, revoked, e := s.config.Store.Grant(r.Context(), b.GrantID)
	if e != nil {
		problem(w, 403, "authority_grant_unknown")
		return
	}
	if revoked && bundle.Seal.Terminal.State == "completed" {
		problem(w, 403, "authority_revoked_completion_rejected")
		return
	}
	stored, e := jobgrant.Decode(a.Grant)
	if e != nil || jobgrant.Digest(stored) != jobgrant.Digest(*bundle.Grant) {
		problem(w, 403, "authority_grant_rejected")
		return
	}
	supplied, e := policy.Parse(a.Document, "json")
	if e != nil {
		problem(w, 503, "authority_document_unavailable")
		return
	}
	doc, e := s.approved(r.Context(), b.PolicyDigest, supplied)
	if e != nil {
		problem(w, 403, "authority_document_unapproved")
		return
	}
	wall, _, e := s.config.Clock.Now()
	if e != nil {
		problem(w, 503, "authority_clock_unavailable")
		return
	}
	trust := jobaudit.Trust{NodeKeys: s.config.NodeKeys, AuthorityKeys: s.authorityKeys(), Registry: s.config.Registry(b), Document: doc}
	receipt, e := jobaudit.SignReceipt(s.config.AuthorityID, s.config.KeyID, s.config.SigningKey, bundle, trust, wall.Unix())
	if e != nil {
		problem(w, 403, "authority_audit_incomplete")
		return
	}
	if s.config.Store.SaveReceipt(r.Context(), b.GrantID, jobaudit.SealDigest(*bundle.Seal), revoked, receipt) != nil {
		problem(w, 409, "authority_receipt_conflict_or_store_unavailable")
		return
	}
	response(w, ReceiptResponse{ReceiptProtocol, receipt})
}

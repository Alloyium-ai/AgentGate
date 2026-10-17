// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"bytes"
	"encoding/base64"
	"errors"
	"net/http"
)

func (s *Server) revoke(w http.ResponseWriter, r *http.Request, subject string, body []byte) {
	var request RevokeRequest
	if lifecycle.DecodeTransport(bytes.NewReader(body), &request) != nil || request.Protocol != RevokeProtocol || !identifier.MatchString(request.GrantID) {
		problem(w, 422, "authority_revoke_invalid")
		return
	}
	authorization, _, err := s.config.Store.Grant(r.Context(), request.GrantID)
	if errors.Is(err, ErrUnknown) {
		problem(w, 403, "authority_grant_revoke_rejected")
		return
	}
	if err != nil {
		problem(w, 503, "authority_revoke_unavailable")
		return
	}
	binding := authorization.Binding
	if binding.AgentID != subject || binding.AgentKey != base64.RawURLEncoding.EncodeToString(s.config.Subjects[subject].Key) || s.config.Enrollment.VerifyEnrollment(r.Context(), binding) != nil {
		problem(w, 403, "authority_grant_revoke_rejected")
		return
	}
	if err = s.config.Store.Revoke(r.Context(), request.GrantID); err != nil {
		problem(w, 503, "authority_revoke_unavailable")
		return
	}
	response(w, StateResponse{Protocol: StateProtocol, GrantID: request.GrantID, Known: true, Revoked: true})
}

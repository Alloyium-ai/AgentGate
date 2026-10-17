// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

type requestStateKey struct{}
type requestState struct{ binding *lifecycle.Binding }

type Server struct {
	config     Config
	resolver   EnrollmentResolver
	proofs     ProofConsumer
	operations NodeOperations
	failed     atomic.Bool
}

func New(config Config, resolver EnrollmentResolver, proofs ProofConsumer, operations NodeOperations) (*Server, error) {
	if !identityPattern.MatchString(config.Identity.NodeID) || !identityPattern.MatchString(config.Identity.BootID) || resolver == nil || proofs == nil || config.Clock == nil || config.ReadHeaderTimeout <= 0 || config.ReadHeaderTimeout > 30*time.Second || config.RequestTimeout <= 0 || config.RequestTimeout > 24*time.Hour || config.ShutdownTimeout <= 0 || config.ShutdownTimeout > 30*time.Second {
		return nil, errors.New("private node identity, dependencies and bounded timeouts are required")
	}
	return &Server{config: config, resolver: resolver, proofs: proofs, operations: operations}, nil
}
func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": code}})
}
func response(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	state := &requestState{}
	r = r.WithContext(context.WithValue(r.Context(), requestStateKey{}, state))
	defer func() {
		if recover() != nil {
			s.failed.Store(true)
			if state.binding != nil {
				s.cleanup(r.Context(), *state.binding)
			}
			problem(w, 500, "node_internal_failure")
		}
	}()
	if r.URL.RawQuery != "" || r.URL.Fragment != "" {
		problem(w, 400, "node_request_target_invalid")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
	if err != nil || len(body) > 2<<20 {
		problem(w, 413, "node_request_bound_exceeded")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	enrollment, err := s.authenticate(r, body)
	if err != nil {
		problem(w, 401, err.Error())
		return
	}
	if s.operations == nil {
		problem(w, 503, "node_runtime_unavailable")
		return
	}
	if s.route(w, r, enrollment, body) {
		return
	}
	problem(w, 404, "node_route_unknown")
}
func (s *Server) unavailable(w http.ResponseWriter) {
	s.failed.Store(true)
	problem(w, 503, "node_runtime_evidence_invalid")
}

func trackRequest(r *http.Request, binding lifecycle.Binding) {
	state, _ := r.Context().Value(requestStateKey{}).(*requestState)
	if state == nil {
		return
	}
	raw, _ := json.Marshal(binding)
	var snapshot lifecycle.Binding
	_ = json.Unmarshal(raw, &snapshot)
	state.binding = &snapshot
}

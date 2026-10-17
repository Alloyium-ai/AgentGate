// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"context"
	"net/http"
	"strings"
)

// GenerationProvider reads the existing node journal. It allocates no generation.
// Prepare remains the sole atomic reservation and replay gate.
type GenerationProvider interface {
	GenerationFloor(context.Context, string) (uint64, error)
}
type GenerationResponse struct {
	Protocol   string `json:"protocol"`
	AgentID    string `json:"agent_id"`
	NodeID     string `json:"node_id"`
	BootID     string `json:"boot_id"`
	Generation uint64 `json:"generation,string"`
}

func (s *Server) generation(w http.ResponseWriter, r *http.Request, enrollment Enrollment) bool {
	const prefix = "/v1/agents/"
	const suffix = "/generation"
	if r.Method != "GET" || !strings.HasPrefix(r.URL.Path, prefix) || !strings.HasSuffix(r.URL.Path, suffix) {
		return false
	}
	agent := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, prefix), suffix)
	if !identityPattern.MatchString(agent) {
		problem(w, 422, "node_generation_invalid")
		return true
	}
	if agent != enrollment.AgentID {
		problem(w, 403, "node_generation_owner_differs")
		return true
	}
	provider, ok := s.operations.(GenerationProvider)
	if !ok {
		problem(w, 503, "node_generation_unavailable")
		return true
	}
	floor, err := provider.GenerationFloor(r.Context(), agent)
	if err != nil || floor >= uint64(1<<63-1) {
		problem(w, 503, "node_generation_unavailable")
		return true
	}
	response(w, GenerationResponse{"agentgate.agent-generation.v1", agent, s.config.Identity.NodeID, s.config.Identity.BootID, floor})
	return true
}

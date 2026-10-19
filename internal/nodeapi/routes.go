// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"reflect"
	"sort"
	"strings"
)

func (s *Server) route(w http.ResponseWriter, r *http.Request, enrollment Enrollment, body []byte) bool {
	if s.inventory(w, r) {
		return true
	}
	if s.generation(w, r, enrollment) {
		return true
	}
	path := r.URL.Path
	if r.Method == "POST" && path == "/v1/jobs/prepare" {
		s.prepare(w, r, enrollment, body)
		return true
	}
	if r.Method == "POST" && path == "/v1/jobs/run" {
		s.run(w, r, enrollment, body)
		return true
	}
	if !strings.HasPrefix(path, "/v1/jobs/") {
		return false
	}
	tail := strings.TrimPrefix(path, "/v1/jobs/")
	if r.Method == "GET" && identityPattern.MatchString(tail) {
		s.status(w, r, enrollment, tail)
		return true
	}
	if r.Method == "POST" && strings.HasSuffix(tail, "/stop") {
		runID := strings.TrimSuffix(tail, "/stop")
		if identityPattern.MatchString(runID) {
			s.stop(w, r, enrollment, runID, body)
			return true
		}
	}
	return false
}
func (s *Server) prepare(w http.ResponseWriter, r *http.Request, enrollment Enrollment, body []byte) {
	var request lifecycle.PrepareRequest
	if lifecycle.DecodeTransport(bytes.NewReader(body), &request) != nil || request.Validate() != nil {
		problem(w, 422, "node_prepare_invalid")
		return
	}
	if !s.bindingMatches(enrollment, request.Binding) || !runtimeMatches(enrollment, request.Manifest, request.Binding) {
		problem(w, 403, "node_job_enrollment_differs")
		return
	}
	if s.qualified(r.Context(), request.Binding, request.RequiredCapabilities) != nil {
		problem(w, 503, "node_required_capability_unavailable")
		return
	}
	trackRequest(r, request.Binding)
	prepared, err := s.operations.Prepare(r.Context(), request)
	if err != nil {
		s.cleanup(r.Context(), request.Binding)
		problem(w, 503, "node_prepare_rejected")
		return
	}
	if !validPrepared(request, prepared, s.config.Clock) || lifecycle.RequireCapabilities(prepared.Evidence, request.RequiredCapabilities) != nil {
		s.cleanup(r.Context(), request.Binding)
		s.unavailable(w)
		return
	}
	response(w, prepared)
}
func validDocument(authorization lifecycle.Authorization) bool {
	if authorization.Grant == "" || len(authorization.Grant) > 32768 {
		return false
	}
	document, err := policy.Parse(authorization.Document, "json")
	if err != nil || document.Profile != policy.KernelProfile || document.CheckDeclaredRequirements() != nil {
		return false
	}
	declared := append([]string{}, authorization.RequiredCapabilities...)
	expected := append([]string{}, document.RequiredCapabilities...)
	sort.Strings(declared)
	sort.Strings(expected)
	return reflect.DeepEqual(declared, expected)
}
func validTerminal(request lifecycle.RunRequest, terminal lifecycle.Terminal) bool {
	if terminal.Protocol != lifecycle.TerminalProtocol || !sameBinding(terminal.Binding, request.Authorization.Binding) || !terminal.DomainEmpty || !terminal.RightsRemoved || !digestPattern.MatchString(terminal.EvidenceDigest) {
		return false
	}
	switch terminal.State {
	case "completed":
		if terminal.ExitCode != 0 || terminal.EvidenceVerdict != "VALID_COMPLETE" {
			return false
		}
	case "failed", "cancelled", "expired", "revoked", "aborted":
	default:
		return false
	}
	if terminal.EvidenceVerdict != "VALID_COMPLETE" && terminal.EvidenceVerdict != "INCOMPLETE" && terminal.EvidenceVerdict != "TAMPERED" && terminal.EvidenceVerdict != "UNKNOWN_KEY" {
		return false
	}
	if len(terminal.Output) > lifecycle.MaxInputBytes {
		return false
	}
	if len(terminal.Output) > 0 || terminal.OutputDigest != "" {
		digest := sha256.Sum256(terminal.Output)
		if hex.EncodeToString(digest[:]) != terminal.OutputDigest {
			return false
		}
	}
	if len(terminal.Stderr) > 0 || terminal.StderrDigest != "" {
		if len(terminal.Stderr) > lifecycle.MaxInputBytes {
			return false
		}
		digest := sha256.Sum256(terminal.Stderr)
		if hex.EncodeToString(digest[:]) != terminal.StderrDigest {
			return false
		}
	}
	return true
}
func (s *Server) cleanup(ctx context.Context, binding lifecycle.Binding) {
	defer func() {
		if recover() != nil {
			s.failed.Store(true)
		}
	}()
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.config.ShutdownTimeout)
	defer cancel()
	_, _ = s.operations.Stop(cleanup, lifecycle.StopRequest{Protocol: "agentgate.job.stop.v1", Binding: binding, Reason: "node-operation-failed"})
}
func (s *Server) run(w http.ResponseWriter, r *http.Request, enrollment Enrollment, body []byte) {
	var request lifecycle.RunRequest
	if lifecycle.DecodeTransport(bytes.NewReader(body), &request) != nil || request.Validate() != nil || !validDocument(request.Authorization) {
		problem(w, 422, "node_run_invalid")
		return
	}
	if !s.bindingMatches(enrollment, request.Authorization.Binding) || !runtimeMatches(enrollment, request.Manifest, request.Authorization.Binding) {
		problem(w, 403, "node_job_enrollment_differs")
		return
	}
	if s.qualified(r.Context(), request.Authorization.Binding, request.Authorization.RequiredCapabilities) != nil {
		problem(w, 503, "node_required_capability_unavailable")
		return
	}
	trackRequest(r, request.Authorization.Binding)
	terminal, err := s.operations.Run(r.Context(), request)
	if err != nil {
		s.cleanup(r.Context(), request.Authorization.Binding)
		problem(w, 503, "node_run_rejected")
		return
	}
	if !validTerminal(request, terminal) {
		s.cleanup(r.Context(), request.Authorization.Binding)
		s.unavailable(w)
		return
	}
	response(w, terminal)
}
func (s *Server) status(w http.ResponseWriter, r *http.Request, enrollment Enrollment, runID string) {
	status, err := s.operations.Status(r.Context(), enrollment.AgentID, runID)
	if err != nil {
		problem(w, 404, "node_run_unknown")
		return
	}
	if status.Record.Binding.AgentID != enrollment.AgentID || status.Record.Binding.AgentKey != enrollment.AgentKey || status.Record.Binding.RunID != runID || status.Record.Binding.NodeID != s.config.Identity.NodeID {
		problem(w, 403, "node_run_owner_differs")
		return
	}
	response(w, status)
}
func (s *Server) stop(w http.ResponseWriter, r *http.Request, enrollment Enrollment, runID string, body []byte) {
	var request lifecycle.StopRequest
	if lifecycle.DecodeTransport(bytes.NewReader(body), &request) != nil || request.Protocol != "agentgate.job.stop.v1" || request.Binding.Validate(request.Binding.CgroupID == 0) != nil || request.Binding.RunID != runID || !identityPattern.MatchString(request.Reason) {
		problem(w, 422, "node_stop_invalid")
		return
	}
	if request.Binding.AgentID != enrollment.AgentID || request.Binding.AgentKey != enrollment.AgentKey || request.Binding.NodeID != s.config.Identity.NodeID {
		problem(w, 403, "node_run_owner_differs")
		return
	}
	stopped, err := s.operations.Stop(r.Context(), request)
	if err != nil {
		problem(w, 503, "node_stop_unconfirmed")
		return
	}
	if !validStopped(request, stopped) {
		s.unavailable(w)
		return
	}
	response(w, stopped)
}

// Only failure cleanup can resolve a previously unknown domain ID. All other
// fields remain exact, and the backend must return a complete stopped readback.
func validStopped(request lifecycle.StopRequest, stopped lifecycle.StopResponse) bool {
	expected := request.Binding
	if expected.CgroupID == 0 {
		expected.CgroupID = stopped.Binding.CgroupID
	}
	return stopped.Protocol == lifecycle.StoppedProtocol && sameBinding(stopped.Binding, expected) && lifecycle.VerifyReadback(stopped.Evidence, expected, "stopped") == nil
}

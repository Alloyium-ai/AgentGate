// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Actor struct {
	Subject string   `json:"subject"`
	Kind    string   `json:"kind"`
	Roles   []string `json:"roles"`
	Scopes  []string `json:"scopes"`
	Name    string   `json:"name,omitempty"`
	Groups  []string `json:"groups,omitempty"`
}
type Rights struct {
	WorkspaceWrite bool   `json:"workspace_write"`
	TCPAddress     string `json:"tcp_address"`
	TCPPort        int    `json:"tcp_port"`
}
type Policy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Created     string `json:"created_at"`
}
type Version struct {
	ID       string `json:"id"`
	PolicyID string `json:"policy_id"`
	Number   int    `json:"number"`
	ParentID string `json:"parent_id"`
	State    string `json:"state"`
	Rights   Rights `json:"rights"`
	Digest   string `json:"digest"`
	Revision int    `json:"revision"`
	Actor    string `json:"actor"`
	Reason   string `json:"reason"`
	Created  string `json:"created_at"`
}
type PolicyRequest struct {
	ID               string `json:"id"`
	AgentID          string `json:"agent_id"`
	RequestedVersion string `json:"requested_version"`
	ApprovedVersion  string `json:"approved_version"`
	State            string `json:"state"`
	Reason           string `json:"reason"`
	DecisionReason   string `json:"decision_reason"`
	DecidedBy        string `json:"decided_by"`
	Revision         int    `json:"revision"`
	Created          string `json:"created_at"`
}
type Admission struct {
	ID           string `json:"id"`
	RequestID    string `json:"request_id"`
	AgentID      string `json:"agent_id"`
	RunID        string `json:"run_id"`
	Node         string `json:"node"`
	Boot         string `json:"boot"`
	Domain       string `json:"cgroup"`
	VersionID    string `json:"version_id"`
	PolicyDigest string `json:"policy_digest"`
	Token        string `json:"grant,omitempty"`
	GrantDigest  string `json:"grant_digest"`
	State        string `json:"state"`
	Created      string `json:"created_at"`
	Expires      string `json:"expires_at"`
}
type Run struct {
	ID             string          `json:"id"`
	AdmissionID    string          `json:"admission_id"`
	AgentID        string          `json:"agent_id"`
	VersionID      string          `json:"version_id"`
	PolicyDigest   string          `json:"policy_digest"`
	Verifier       string          `json:"verifier"`
	EvidenceDigest string          `json:"evidence_digest"`
	Evidence       json.RawMessage `json:"evidence,omitempty"`
	Created        string          `json:"created_at"`
}
type Service struct {
	Subject   string   `json:"subject"`
	Kind      string   `json:"kind"`
	PublicKey string   `json:"public_key"`
	Scopes    []string `json:"scopes"`
	Node      string   `json:"node,omitempty"`
	Enabled   bool     `json:"enabled"`
}
type AuditEntry struct {
	ID            int64           `json:"id"`
	Time          string          `json:"time"`
	Actor         string          `json:"actor"`
	ActorKind     string          `json:"actor_kind"`
	Action        string          `json:"action"`
	Resource      string          `json:"resource"`
	Version       string          `json:"version"`
	Run           string          `json:"run"`
	Before        json.RawMessage `json:"before"`
	After         json.RawMessage `json:"after"`
	Reason        string          `json:"reason"`
	RequestID     string          `json:"request_id"`
	CorrelationID string          `json:"correlation_id"`
	Result        string          `json:"result"`
}
type Operation struct {
	LoginAuthority                                                                                        string
	SessionHash                                                                                           string
	TokenHash                                                                                             string
	Revalidate                                                                                            func(*sql.Tx) error
	RevalidateCached                                                                                      func(*sql.Tx, string) error
	Actor                                                                                                 Actor
	Action, Resource, Version, Run, Reason, RequestID, CorrelationID, Idempotency, BodyDigest, ProofNonce string
	Before, After                                                                                         any
}
type Page[T any] struct {
	Items []T    `json:"items"`
	Next  string `json:"next_cursor,omitempty"`
}
type Error struct {
	Status        int
	Code, Message string
}

func (e *Error) Error() string                    { return e.Message }
func fail(status int, code, message string) error { return &Error{status, code, message} }
func digest(data []byte) string                   { v := sha256.Sum256(data); return hex.EncodeToString(v[:]) }
func stamp() string                               { return time.Now().UTC().Format("2006-01-02T15:04:05.000000000Z") }
func jsonText(v any) string {
	if v == nil {
		return "null"
	}
	b, _ := json.Marshal(v)
	return string(b)
}
func reasonValid(s string) error {
	if len(strings.TrimSpace(s)) < 3 || len(s) > 512 {
		return fail(422, "invalid_reason", "Supply a reason between 3 and 512 characters.")
	}
	return nil
}
func (r Rights) Validate() error {
	if r.TCPAddress != "127.0.0.1" || (r.TCPPort != 18081 && r.TCPPort != 18082) {
		return fail(422, "unsupported_rights", "This kernel profile supports only the two controlled IPv4 TCP endpoints.")
	}
	return nil
}
func (a Actor) Can(scope string) bool {
	if a.Kind == "human" && scope == "auth:write" && len(a.Roles) > 0 {
		return true
	}
	if a.Kind != "human" {
		for _, s := range a.Scopes {
			if s == scope {
				return true
			}
		}
		return false
	}
	for _, role := range a.Roles {
		if role == "admin" {
			return true
		}
		if role == "viewer" && strings.HasSuffix(scope, ":read") {
			return true
		}
		if role == "auditor" && (strings.HasSuffix(scope, ":read") || scope == "audit:export") {
			return true
		}
		if role == "editor" && (scope == "policy:write" || strings.HasSuffix(scope, ":read")) {
			return true
		}
		if role == "approver" && (scope == "decision:write" || scope == "launch:approve" || strings.HasSuffix(scope, ":read")) {
			return true
		}
		if role == "launcher" && (scope == "launch:write" || strings.HasSuffix(scope, ":read")) {
			return true
		}
	}
	return false
}
func require(a Actor, scope string, human bool) error {
	if (scope == "admission:write" || scope == "admission:release" || scope == "evidence:write" || scope == "target:write") && a.Kind != "service" {
		return fail(403, "forbidden", "The enforcer channel requires a scoped service identity.")
	}
	if (human && a.Kind != "human") || !a.Can(scope) {
		return fail(403, "forbidden", "Your identity does not permit this operation.")
	}
	return nil
}
func errorResult(err error) (int, string, string) {
	var e *Error
	if errors.As(err, &e) {
		return e.Status, e.Code, e.Message
	}
	return 503, "persistence_unavailable", "The operation did not commit. Try again after storage recovers."
}
func etag(revision int) string { return fmt.Sprintf("\"revision-%d\"", revision) }

func safeReason(value string) string {
	if len(value) > 512 {
		return "Request reason exceeded its validation limit"
	}
	if len(strings.TrimSpace(value)) < 3 {
		return "The request omitted a valid reason"
	}
	return value
}

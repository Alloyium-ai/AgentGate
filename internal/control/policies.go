// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
)

type CreatePolicy struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Rights      Rights `json:"rights"`
	Reason      string `json:"reason"`
}
type EditVersion struct {
	ParentID string `json:"parent_id"`
	Rights   Rights `json:"rights"`
	Reason   string `json:"reason"`
}
type Decision struct {
	State     string `json:"state"`
	VersionID string `json:"version_id,omitempty"`
	Reason    string `json:"reason"`
}
type RequestPolicy struct {
	VersionID string `json:"version_id"`
	AgentID   string `json:"agent_id,omitempty"`
	Reason    string `json:"reason"`
}
type rowScanner interface{ Scan(...any) error }
type queryer interface{ QueryRow(string, ...any) *sql.Row }

func scanVersion(row rowScanner) (Version, error) {
	var v Version
	var rights string
	err := row.Scan(&v.ID, &v.PolicyID, &v.Number, &v.ParentID, &v.State, &rights, &v.Digest, &v.Revision, &v.Actor, &v.Reason, &v.Created)
	if err == nil {
		err = json.Unmarshal([]byte(rights), &v.Rights)
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = fail(404, "not_found", "The policy version does not exist.")
	}
	return v, err
}
func versionFrom(q queryer, id string) (Version, error) {
	return scanVersion(q.QueryRow("SELECT * FROM versions WHERE id=?", id))
}
func insertVersion(tx *sql.Tx, v Version) error {
	_, err := tx.Exec("INSERT INTO versions VALUES(?,?,?,?,?,?,?,?,?,?,?)", v.ID, v.PolicyID, v.Number, v.ParentID, v.State, jsonText(v.Rights), v.Digest, v.Revision, v.Actor, v.Reason, v.Created)
	return err
}
func versionDigest(v Version) string {
	return digest([]byte(jsonText(struct {
		Policy string `json:"policy"`
		Number int    `json:"number"`
		Parent string `json:"parent"`
		Rights Rights `json:"rights"`
	}{v.PolicyID, v.Number, v.ParentID, v.Rights})))
}

func (s *Store) CreatePolicy(op Operation, in CreatePolicy) (any, error) {
	op.Action = "policy.created"
	op.Reason = safeReason(in.Reason)
	return s.Mutation(op, "policy:write", true, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if err := s.validateRights(in.Rights); err != nil {
			return nil, err
		}
		if len(strings.TrimSpace(in.Name)) < 2 || len(in.Name) > 100 || len(in.Description) > 1000 {
			return nil, fail(422, "invalid_policy", "Supply a policy name and a short description.")
		}
		p := Policy{newID(), strings.TrimSpace(in.Name), in.Description, stamp()}
		if _, err := tx.Exec("INSERT INTO policies VALUES(?,?,?,?)", p.ID, p.Name, p.Description, p.Created); err != nil {
			return nil, err
		}
		v := Version{ID: newID(), PolicyID: p.ID, Number: 1, State: "draft", Rights: in.Rights, Revision: 1, Actor: op.Actor.Subject, Reason: in.Reason, Created: stamp()}
		v.Digest = versionDigest(v)
		if err := insertVersion(tx, v); err != nil {
			return nil, err
		}
		op.Resource = p.ID
		op.Version = v.ID
		return map[string]any{"policy": p, "version": v}, nil
	})
}
func (s *Store) EditVersion(op Operation, policyID string, in EditVersion) (any, error) {
	op.Action = "policy.version.created"
	op.Resource = policyID
	op.Reason = safeReason(in.Reason)
	scope := "policy:write"
	if op.Actor.Kind == "agent" {
		scope = "proposal:create"
	}
	return s.Mutation(op, scope, false, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if err := s.validateRights(in.Rights); err != nil {
			return nil, err
		}
		parent, err := versionFrom(tx, in.ParentID)
		if err != nil {
			return nil, err
		}
		var documentCount int
		if err = tx.QueryRow("SELECT count(*) FROM policy_documents WHERE version_id=?", parent.ID).Scan(&documentCount); err != nil {
			return nil, err
		}
		if documentCount != 0 {
			return nil, fail(422, "document_required", "Create a full document version to preserve every policy field.")
		}
		if parent.PolicyID != policyID {
			return nil, fail(422, "invalid_parent", "The parent belongs to a different policy.")
		}
		var number int
		if err = tx.QueryRow("SELECT MAX(number)+1 FROM versions WHERE policy_id=?", policyID).Scan(&number); err != nil {
			return nil, err
		}
		state := "draft"
		if op.Actor.Kind == "agent" {
			state = "proposed"
		}
		v := Version{ID: newID(), PolicyID: policyID, Number: number, ParentID: parent.ID, State: state, Rights: in.Rights, Revision: 1, Actor: op.Actor.Subject, Reason: in.Reason, Created: stamp()}
		v.Digest = versionDigest(v)
		if err = insertVersion(tx, v); err != nil {
			return nil, err
		}
		op.Before = parent
		op.Version = v.ID
		return v, nil
	})
}
func (s *Store) Transition(op Operation, id, match string, in Decision) (any, error) {
	op.Action = "policy.transition"
	if map[string]bool{"proposed": true, "approved": true, "published": true, "retired": true}[in.State] {
		op.Action = "policy." + in.State
	}
	op.Resource = id
	op.Version = id
	op.Reason = safeReason(in.Reason)
	scope := "decision:write"
	human := true
	if in.State == "proposed" {
		scope = "policy:write"
		human = false
		if op.Actor.Kind == "agent" {
			scope = "proposal:create"
		}
	}
	return s.Mutation(op, scope, human, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		v, err := versionFrom(tx, id)
		if err != nil {
			return nil, err
		}
		if match == "" {
			return nil, fail(428, "precondition_required", "Supply the current If-Match revision.")
		}
		if match != etag(v.Revision) {
			return nil, fail(412, "version_conflict", "The version changed. Refresh its history before deciding.")
		}
		if err = rejectDocumentPublication(tx, id, in.State); err != nil {
			return nil, err
		}
		next := map[string]string{"draft": "proposed", "proposed": "approved", "approved": "published", "published": "retired"}
		if next[v.State] != in.State {
			return nil, fail(409, "invalid_transition", "This lifecycle transition is not available.")
		}
		if op.Actor.Kind == "agent" && v.Actor != op.Actor.Subject {
			return nil, fail(403, "forbidden", "An agent can submit only its own proposal.")
		}
		op.Before = v
		v.State = in.State
		v.Revision++
		if _, err = tx.Exec("UPDATE versions SET state=?,revision=? WHERE id=?", v.State, v.Revision, id); err != nil {
			return nil, err
		}
		return v, nil
	})
}
func scanRequest(row rowScanner) (PolicyRequest, error) {
	var q PolicyRequest
	err := row.Scan(&q.ID, &q.AgentID, &q.RequestedVersion, &q.ApprovedVersion, &q.State, &q.Reason, &q.DecisionReason, &q.DecidedBy, &q.Revision, &q.Created)
	if errors.Is(err, sql.ErrNoRows) {
		err = fail(404, "not_found", "The request does not exist.")
	}
	return q, err
}
func (s *Store) RequestPolicy(op Operation, in RequestPolicy) (any, error) {
	op.Action = "request.created"
	op.Reason = safeReason(in.Reason)
	return s.Mutation(op, "request:create", false, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		v, err := versionFrom(tx, in.VersionID)
		if err != nil {
			return nil, err
		}
		if v.State != "published" {
			return nil, fail(409, "policy_unpublished", "Request a published policy version.")
		}
		agent := op.Actor.Subject
		if op.Actor.Kind == "agent" && in.AgentID != "" && in.AgentID != agent {
			return nil, fail(403, "agent_binding_failed", "An agent can request policy only for itself.")
		}
		if op.Actor.Kind != "agent" {
			if err := require(op.Actor, "agents:write", true); err != nil {
				return nil, err
			}
			agent = in.AgentID
		}
		svc, err := serviceFrom(tx, agent)
		if err != nil || svc.Kind != "agent" || !svc.Enabled {
			return nil, fail(422, "unknown_agent", "Choose an enrolled active agent.")
		}
		q := PolicyRequest{ID: newID(), AgentID: agent, RequestedVersion: v.ID, State: "pending", Reason: in.Reason, Revision: 1, Created: stamp()}
		if _, err = tx.Exec("INSERT INTO requests VALUES(?,?,?,?,?,?,?,?,?,?)", q.ID, q.AgentID, q.RequestedVersion, "", q.State, q.Reason, "", "", q.Revision, q.Created); err != nil {
			return nil, err
		}
		op.Resource = q.ID
		op.Version = v.ID
		return q, nil
	})
}
func (s *Store) DecideRequest(op Operation, id, match string, in Decision) (any, error) {
	op.Action = "request.decision"
	if in.State == "approved" || in.State == "rejected" {
		op.Action = "request." + in.State
	}
	op.Resource = id
	op.Reason = safeReason(in.Reason)
	return s.Mutation(op, "decision:write", true, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		q, err := scanRequest(tx.QueryRow("SELECT * FROM requests WHERE id=?", id))
		if err != nil {
			return nil, err
		}
		if match == "" {
			return nil, fail(428, "precondition_required", "Supply the request If-Match revision.")
		}
		if match != etag(q.Revision) {
			return nil, fail(412, "version_conflict", "The request changed. Refresh the queue.")
		}
		if q.State != "pending" {
			return nil, fail(409, "already_decided", "The request already has a decision.")
		}
		if in.State != "approved" && in.State != "rejected" {
			return nil, fail(422, "invalid_decision", "Approve or reject the request.")
		}
		op.Before = q
		if in.State == "approved" {
			id := in.VersionID
			if id == "" {
				id = q.RequestedVersion
			}
			v, err := versionFrom(tx, id)
			if err != nil {
				return nil, err
			}
			if v.State != "published" {
				return nil, fail(409, "policy_unpublished", "Approve an exact published version.")
			}
			q.ApprovedVersion = id
			op.Version = id
		}
		q.State = in.State
		q.DecisionReason = in.Reason
		q.DecidedBy = op.Actor.Subject
		q.Revision++
		_, err = tx.Exec("UPDATE requests SET approved_version=?,state=?,decision_reason=?,decided_by=?,revision=? WHERE id=?", q.ApprovedVersion, q.State, q.DecisionReason, q.DecidedBy, q.Revision, q.ID)
		return q, err
	})
}

func serviceFrom(q queryer, id string) (Service, error) {
	var s Service
	var scopes string
	err := q.QueryRow("SELECT * FROM services WHERE subject=?", id).Scan(&s.Subject, &s.Kind, &s.PublicKey, &scopes, &s.Node, &s.Enabled)
	if err == nil {
		err = json.Unmarshal([]byte(scopes), &s.Scopes)
	}
	return s, err
}
func (s *Store) RegisterService(op Operation, in Service) (any, error) {
	op.Action = "agent.enrolled"
	op.Resource = in.Subject
	op.Reason = "Enroll a deployment-managed service identity"
	return s.Mutation(op, "agents:write", op.Actor.Kind != "system", func(tx *sql.Tx, op *Operation) (any, error) {
		if in.Kind != "agent" && in.Kind != "service" {
			return nil, fail(422, "invalid_actor_kind", "Choose an agent or service identity.")
		}
		if len(in.Subject) < 2 || len(in.Subject) > 100 {
			return nil, fail(422, "invalid_subject", "Supply a stable subject.")
		}
		allowed := map[string]bool{"policy:read": true, "proposal:create": true, "request:create": true, "request:read": true, "run:read": true, "admission:write": true, "admission:read": true, "evidence:write": true, "admission:release": true, "target:write": true, "target:read": true}
		for _, scope := range in.Scopes {
			if !allowed[scope] {
				return nil, fail(422, "invalid_scope", "A machine identity cannot receive human decision scopes.")
			}
			if in.Kind == "agent" && (scope == "admission:write" || scope == "evidence:write" || scope == "admission:release" || scope == "target:write" || scope == "target:read") {
				return nil, fail(422, "invalid_scope", "An agent cannot operate the enforcer admission channel.")
			}
		}
		if err := validPublicKey(in.PublicKey); err != nil {
			return nil, err
		}
		if in.Kind == "service" && in.Node == "" {
			return nil, fail(422, "invalid_node", "Bind the enforcer service to a node.")
		}
		in.Enabled = true
		_, err := tx.Exec("INSERT INTO services VALUES(?,?,?,?,?,?)", in.Subject, in.Kind, in.PublicKey, jsonText(in.Scopes), in.Node, true)
		return in, err
	})
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"time"
)

func approvalAfterRestore(tx *sql.Tx, request string) error {
	var restored, approved int64
	if err := tx.QueryRow("SELECT COALESCE(MAX(id),0) FROM audit WHERE action='backup.restored' AND result='committed'").Scan(&restored); err != nil {
		return err
	}
	if restored == 0 {
		return nil
	}
	if err := tx.QueryRow("SELECT COALESCE(MAX(id),0) FROM audit WHERE resource=? AND action='request.approved' AND actor_kind='human' AND result='committed'", request).Scan(&approved); err != nil {
		return err
	}
	if approved <= restored {
		return fail(409, "request_restore_fenced", "Restore requires a fresh human-approved request before admission or activation.")
	}
	return nil
}

func requestAdmissionReady(tx *sql.Tx, id string) error {
	q, err := scanRequest(tx.QueryRow("SELECT * FROM requests WHERE id=?", id))
	if err != nil {
		return err
	}
	if q.State != "approved" {
		return fail(409, "request_unapproved", "A human must approve this request.")
	}
	if err = approvalAfterRestore(tx, q.ID); err != nil {
		return err
	}
	agent, err := serviceFrom(tx, q.AgentID)
	if err != nil || !agent.Enabled || agent.Kind != "agent" {
		return fail(403, "agent_disabled", "The requested agent is not active.")
	}
	v, err := versionFrom(tx, q.ApprovedVersion)
	if err != nil {
		return err
	}
	if v.State != "published" {
		return fail(409, "policy_unpublished", "The approved version is no longer published.")
	}
	return nil
}

func cachedGrantReady(tx *sql.Tx, id, subject string) error {
	a, err := scanAdmission(tx.QueryRow("SELECT * FROM admissions WHERE id=?", id))
	if err != nil {
		return notFound(err)
	}
	svc, err := serviceFrom(tx, subject)
	if err != nil || !svc.Enabled || svc.Kind != "service" || svc.Node != a.Node {
		return fail(403, "node_binding_failed", "This service does not own that admission.")
	}
	if err = requestAdmissionReady(tx, a.RequestID); err != nil {
		return err
	}
	expires, err := time.Parse(time.RFC3339, a.Expires)
	if err != nil || !time.Now().Before(expires) {
		return fail(409, "grant_expired", "The grant expired before this authorization reply.")
	}
	if a.State != "issued" && a.State != "admitted" {
		return fail(409, "stale_admission", "This admission has a terminal state.")
	}
	return nil
}

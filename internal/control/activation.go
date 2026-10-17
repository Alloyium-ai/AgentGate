// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"encoding/hex"
	"time"
)

type ActivateInput struct {
	VersionID    string `json:"version_id"`
	PolicyDigest string `json:"policy_digest"`
	BPFDigest    string `json:"bpf_digest"`
	Reason       string `json:"reason"`
}

func (s *Store) Activate(op Operation, id string, in ActivateInput) (any, error) {
	op.Action = "grant.admitted"
	op.Resource = id
	op.Reason = safeReason(in.Reason)
	op.Revalidate = func(tx *sql.Tx) error {
		if err := s.customerEnforcementReady(); err != nil {
			return err
		}
		return cachedGrantReady(tx, id, op.Actor.Subject)
	}

	return s.Mutation(op, "admission:write", false, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := s.customerEnforcementReady(); err != nil {
			return nil, err
		}
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		a, err := scanAdmission(tx.QueryRow("SELECT * FROM admissions WHERE id=?", id))
		if err != nil {
			return nil, notFound(err)
		}
		svc, err := serviceFrom(tx, op.Actor.Subject)
		if err != nil || svc.Kind != "service" || svc.Node != a.Node {
			return nil, fail(403, "node_binding_failed", "This service cannot activate that execution domain.")
		}
		expires, err := time.Parse(time.RFC3339, a.Expires)
		if err != nil || !time.Now().Before(expires) {
			return nil, fail(409, "grant_expired", "The grant expired before admission.")
		}
		if a.State != "issued" || a.VersionID != in.VersionID || a.PolicyDigest != in.PolicyDigest {
			return nil, fail(409, "activation_binding_failed", "The activation does not match the issued policy version.")
		}
		if len(in.BPFDigest) != 64 {
			return nil, fail(422, "invalid_measurement", "Supply the BPF object SHA-256 digest.")
		}
		if _, err = hex.DecodeString(in.BPFDigest); err != nil {
			return nil, fail(422, "invalid_measurement", "The object digest is invalid.")
		}
		v, err := versionFrom(tx, a.VersionID)
		if err != nil {
			return nil, err
		}
		if v.State != "published" {
			return nil, fail(409, "policy_retired", "The published policy retired before admission.")
		}
		_, err = tx.Exec("INSERT INTO activations VALUES(?,?,?,?,?,?)", a.ID, a.VersionID, a.PolicyDigest, in.BPFDigest, op.Actor.Subject, stamp())
		if err != nil {
			return nil, err
		}
		a.Token = ""
		op.Before = a
		a.State = "admitted"
		op.Version = a.VersionID
		op.Run = a.RunID
		_, err = tx.Exec("UPDATE admissions SET state='admitted' WHERE id=?", a.ID)
		return a, err
	})
}

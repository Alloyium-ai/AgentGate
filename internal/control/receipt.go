// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/ed25519"
	"database/sql"
	"os"
	"path/filepath"

	"alloyium.local/kernel-poc/internal/audit"
)

func writeEvidence(dir string, e Evidence) error {
	for name, data := range map[string][]byte{"grant.jws": []byte(e.Grant), "events.jsonl": []byte(e.Events), "terminal.json": e.Terminal} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) Receipt(op Operation, in IngestInput, spool string) (any, error) {
	op.Action = "evidence.countersigned"
	op.Resource = in.AdmissionID
	op.Reason = safeReason(in.Reason)
	return s.Mutation(op, "evidence:write", false, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		a, err := scanAdmission(tx.QueryRow("SELECT * FROM admissions WHERE id=?", in.AdmissionID))
		if err != nil {
			return nil, notFound(err)
		}
		svc, err := serviceFrom(tx, op.Actor.Subject)
		if err != nil || svc.Kind != "service" || svc.Node != a.Node {
			return nil, fail(403, "node_binding_failed", "Only the enrolled node can request an evidence receipt.")
		}
		if a.Token != in.Evidence.Grant {
			return nil, fail(422, "grant_binding_failed", "The evidence belongs to a different admission.")
		}
		if err = os.MkdirAll(spool, 0700); err != nil {
			return nil, err
		}
		dir, err := os.MkdirTemp(spool, "receipt-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		if err = writeEvidence(dir, in.Evidence); err != nil {
			return nil, err
		}
		key, err := b64.DecodeString(svc.PublicKey)
		if err != nil {
			return nil, err
		}
		seal, err := audit.Countersign(dir, s.Authority, ed25519.PublicKey(key))
		if err != nil {
			return nil, fail(422, "evidence_integrity_failed", "The node commitment or evidence chain does not match the admission.")
		}
		var object string
		if err = tx.QueryRow("SELECT bpf_digest FROM activations WHERE admission_id=?", a.ID).Scan(&object); err != nil {
			return nil, fail(409, "not_admitted", "The node did not confirm policy installation.")
		}
		if seal.Manifest.ObjectDigest != object {
			return nil, fail(422, "program_binding_failed", "The evidence names a different admitted BPF object.")
		}
		op.Run = a.RunID
		op.Version = a.VersionID
		return seal, nil
	})
}

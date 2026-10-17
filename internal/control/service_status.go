// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import "database/sql"

type ServiceStatus struct {
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason"`
}

func (s *Store) SetServiceStatus(op Operation, id string, in ServiceStatus) (any, error) {
	op.Action = "agent.status.changed"
	op.Resource = id
	op.Reason = safeReason(in.Reason)
	return s.Mutation(op, "agents:write", true, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		svc, err := serviceFrom(tx, id)
		if err != nil {
			return nil, notFound(err)
		}
		op.Before = svc
		svc.Enabled = in.Enabled
		_, err = tx.Exec("UPDATE services SET enabled=? WHERE subject=?", in.Enabled, id)
		return svc, err
	})
}

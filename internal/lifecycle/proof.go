// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"encoding/base64"
	"errors"
	"time"
)

func NodeAudience(nodeID string) string { return "agentgate-node.v1:" + nodeID }

// ConsumeProof follows successful signature, enrollment, peer and body checks.
// It rejects nonce replay across requests and manager restarts.
func (j *SQLiteJournal) ConsumeProof(ctx context.Context, subject, nonce string, issuedUnix int64) error {
	now := time.Now().Unix()
	bytes, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if !identifier.MatchString(subject) || err != nil || len(bytes) != 32 || issuedUnix < now-60 || issuedUnix > now+5 {
		return errors.New("the node proof identity, nonce or time is invalid")
	}
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM lifecycle_proof_nonces WHERE expires<=?`, now); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO lifecycle_proof_nonces VALUES(?,?,?) ON CONFLICT(subject,nonce) DO NOTHING`, subject, nonce, issuedUnix+65)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrReplay
	}
	return tx.Commit()
}

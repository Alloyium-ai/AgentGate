// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"alloyium.local/kernel-poc/internal/grant"
	"alloyium.local/kernel-poc/internal/policy"
	"database/sql"
	"time"
)

const targetReportSchema = `
CREATE TABLE IF NOT EXISTS target_challenges(id TEXT PRIMARY KEY,subject TEXT NOT NULL,node TEXT NOT NULL,boot TEXT NOT NULL,public_key TEXT NOT NULL,challenge TEXT NOT NULL UNIQUE,expires INTEGER NOT NULL,used INTEGER NOT NULL,created TEXT NOT NULL,restore_fence INTEGER NOT NULL);
CREATE TRIGGER IF NOT EXISTS target_challenge_binding_immutable BEFORE UPDATE OF id,subject,node,boot,public_key,challenge,created,restore_fence ON target_challenges BEGIN SELECT RAISE(ABORT,'immutable target challenge'); END;
CREATE TABLE IF NOT EXISTS target_reports(digest TEXT PRIMARY KEY,subject TEXT NOT NULL,node TEXT NOT NULL,boot TEXT NOT NULL,challenge_id TEXT NOT NULL UNIQUE REFERENCES target_challenges(id),public_key TEXT NOT NULL,envelope TEXT NOT NULL,received TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS target_report_no_update BEFORE UPDATE ON target_reports BEGIN SELECT RAISE(ABORT,'immutable target report'); END;
CREATE TRIGGER IF NOT EXISTS target_report_no_delete BEFORE DELETE ON target_reports BEGIN SELECT RAISE(ABORT,'immutable target report'); END;
CREATE INDEX IF NOT EXISTS target_report_node ON target_reports(node,received);
`

type TargetChallengeInput struct {
	Node   string `json:"node"`
	Boot   string `json:"boot"`
	Reason string `json:"reason"`
}
type TargetChallenge struct {
	ID        string `json:"id"`
	Node      string `json:"node"`
	Boot      string `json:"boot"`
	Challenge string `json:"challenge"`
	Expires   int64  `json:"expires"`
}
type TargetReportInput struct {
	ChallengeID string `json:"challenge_id"`
	Envelope    string `json:"envelope"`
	Reason      string `json:"reason"`
}
type TargetReportRecord struct {
	Digest   string                  `json:"digest"`
	Subject  string                  `json:"subject"`
	Report   policy.CapabilityReport `json:"report"`
	Received string                  `json:"received_at"`
}

func nodeService(q queryer, subject, node string) (Service, error) {
	svc, err := serviceFrom(q, subject)
	if err != nil || !svc.Enabled || svc.Kind != "service" || svc.Node != node {
		return Service{}, fail(403, "node_binding_failed", "This active service does not own the target node.")
	}
	return svc, nil
}

func (s *Store) CreateTargetChallenge(op Operation, in TargetChallengeInput) (any, error) {
	op.Action = "target.challenge.issued"
	op.Resource = in.Node
	op.Reason = safeReason(in.Reason)
	return s.Mutation(op, "target:write", false, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		if len(in.Node) == 0 || len(in.Node) > 100 || len(in.Boot) == 0 || len(in.Boot) > 100 {
			return nil, fail(422, "invalid_target", "Supply bounded node and boot identities.")
		}
		svc, err := nodeService(tx, op.Actor.Subject, in.Node)
		if err != nil {
			return nil, err
		}
		var pending int
		now := time.Now().Unix()
		if err = tx.QueryRow("SELECT count(*) FROM target_challenges WHERE subject=? AND used=0 AND expires>?", svc.Subject, now).Scan(&pending); err != nil {
			return nil, err
		}
		if pending >= 4 {
			return nil, fail(429, "target_challenge_limit", "This node already has four current target challenges.")
		}
		challenge := TargetChallenge{newID(), in.Node, in.Boot, randomToken(), now + 60}
		fence, err := currentRestoreFence(tx)
		if err != nil {
			return nil, err
		}
		_, err = tx.Exec("INSERT INTO target_challenges VALUES(?,?,?,?,?,?,?,?,?,?)", challenge.ID, svc.Subject, in.Node, in.Boot, svc.PublicKey, challenge.Challenge, challenge.Expires, 0, stamp(), fence)
		return challenge, err
	})
}

func (s *Store) PutTargetReport(op Operation, in TargetReportInput) (any, error) {
	op.Action = "target.report.accepted"
	op.Resource = in.ChallengeID
	op.Reason = safeReason(in.Reason)
	return s.Mutation(op, "target:write", false, func(tx *sql.Tx, op *Operation) (any, error) {
		if err := reasonValid(in.Reason); err != nil {
			return nil, err
		}
		var subject, node, boot, key, challenge string
		var expires, fence int64
		var used bool
		err := tx.QueryRow("SELECT subject,node,boot,public_key,challenge,expires,used,restore_fence FROM target_challenges WHERE id=?", in.ChallengeID).Scan(&subject, &node, &boot, &key, &challenge, &expires, &used, &fence)
		if err != nil || subject != op.Actor.Subject || used || time.Now().Unix() >= expires {
			return nil, fail(409, "target_challenge_invalid", "The target challenge expired, changed, or already has a report.")
		}
		if err = targetAfterRestore(tx, fence); err != nil {
			return nil, err
		}
		svc, err := nodeService(tx, subject, node)
		if err != nil {
			return nil, err
		}
		if svc.PublicKey != key {
			return nil, fail(409, "target_key_changed", "Create a new target challenge after a node key change.")
		}
		pub, err := grant.Public(key)
		if err != nil {
			return nil, err
		}
		target, err := policy.VerifyTarget([]byte(in.Envelope), pub, policy.TargetBinding{Node: node, Boot: boot, Challenge: challenge}, time.Now().Unix())
		if err != nil {
			return nil, fail(422, "invalid_target_report", err.Error())
		}
		received := stamp()
		_, err = tx.Exec("INSERT INTO target_reports VALUES(?,?,?,?,?,?,?,?)", target.Digest(), subject, node, boot, in.ChallengeID, key, in.Envelope, received)
		if err != nil {
			return nil, err
		}
		if _, err = tx.Exec("UPDATE target_challenges SET used=1 WHERE id=?", in.ChallengeID); err != nil {
			return nil, err
		}
		op.Resource = target.Digest()
		return TargetReportRecord{target.Digest(), subject, target.Report(), received}, nil
	})
}

func currentRestoreFence(q queryer) (int64, error) {
	var fence int64
	err := q.QueryRow("SELECT COALESCE(MAX(id),0) FROM audit WHERE action='backup.restored' AND result='committed'").Scan(&fence)
	return fence, err
}
func targetAfterRestore(q queryer, fence int64) error {
	restored, err := currentRestoreFence(q)
	if err != nil {
		return err
	}
	if restored != fence {
		return fail(409, "target_restore_fenced", "Restore requires a new target challenge and report.")
	}
	return nil
}

func verifiedStoredTarget(q queryer, id string, expected policy.TargetBinding) (policy.VerifiedTarget, TargetReportRecord, error) {
	var record TargetReportRecord
	var node, boot, key, envelope, challenge string
	var fence int64
	err := q.QueryRow("SELECT r.digest,r.subject,r.node,r.boot,r.public_key,r.envelope,r.received,c.challenge,c.restore_fence FROM target_reports r JOIN target_challenges c ON c.id=r.challenge_id WHERE r.digest=?", id).Scan(&record.Digest, &record.Subject, &node, &boot, &key, &envelope, &record.Received, &challenge, &fence)
	if err != nil {
		return policy.VerifiedTarget{}, record, notFound(err)
	}
	if err = targetAfterRestore(q, fence); err != nil {
		return policy.VerifiedTarget{}, record, err
	}
	if expected.Node != "" && (expected.Node != node || expected.Boot != boot) {
		return policy.VerifiedTarget{}, record, fail(409, "target_binding_failed", "The target report belongs to another node or boot.")
	}
	svc, err := nodeService(q, record.Subject, node)
	if err != nil {
		return policy.VerifiedTarget{}, record, err
	}
	if svc.PublicKey != key {
		return policy.VerifiedTarget{}, record, fail(409, "target_key_changed", "The target report uses a previous node key.")
	}
	pub, err := grant.Public(key)
	if err != nil {
		return policy.VerifiedTarget{}, record, err
	}
	target, err := policy.VerifyTarget([]byte(envelope), pub, policy.TargetBinding{Node: node, Boot: boot, Challenge: challenge}, time.Now().Unix())
	if err != nil {
		return policy.VerifiedTarget{}, record, fail(409, "target_report_stale", err.Error())
	}
	if target.Digest() != id {
		return policy.VerifiedTarget{}, record, fail(409, "target_digest_changed", "The stored target report differs from its digest.")
	}
	record.Report = target.Report()
	return target, record, nil
}

func (s *Store) TargetReport(id string, actor Actor) (any, error) {
	// Keep current enrollment and the report read in one transaction.
	tx, err := s.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	_, record, err := verifiedStoredTarget(tx, id, policy.TargetBinding{})
	if err == nil && actor.Kind != "human" && actor.Subject != record.Subject {
		return nil, fail(403, "forbidden", "A machine can read only its own target report.")
	}
	return record, err
}

func decodeTargetBody(data []byte, dst any) error {
	if _, err := policy.ReadJSON(data); err != nil {
		return fail(422, "invalid_json", "Supply one target request with unique fields.")
	}
	return decodeBody(data, dst)
}

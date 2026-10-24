// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// JobRecord is a queued host job as the API shows it. The signed envelope
// and any ciphertext stay server side.
type JobRecord struct {
	ID           string          `json:"id"`
	Type         string          `json:"type"`
	TargetID     string          `json:"target_id"`
	LaunchID     string          `json:"launch_id,omitempty"`
	SecretID     string          `json:"secret_id,omitempty"`
	SpecDigest   string          `json:"spec_digest,omitempty"`
	PolicyDigest string          `json:"policy_digest,omitempty"`
	KeyID        string          `json:"key_id"`
	State        string          `json:"state"`
	Attempts     int             `json:"attempts"`
	Created      string          `json:"created_at"`
	Deadline     string          `json:"deadline"`
	Completed    string          `json:"completed_at,omitempty"`
	Result       json.RawMessage `json:"result,omitempty"`
	EventSeq     uint32          `json:"event_seq"`
	revision     int
	envelope     string
	deadlineMS   int64
	deliveredMS  int64
}

const jobColumns = "id,type,target_id,launch_id,secret_id,spec_digest,policy_digest,key_id,envelope,state,attempts,created,deadline,delivered,completed,result,event_seq,revision"

func scanJob(row rowScanner) (JobRecord, error) {
	var j JobRecord
	var result string
	err := row.Scan(&j.ID, &j.Type, &j.TargetID, &j.LaunchID, &j.SecretID, &j.SpecDigest, &j.PolicyDigest, &j.KeyID, &j.envelope, &j.State, &j.Attempts, &j.Created, &j.deadlineMS, &j.deliveredMS, &j.Completed, &result, &j.EventSeq, &j.revision)
	if err != nil {
		return j, err
	}
	j.Deadline = time.UnixMilli(j.deadlineMS).UTC().Format(time.RFC3339Nano)
	if result != "" {
		j.Result = json.RawMessage(result)
	}
	return j, nil
}

func jobFrom(q queryer, id string) (JobRecord, error) {
	j, err := scanJob(q.QueryRow("SELECT "+jobColumns+" FROM jobs WHERE id=?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return j, fail(404, "not_found", "The job does not exist.")
	}
	return j, err
}

// jobSpec is what enqueueJob signs.
type jobSpec struct {
	Type     string
	TargetID string
	Launch   *launchRow
	SecretID string
	Payload  any
	Deadline time.Time
	Reason   string
	Actor    Actor
}

// enqueueJob signs a job with the active job key and queues it. Signing at
// enqueue time means a delivered job is byte-for-byte the job that was
// audited. The caller holds the store lock and the transaction.
func (s *Store) enqueueJob(tx *sql.Tx, spec jobSpec, op *Operation) (string, error) {
	payload, err := json.Marshal(spec.Payload)
	if err != nil {
		return "", err
	}
	now := s.now()
	job := hostproto.Job{Version: hostproto.JobVersion, ID: newID(), Type: spec.Type, TargetID: spec.TargetID, IssuedAtMS: now.UnixMilli(), DeadlineMS: spec.Deadline.UnixMilli(), Payload: payload}
	if spec.Launch != nil {
		job.LaunchID, job.SpecDigest, job.PolicyDigest = spec.Launch.ID, spec.Launch.SpecDigest, spec.Launch.PolicyDigest
	}
	if spec.Type == hostproto.JobApplyProfile || spec.Type == hostproto.JobSnapshotMount {
		job.SpecDigest, job.PolicyDigest = "", ""
		if spec.Type == hostproto.JobApplyProfile {
			var p hostproto.ApplyProfilePayload
			json.Unmarshal(payload, &p)
			job.PolicyDigest = hostproto.SHA256Hex(p.Policy)
		}
		if spec.Type == hostproto.JobSnapshotMount && spec.Launch != nil {
			job.SpecDigest = spec.Launch.SpecDigest
		}
	}
	// The service applies the same checks a host will, so it never queues a
	// job that an honest host must reject.
	if _, err = job.Check(spec.TargetID, now); err != nil {
		return "", fail(500, "job_invalid", "The service built a job that fails its own protocol checks.")
	}
	env, err := hostproto.Seal(hostproto.DomainJob, s.JobKey, job)
	if err != nil {
		return "", err
	}
	_, err = tx.Exec("INSERT INTO jobs VALUES(?,?,?,?,?,?,?,?,?,'queued',0,?,?,0,'','',0,1)", job.ID, job.Type, job.TargetID, job.LaunchID, spec.SecretID, job.SpecDigest, job.PolicyDigest, env.KeyID, jsonText(env), stamp(), job.DeadlineMS)
	if err != nil {
		return "", err
	}
	audit := Operation{Actor: spec.Actor, Action: "job.queued", Resource: "job:" + job.ID, Run: job.LaunchID, Reason: spec.Reason,
		After: map[string]any{"type": job.Type, "target_id": job.TargetID, "launch_id": job.LaunchID, "spec_digest": job.SpecDigest, "policy_digest": job.PolicyDigest, "key_id": env.KeyID, "deadline": time.UnixMilli(job.DeadlineMS).UTC().Format(time.RFC3339)}}
	if op != nil {
		audit.RequestID, audit.CorrelationID = op.RequestID, op.CorrelationID
	}
	if audit.Reason == "" {
		audit.Reason = "Queue a host job"
	}
	if _, err = appendAudit(tx, audit, "committed"); err != nil {
		return "", err
	}
	return job.ID, nil
}

// cancelJob cancels a job that was never delivered.
func cancelJob(tx *sql.Tx, id string) (bool, error) {
	res, err := tx.Exec("UPDATE jobs SET state='cancelled',envelope='',completed=?,revision=revision+1 WHERE id=? AND state='queued'", stamp(), id)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// LaunchJobs lists the jobs of one launch.
func (s *Store) LaunchJobs(launchID string) ([]JobRecord, error) {
	rows, err := s.DB.Query("SELECT "+jobColumns+" FROM jobs WHERE launch_id=? ORDER BY created LIMIT 100", launchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JobRecord{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

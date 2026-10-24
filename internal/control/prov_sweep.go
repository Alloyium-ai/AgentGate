// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"context"
	"database/sql"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

var scheduler = Actor{Subject: "agentgate-scheduler", Kind: "system"}

// SweepResult counts what one sweep changed.
type SweepResult struct {
	LostHost        int `json:"lost_host"`
	Expired         int `json:"expired"`
	JobsExpired     int `json:"jobs_expired"`
	ApprovalTimeout int `json:"approval_timeout"`
}

// Sweep applies every time-based rule once:
//   - a launch on a host without a verified poll for MissedHeartbeatsLimit
//     intervals fails with lost_host and gets a stop job the host runs when it
//     returns;
//   - a launch past its lifetime moves to stopping with a stop job;
//   - a job past its deadline that was never delivered expires, and its
//     launch fails as not_started;
//   - a launch waiting for approval longer than ApprovalTimeout is cancelled.
func (s *Store) Sweep() (SweepResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out SweepResult
	tx, err := s.DB.Begin()
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	now := s.now()
	ids := func(query string, args ...any) ([]string, error) {
		rows, err := tx.Query(query, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		list := []string{}
		for rows.Next() {
			var id string
			if err = rows.Scan(&id); err != nil {
				return nil, err
			}
			list = append(list, id)
		}
		return list, rows.Err()
	}
	// Heartbeat loss.
	lost, err := ids(`SELECT l.id FROM launches l JOIN targets t ON t.id=l.target_id
		WHERE (l.state IN ('provisioning','running','stopping') OR (l.state='queued' AND EXISTS (SELECT 1 FROM jobs j WHERE j.launch_id=l.id AND j.type='launch' AND j.state<>'queued' AND j.state<>'cancelled')))
		AND t.last_seen < ? - t.heartbeat_seconds*1000*?`, now.UnixMilli(), hostproto.MissedHeartbeatsLimit)
	if err != nil {
		return out, err
	}
	for _, id := range lost {
		l, err := launchFrom(tx, id)
		if err != nil {
			return out, err
		}
		if err = s.transitionLaunch(tx, &l, transition{To: StateFailed, Reason: "lost_host: no verified heartbeat for three intervals", EvidenceMissing: MissingLostHost, Actor: scheduler}); err != nil {
			return out, err
		}
		if err = s.queueStop(tx, &l, "lost-host", scheduler, nil); err != nil {
			return out, err
		}
		out.LostHost++
	}
	// Lifetime expiry.
	expired, err := ids("SELECT id FROM launches WHERE state IN ('queued','provisioning','running') AND expires_at>0 AND expires_at<=?", now.UnixMilli())
	if err != nil {
		return out, err
	}
	for _, id := range expired {
		l, err := launchFrom(tx, id)
		if err != nil {
			return out, err
		}
		if err = s.stopLocked(tx, &l, expiredReason, "expired", scheduler, nil); err != nil {
			return out, err
		}
		out.Expired++
	}
	// Undelivered jobs past their deadline.
	stale, err := ids("SELECT id FROM jobs WHERE state='queued' AND deadline<=?", now.UnixMilli())
	if err != nil {
		return out, err
	}
	for _, id := range stale {
		job, err := jobFrom(tx, id)
		if err != nil {
			return out, err
		}
		if _, err = tx.Exec("UPDATE jobs SET state='expired',envelope='',completed=?,revision=revision+1 WHERE id=? AND state='queued'", stamp(), id); err != nil {
			return out, err
		}
		if _, err = appendAudit(tx, Operation{Actor: scheduler, Action: "job.expired", Resource: "job:" + id, Run: job.LaunchID, Reason: "The job passed its deadline before delivery", RequestID: "scheduler-" + newID()}, "committed"); err != nil {
			return out, err
		}
		if job.Type == hostproto.JobSecretPut {
			if _, err = tx.Exec("UPDATE secrets SET state='failed',updated=?,revision=revision+1 WHERE id=? AND state='pending'", stamp(), job.SecretID); err != nil {
				return out, err
			}
		}
		if job.LaunchID != "" && job.Type == hostproto.JobLaunch {
			l, err := launchFrom(tx, job.LaunchID)
			if err != nil {
				return out, err
			}
			if !TerminalState(l.State) {
				if err = s.transitionLaunch(tx, &l, transition{To: StateFailed, Reason: "job_expired: the host never collected the launch job", EvidenceMissing: MissingNotStarted, Actor: scheduler}); err != nil {
					return out, err
				}
			}
		}
		out.JobsExpired++
	}
	// Ciphertext never outlives its job deadline, delivered or not.
	if _, err = tx.Exec("UPDATE jobs SET envelope='' WHERE type='secret-put' AND envelope<>'' AND deadline<=?", now.UnixMilli()); err != nil {
		return out, err
	}
	// Approval timeout.
	waiting, err := ids("SELECT id FROM launches WHERE state='approval_pending' AND created<=?", now.Add(-s.Provisioning.approvalTimeout()).UTC().Format("2006-01-02T15:04:05.000000000Z"))
	if err != nil {
		return out, err
	}
	for _, id := range waiting {
		l, err := launchFrom(tx, id)
		if err != nil {
			return out, err
		}
		if err = s.transitionLaunch(tx, &l, transition{To: StateCancelled, Reason: "approval_timeout: no decision in time", EvidenceMissing: MissingNotStarted, Actor: scheduler}); err != nil {
			return out, err
		}
		out.ApprovalTimeout++
	}
	if out == (SweepResult{}) {
		return out, nil
	}
	var last int64
	tx.QueryRow("SELECT max(id) FROM audit").Scan(&last)
	if err = tx.Commit(); err != nil {
		return out, err
	}
	s.notify(last)
	return out, nil
}

// RunSweeper sweeps every interval until ctx ends.
func (s *Store) RunSweeper(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = s.Provisioning.pollInterval()
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.Sweep()
		}
	}
}

var _ = sql.ErrNoRows

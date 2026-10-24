// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"
)

// Event kinds.
const (
	EventProgress = "progress" // a human-readable step
	EventLog      = "log"      // bounded agent output
	EventState    = "state"    // the launch reached State (provisioning, running, stopping)
	EventResult   = "result"   // the final event of a job; carries Result
)

// Event bounds.
const (
	MaxEventsPerBatch  = 64
	MaxEventsPerJob    = 4096
	MaxEventMessage    = 8192
	MaxEventBatchBytes = 256 << 10
)

// Event is one ordered job event. Seq starts at 1 for each job and is
// contiguous. Re-sending an event the service already holds is accepted when
// it is byte-for-byte identical and rejected as a conflict otherwise.
type Event struct {
	Seq     uint32     `json:"seq"`
	TimeMS  int64      `json:"time_ms"`
	Kind    string     `json:"kind"`
	Message string     `json:"message,omitempty"`
	Stream  string     `json:"stream,omitempty"`
	State   string     `json:"state,omitempty"`
	Result  *JobResult `json:"result,omitempty"`
}

// Result statuses.
const (
	ResultSucceeded = "succeeded"
	ResultFailed    = "failed"
	// ResultRejected means the host refused the job (bad signature, expired,
	// unknown type, digest mismatch, unsupported capability) and did nothing.
	ResultRejected = "rejected"
)

// JobResult is the outcome of one job. A launch, stop or collect result
// carries the Receipt, or names why evidence is missing. A successful
// secret-put carries the host's SecretReceipt for the sealing client.
type JobResult struct {
	Status          string         `json:"status"`
	Reason          string         `json:"reason"`
	Receipt         *Receipt       `json:"receipt,omitempty"`
	EvidenceMissing string         `json:"evidence_missing,omitempty"`
	SecretReceipt   *SecretReceipt `json:"secret_receipt,omitempty"`
}

// EventsRequest is sealed under DomainEvents with the enrolled host key and
// posted to PathEvents for JobID.
type EventsRequest struct {
	Header
	JobID  string  `json:"job_id"`
	Events []Event `json:"events"`
}

// EventsResponse acknowledges every event through AcceptedThrough. The host
// may delete its local copy of acknowledged events, but keeps the receipt on
// disk until the job is Completed.
type EventsResponse struct {
	AcceptedThrough uint32 `json:"accepted_through"`
	Completed       bool   `json:"completed"`
	JobState        string `json:"job_state"`
}

// Check validates the batch shape: ordering, bounds, kinds and that a result
// event, if present, is the last one.
func (e EventsRequest) Check(now time.Time) error {
	if err := e.Header.Check(now); err != nil {
		return err
	}
	if !validID(e.JobID) {
		return errors.New("hostproto: job id invalid")
	}
	if len(e.Events) < 1 || len(e.Events) > MaxEventsPerBatch {
		return errors.New("hostproto: 1 to 64 events per batch")
	}
	raw, _ := json.Marshal(e.Events)
	if len(raw) > MaxEventBatchBytes {
		return errors.New("hostproto: event batch exceeds its size limit")
	}
	for i, ev := range e.Events {
		if ev.Seq == 0 || ev.Seq > MaxEventsPerJob || i > 0 && ev.Seq != e.Events[i-1].Seq+1 {
			return errors.New("hostproto: event sequence must be contiguous from 1")
		}
		if ev.TimeMS <= 0 || time.UnixMilli(ev.TimeMS).After(now.Add(MaxClockSkew)) {
			return errors.New("hostproto: event time invalid")
		}
		if len(ev.Message) > MaxEventMessage || !utf8.ValidString(ev.Message) {
			return errors.New("hostproto: event message too large or not UTF-8")
		}
		switch ev.Kind {
		case EventProgress:
			if ev.Stream != "" || ev.State != "" || ev.Result != nil {
				return errors.New("hostproto: progress event carries foreign fields")
			}
		case EventLog:
			if (ev.Stream != "stdout" && ev.Stream != "stderr") || ev.State != "" || ev.Result != nil {
				return errors.New("hostproto: log event needs stream stdout or stderr")
			}
		case EventState:
			if (ev.State != "provisioning" && ev.State != "running" && ev.State != "stopping") || ev.Stream != "" || ev.Result != nil {
				return errors.New("hostproto: state event needs provisioning, running or stopping")
			}
		case EventResult:
			if ev.Result == nil || ev.Stream != "" || ev.State != "" || i != len(e.Events)-1 {
				return errors.New("hostproto: a result event carries a result and ends the batch")
			}
			if err := ev.Result.check(); err != nil {
				return err
			}
		default:
			return errors.New("hostproto: unknown event kind")
		}
	}
	return nil
}

func (r JobResult) check() error {
	if r.Status != ResultSucceeded && r.Status != ResultFailed && r.Status != ResultRejected {
		return errors.New("hostproto: result status invalid")
	}
	if !reasonPattern.MatchString(r.Reason) {
		return errors.New("hostproto: result reason must be a short code")
	}
	if r.EvidenceMissing != "" && !reasonPattern.MatchString(r.EvidenceMissing) {
		return errors.New("hostproto: evidence_missing must be a short code")
	}
	if r.Receipt != nil && r.EvidenceMissing != "" {
		return errors.New("hostproto: a result has a receipt or names missing evidence, not both")
	}
	if r.SecretReceipt != nil {
		if r.Receipt != nil || r.EvidenceMissing != "" || r.Status != ResultSucceeded {
			return errors.New("hostproto: a secret receipt belongs only to a successful secret-put result")
		}
		if err := r.SecretReceipt.Check(); err != nil {
			return err
		}
	}
	return nil
}

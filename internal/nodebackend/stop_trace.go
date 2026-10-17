// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"encoding/json"
	"io"
)

// stopTrace records private fixture diagnostics. It supplies no audit coverage.
type stopTrace struct {
	clock    lifecycle.Clock
	out      io.Writer
	run      string
	last     uint64
	clockErr error
}
type stopPhase struct {
	Protocol   string  `json:"protocol"`
	RunID      string  `json:"run_id"`
	Phase      string  `json:"phase"`
	StartedNS  uint64  `json:"started_mono_ns,string"`
	FinishedNS uint64  `json:"finished_mono_ns,string"`
	ElapsedNS  *uint64 `json:"elapsed_ns,string,omitempty"`
	Error      string  `json:"error,omitempty"`
	ClockError string  `json:"clock_error,omitempty"`
}

func newStopTrace(clock lifecycle.Clock, out io.Writer, run string) *stopTrace {
	mono, err := clock.NowNS()
	return &stopTrace{clock: clock, out: out, run: run, last: mono, clockErr: err}
}
func (t *stopTrace) phase(name string, problem error) {
	if t == nil {
		return
	}
	now, err := t.clock.NowNS()
	r := stopPhase{Protocol: "agentgate.stop-phase.v1", RunID: t.run, Phase: name, StartedNS: t.last, FinishedNS: now}
	if t.clockErr != nil || err != nil || t.last == 0 || now < t.last {
		r.ClockError = "the stop phase clock is unavailable or inconsistent"
	} else {
		elapsed := now - t.last
		r.ElapsedNS = &elapsed
	}
	if problem != nil {
		r.Error = problem.Error()
		if len(r.Error) > 512 {
			r.Error = r.Error[:512]
		}
	}
	_ = json.NewEncoder(t.out).Encode(r)
	t.last = now
	t.clockErr = err
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type phaseClock struct {
	values  []uint64
	failure error
}

func (c *phaseClock) NowNS() (uint64, error) {
	value := c.values[0]
	c.values = c.values[1:]
	return value, c.failure
}
func TestStopTraceRetainsActualPhaseClocksAndBoundedErrors(t *testing.T) {
	var out bytes.Buffer
	trace := newStopTrace(&phaseClock{values: []uint64{10, 25, 80}}, &out, "owned-run")
	trace.phase("resource-close", nil)
	trace.phase("domain-remove", errors.New(strings.Repeat("x", 800)))
	decode := json.NewDecoder(&out)
	var first, second stopPhase
	if decode.Decode(&first) != nil || decode.Decode(&second) != nil {
		t.Fatal("phase output differs")
	}
	if first.StartedNS != 10 || first.FinishedNS != 25 || first.ElapsedNS == nil || *first.ElapsedNS != 15 || first.Error != "" || first.ClockError != "" {
		t.Fatal(first)
	}
	if second.RunID != "owned-run" || second.StartedNS != 25 || second.FinishedNS != 80 || second.ElapsedNS == nil || *second.ElapsedNS != 55 || len(second.Error) != 512 {
		t.Fatal(second)
	}
}
func TestStopTraceDoesNotInventDurationForBrokenClocks(t *testing.T) {
	for _, clock := range []*phaseClock{{values: []uint64{10, 9}}, {values: []uint64{0, 0}, failure: errors.New("clock read failed")}} {
		var out bytes.Buffer
		trace := newStopTrace(clock, &out, "owned-run")
		trace.phase("domain-stop", nil)
		var r stopPhase
		if json.Unmarshal(out.Bytes(), &r) != nil || r.ElapsedNS != nil || r.ClockError == "" {
			t.Fatal(out.String())
		}
	}
	var disabled *stopTrace
	disabled.phase("disabled", nil)
}

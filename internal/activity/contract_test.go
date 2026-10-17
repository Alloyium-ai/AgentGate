// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package activity

import (
	"strings"
	"testing"
)

func decisionFixture() Event {
	return Event{SchemaVersion: SchemaVersion, Node: "node", Boot: "boot", Sequence: 1, Correlation: Correlation{Agent: "agent", Job: "job", GrantDigest: strings.Repeat("a", 64), PolicyVersion: "version", PolicyDigest: strings.Repeat("b", 64), Process: Process{42, 100}}, Kind: "decision", Operation: "file.read", ResourceID: strings.Repeat("c", 64), Decision: "allow", Redacted: true}
}
func TestAllowedAttemptDoesNotBecomeSuccessfulOutcome(t *testing.T) {
	e := decisionFixture()
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	e.Outcome = "succeeded"
	if e.Validate() == nil {
		t.Fatal("an allowed attempt claimed a successful outcome")
	}
	e.Kind = "outcome"
	e.Decision = ""
	e.AttemptSequence = 1
	e.Sequence = 2
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	e.AttemptSequence = 2
	if e.Validate() == nil {
		t.Fatal("an outcome referred to its own sequence")
	}
}
func TestProcessReuseAndNodeIdentityRemainDistinct(t *testing.T) {
	e := decisionFixture()
	other := e
	other.Boot = "another-boot"
	if e.ID() == other.ID() {
		t.Fatal("another boot reused an event identity")
	}
	e.Node = "a:b"
	e.Boot = "c"
	other.Node = "a"
	other.Boot = "b:c"
	if e.ID() == other.ID() {
		t.Fatal("identity separators collided")
	}
	e = decisionFixture()
	e.Correlation.Process.StartNS = 0
	if e.Validate() == nil {
		t.Fatal("a PID without process start time accepted correlation")
	}
	e = decisionFixture()
	e.ResourceID = "/run/secrets/credential"
	if e.Validate() == nil {
		t.Fatal("a raw resource name entered the default event contract")
	}
}

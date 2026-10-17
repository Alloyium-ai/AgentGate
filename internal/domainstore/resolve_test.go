// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package domainstore

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"strings"
	"testing"
)

func TestPureReservationNameIsNotAnOwnershipProof(t *testing.T) {
	proof := proofFixture()
	b := bindingFixture(proof)
	name, err := ReservationName(proof.OwnedPrefix, b)
	if err != nil {
		t.Fatal(err)
	}
	b.CgroupID = 123
	resolved, err := ReservationName(proof.OwnedPrefix, b)
	if err != nil || resolved != name {
		t.Fatal("resolution changed the immutable name", err)
	}
	for _, prefix := range []string{"/", "../system.slice", "alloyium-poc-job-"} {
		if _, err = ReservationName(prefix, b); err == nil {
			t.Fatal("an unsafe pure name input passed")
		}
	}
	b.AgentKey = "not-an-enrolled-public-key"
	if _, err = ReservationName(proof.OwnedPrefix, b); err == nil {
		t.Fatal("an invalid binding derived a name")
	}
}
func TestResolveRejectsEveryChangedBindingField(t *testing.T) {
	s := unitStore(t)
	r := unitReservation(t, s)
	resolved, err := s.resolveLocked(s.stateFD, r.Binding)
	if err != nil || resolved.Binding.CgroupID != 0 {
		t.Fatal("an absent reserved allocation did not resolve safely", err)
	}
	for _, change := range []func(*lifecycle.Binding){func(b *lifecycle.Binding) { b.AgentID = "another-agent" }, func(b *lifecycle.Binding) { b.GrantID = "another-grant" }, func(b *lifecycle.Binding) { b.PolicyDigest = strings.Repeat("a", 64) }, func(b *lifecycle.Binding) { b.Generation++ }, func(b *lifecycle.Binding) { b.DeadlineNS-- }, func(b *lifecycle.Binding) { b.CgroupID = 55 }} {
		changed := copyValue(r.Binding)
		change(&changed)
		if _, err = s.resolveLocked(s.stateFD, changed); err == nil {
			t.Fatal("a changed reservation query passed")
		}
	}
}
func TestResolvedBindingSurvivesTerminalAbsenceAndCannotChange(t *testing.T) {
	s := unitStore(t)
	r := unitReservation(t, s)
	original := copyValue(r.Binding)
	r.Binding.CgroupID = 123
	r.State = "terminated"
	r.TerminationReadback = strings.Repeat("b", 64)
	if err := s.save(&r); err != nil {
		t.Fatal(err)
	}
	resolved, err := s.resolveLocked(s.stateFD, original)
	if err != nil || resolved.Binding.CgroupID != 123 {
		t.Fatal("cleanup lost the actual resolved binding", err)
	}
	original.CgroupID = 124
	if _, err = s.resolveLocked(s.stateFD, original); err == nil {
		t.Fatal("a caller replaced the actual cgroup identity")
	}
}
func TestResolutionCannotInventAbsenceForAnActiveAllocation(t *testing.T) {
	s := unitStore(t)
	r := unitReservation(t, s)
	original := copyValue(r.Binding)
	r.Binding.CgroupID = 123
	r.State = "placed"
	if err := s.save(&r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.resolveLocked(s.stateFD, original); err == nil {
		t.Fatal("an unconfirmed active allocation became no-domain proof")
	}
	if _, err := s.Resolve(context.Background(), original); err == nil {
		t.Fatal("a synthetic root proof qualified live resolution")
	}
}

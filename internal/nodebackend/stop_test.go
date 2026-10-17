// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"context"
	"errors"
	"testing"
)

func TestCancellationPreservesJoinedStopFailure(t *testing.T) {
	failure := errors.New("whole-domain-stop-failed")
	got := nonCancellationErrors(errors.Join(context.Canceled, failure))
	if len(got) != 1 || got[0] != failure {
		t.Fatal(got)
	}
	if len(nonCancellationErrors(errors.Join(context.Canceled))) != 0 {
		t.Fatal("the normal cancellation is a stop failure")
	}
}
func TestStopQueryResolvesOnlyTheDomainID(t *testing.T) {
	actual := pinBinding()
	query := copyValue(actual)
	query.CgroupID = 0
	if !sameQuery(actual, query) {
		t.Fatal("the unresolved query differs")
	}
	for _, change := range []func(){func() { query.RunID = "other" }, func() { query.ArtifactDigests["node"] = "changed" }, func() { query.Generation++ }} {
		query = copyValue(actual)
		query.CgroupID = 0
		change()
		if sameQuery(actual, query) {
			t.Fatal("a changed immutable field resolved")
		}
	}
}
func TestExplicitLimitsHaveFiniteBounds(t *testing.T) {
	for _, l := range []Limits{{}, {16 << 20, 0, 1000}, {16 << 20, 1, 0}, {9 << 30, 1, 1000}, {16 << 20, 1025, 1000}, {16 << 20, 1, 200001}} {
		if l.validate() == nil {
			t.Fatalf("invalid limits accepted: %+v", l)
		}
	}
	if (Limits{64 << 20, 16, 10000}).validate() != nil {
		t.Fatal("bounded explicit limits rejected")
	}
}

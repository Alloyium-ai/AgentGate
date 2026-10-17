// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"errors"
	"math"
	"testing"
)

func TestGenerationFloorReadsDurableScopedStateWithoutAllocation(t *testing.T) {
	j := journalFixture(t)
	ctx := context.Background()
	b := fixtureBinding()
	floor, err := j.GenerationFloor(ctx, b.AgentID, b.NodeID, b.BootID)
	if err != nil || floor != 0 {
		t.Fatal("fresh floor differs", floor, err)
	}
	var count int
	if err = j.db.QueryRow(`SELECT count(*) FROM lifecycle_generations`).Scan(&count); err != nil || count != 0 {
		t.Fatal("a floor read allocated a generation", err)
	}
	r := Record{Binding: b, Revision: 1, State: "preparing", Evidence: []Evidence{}}
	if err = j.Save(ctx, r, 0); err != nil {
		t.Fatal(err)
	}
	floor, err = j.GenerationFloor(ctx, b.AgentID, b.NodeID, b.BootID)
	if err != nil || floor != 1 {
		t.Fatal("durable floor differs", floor, err)
	}
	for _, scope := range [][3]string{{"other-agent", b.NodeID, b.BootID}, {b.AgentID, "other-node", b.BootID}, {b.AgentID, b.NodeID, "other-boot"}} {
		floor, err = j.GenerationFloor(ctx, scope[0], scope[1], scope[2])
		if err != nil || floor != 0 {
			t.Fatal("generation floor crossed an identity boundary", err)
		}
	}
	stale := r
	stale.Binding.RunID = "other-run"
	if err = j.Save(ctx, stale, 0); !errors.Is(err, ErrReplay) {
		t.Fatal("a floor read bypassed the atomic replay gate", err)
	}
	reopened, err := OpenJournal(j.path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	floor, err = reopened.GenerationFloor(ctx, b.AgentID, b.NodeID, b.BootID)
	if err != nil || floor != 1 {
		t.Fatal("a reopened journal lost its floor", err)
	}
}
func TestGenerationFloorRejectsInvalidExhaustedAndUnavailableState(t *testing.T) {
	for _, value := range []any{"invalid", 1.5, math.MaxInt64} {
		t.Run("invalid-storage", func(t *testing.T) {
			j := journalFixture(t)
			ctx := context.Background()
			b := fixtureBinding()
			if _, err := j.db.Exec(`INSERT INTO lifecycle_generations VALUES(?,?,?,?)`, b.AgentID, b.NodeID, b.BootID, value); err != nil {
				t.Fatal(err)
			}
			if _, err := j.GenerationFloor(ctx, b.AgentID, b.NodeID, b.BootID); err == nil {
				t.Fatal("an invalid or exhausted floor passed")
			}
		})
	}
	j := journalFixture(t)
	b := fixtureBinding()
	if _, err := j.GenerationFloor(context.Background(), "../invalid", b.NodeID, b.BootID); err == nil {
		t.Fatal("an invalid identity passed")
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := j.GenerationFloor(context.Background(), b.AgentID, b.NodeID, b.BootID); err == nil {
		t.Fatal("a closed journal returned a floor")
	}
}

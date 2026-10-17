// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobaudit

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math"
	"testing"
	"time"
)

func expiryFixture() GrantExpiry {
	return GrantExpiry{ExpiresAt: 160, WallSampleUnixNS: int64(141 * time.Second), MonoSampleNS: uint64(1500 * time.Millisecond), MonoAfterNS: uint64(1501 * time.Millisecond), KernelDeadlineNS: uint64(20500 * time.Millisecond)}
}
func (f *fixture) bound(t *testing.T) {
	t.Helper()
	f.clock.now = uint64(1502 * time.Millisecond)
	raw, err := json.Marshal(struct {
		State       string      `json:"state"`
		GrantExpiry GrantExpiry `json:"grant_expiry"`
	}{"grant_expiry_bound", expiryFixture()})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.w.Append(context.Background(), "lifecycle", raw); err != nil {
		t.Fatal(err)
	}
	f.clock.now = uint64(10 * time.Second)
}
func TestGrantExpiryUsesExactConservativePairedClock(t *testing.T) {
	b := lifecycle.Binding{DeadlineNS: uint64(21 * time.Second)}
	for _, test := range []struct {
		name   string
		change func(*GrantExpiry, *lifecycle.Binding)
		valid  bool
	}{
		{"exact", func(*GrantExpiry, *lifecycle.Binding) {}, true},
		{"binding-clamp", func(g *GrantExpiry, b *lifecycle.Binding) {
			b.DeadlineNS = uint64(20 * time.Second)
			g.KernelDeadlineNS = b.DeadlineNS
		}, true},
		{"pair-boundary", func(g *GrantExpiry, _ *lifecycle.Binding) { g.MonoAfterNS = g.MonoSampleNS + MaxGrantExpiryPairingNS }, true},
		{"pair-too-slow", func(g *GrantExpiry, _ *lifecycle.Binding) {
			g.MonoAfterNS = g.MonoSampleNS + MaxGrantExpiryPairingNS + 1
		}, false},
		{"backward-monotonic", func(g *GrantExpiry, _ *lifecycle.Binding) { g.MonoAfterNS = g.MonoSampleNS - 1 }, false},
		{"elapsed-wall", func(g *GrantExpiry, _ *lifecycle.Binding) { g.WallSampleUnixNS = g.ExpiresAt * int64(time.Second) }, false},
		{"different-claim", func(g *GrantExpiry, _ *lifecycle.Binding) { g.ExpiresAt++ }, false},
		{"widened", func(g *GrantExpiry, _ *lifecycle.Binding) { g.KernelDeadlineNS++ }, false},
		{"shorter-without-proof", func(g *GrantExpiry, _ *lifecycle.Binding) { g.KernelDeadlineNS-- }, false},
		{"cutoff-during-pair", func(g *GrantExpiry, b *lifecycle.Binding) {
			b.DeadlineNS = g.MonoAfterNS
			g.KernelDeadlineNS = b.DeadlineNS
		}, false},
		{"overflow", func(g *GrantExpiry, b *lifecycle.Binding) {
			g.MonoSampleNS = math.MaxUint64 - 2
			g.MonoAfterNS = g.MonoSampleNS
			b.DeadlineNS = math.MaxUint64
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := expiryFixture()
			binding := b
			test.change(&g, &binding)
			if (g.Validate(binding, 160) == nil) != test.valid {
				t.Fatal("unexpected clock boundary result", g)
			}
		})
	}
}
func TestAuditRequiresOneSignedExpiryFrameBeforeActivity(t *testing.T) {
	for _, name := range []string{"missing-resource", "missing-control", "duplicate", "late-sample", "wrong-expiry", "before-grant-time", "future-frame"} {
		t.Run(name, func(t *testing.T) {
			f := setupWithBound(t, name == "duplicate")
			if name == "missing-resource" {
				if f.w.Append(context.Background(), "files", rawEvent(216, 1)) == nil {
					t.Fatal("unbounded resource passed")
				}
				return
			}
			if name == "missing-control" {
				if f.w.Append(context.Background(), "lifecycle", []byte(`{"state":"released"}`)) == nil {
					t.Fatal("unbounded launch passed")
				}
				return
			}
			g := expiryFixture()
			f.clock.now = uint64(1502 * time.Millisecond)
			switch name {
			case "late-sample":
				f.clock.now = uint64(1600 * time.Millisecond)
				if err := f.w.Append(context.Background(), "lifecycle", []byte(`{"state":"prepared"}`)); err != nil {
					t.Fatal(err)
				}
			case "wrong-expiry":
				g.ExpiresAt++
			case "before-grant-time":
				g.MonoSampleNS = uint64(time.Second) - 1
				g.MonoAfterNS = g.MonoSampleNS
				g.KernelDeadlineNS = g.MonoSampleNS + uint64(19*time.Second)
			case "future-frame":
				f.clock.now = g.MonoAfterNS - 1
			}
			raw, _ := json.Marshal(struct {
				State       string      `json:"state"`
				GrantExpiry GrantExpiry `json:"grant_expiry"`
			}{"grant_expiry_bound", g})
			if f.w.Append(context.Background(), "lifecycle", raw) == nil {
				t.Fatal("invalid expiry frame passed")
			}
		})
	}
}
func TestEffectiveCutoffRejectsAllowBeforeOriginalDeadline(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "denied", true: "allowed"}[allowed], func(t *testing.T) {
			f := setup(t)
			raw := rawEvent(216, 1)
			binary.LittleEndian.PutUint64(raw[24:32], expiryFixture().KernelDeadlineNS)
			if allowed {
				raw[48] = 1
			}
			err := f.w.Append(context.Background(), "files", raw)
			if allowed {
				if err == nil {
					t.Fatal("an allow crossed the signed wall cutoff")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			f.fill(t)
			f.clock.now = uint64(21 * time.Second)
			term := terminal()
			term.State = "expired"
			term.ExitCode = 137
			if _, err = f.w.Seal(context.Background(), term, signer{f.node}); err != nil {
				t.Fatal(err)
			}
			f.accept(t)
			if v := VerifyOffline(f.w.Export(), f.trust); v.State != "VALID_COMPLETE" {
				t.Fatal(v)
			}
		})
	}
}

// Re-signing proves that raw provenance still fails with trusted node custody.
func resignNode(t *testing.T, f *fixture, b *Bundle) {
	t.Helper()
	chain := mustHeaderDigest(b.Header)
	for i := range b.Events {
		e := &b.Events[i]
		e.Index = uint64(i) + 1
		e.PreviousDigest = chain
		e.Digest = eventDigest(*e)
		chain = e.Digest
	}
	b.Seal.EventsDigest = chain
	b.Seal.CountersDigest = hash("AGENTGATE_JOB_AUDIT_COUNTERS_V1\n", b.Counters)
	b.Seal.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.node, sealBytes(*b.Seal)))
}
func TestOfflineCutoffCannotBeBypassedByNodeResigning(t *testing.T) {
	f := setup(t)
	f.fill(t)
	f.clock.now = uint64(21 * time.Second)
	f.seal(t)
	b := f.w.Export()
	binary.LittleEndian.PutUint64(b.Events[2].Raw[24:32], expiryFixture().KernelDeadlineNS)
	b.Events[2].Raw[48] = 1
	b.Events[2].Observation.TimestampNS = expiryFixture().KernelDeadlineNS
	*b.Events[2].Observation.Decision = true
	resignNode(t, f, &b)
	if v := VerifyOffline(b, f.trust); v.State != "TAMPERED" || v.Reason != "raw-resource-event-differs" {
		t.Fatal(v)
	}
}
func TestHistoricalUnboundedTrailStaysReadableAndIncomplete(t *testing.T) {
	f := setup(t)
	f.fill(t)
	f.seal(t)
	b := f.w.Export()
	b.Events = b.Events[1:]
	for i := range b.Events {
		if b.Events[i].Kind == "control" {
			b.Events[i].Observation.Sequence--
		}
	}
	c := b.Counters["lifecycle"]
	c.Sequence--
	b.Counters["lifecycle"] = c
	resignNode(t, f, &b)
	if v := VerifyOffline(b, f.trust); v.State != "INCOMPLETE" || v.Reason != "grant-expiry-bound-missing" {
		t.Fatal(v)
	}
}

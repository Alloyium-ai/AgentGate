// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobaudit

import (
	"context"
	"encoding/binary"
	"testing"
)

func TestRuntimeProofPrecedesActivityAndCannotRepeatOrExpire(t *testing.T) {
	for _, name := range []string{"resource", "launch", "duplicate", "expired", "earlier-event", "seal"} {
		t.Run(name, func(t *testing.T) {
			f := setupWithBound(t, false)
			f.bound(t)
			proof := []byte(`{"state":"runtime_files_verified"}`)
			switch name {
			case "resource":
				if f.w.Append(context.Background(), "files", rawEvent(216, 1)) == nil {
					t.Fatal("resource activity lacked runtime proof")
				}
			case "launch":
				if f.w.Append(context.Background(), "lifecycle", []byte(`{"state":"held"}`)) == nil {
					t.Fatal("launch control lacked runtime proof")
				}
			case "duplicate":
				if err := f.w.Append(context.Background(), "lifecycle", proof); err != nil {
					t.Fatal(err)
				}
				if f.w.Append(context.Background(), "lifecycle", proof) == nil {
					t.Fatal("duplicate runtime proof passed")
				}
			case "expired":
				f.clock.now = expiryFixture().KernelDeadlineNS
				if f.w.Append(context.Background(), "lifecycle", proof) == nil {
					t.Fatal("expired runtime proof passed")
				}
			case "earlier-event":
				if err := f.w.Append(context.Background(), "lifecycle", proof); err != nil {
					t.Fatal(err)
				}
				raw := rawEvent(216, 1)
				binary.LittleEndian.PutUint64(raw[24:32], f.clock.now-1)
				if f.w.Append(context.Background(), "files", raw) == nil {
					t.Fatal("activity preceded the runtime proof time")
				}
			case "seal":
				for _, s := range f.config.Header.RequiredStreams {
					if err := f.w.FinishStream(context.Background(), s.Name, FinalCounters{Sequence: f.w.last[s.Name], Available: true}); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := f.w.Seal(context.Background(), terminal(), signer{f.node}); err == nil {
					t.Fatal("missing runtime proof sealed")
				}
			}
		})
	}
}

func TestObserverReadbackFollowsRuntimeProofBeforeHeldLaunch(t *testing.T) {
	ctx := context.Background()
	for _, before := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing-runtime-proof", false: "before-held-launch"}[before], func(t *testing.T) {
			f := setupWithBound(t, false)
			f.bound(t)
			if !before {
				if err := f.w.Append(ctx, "lifecycle", []byte(`{"state":"runtime_files_verified"}`)); err != nil {
					t.Fatal(err)
				}
			}
			err := f.w.Append(ctx, "lifecycle", []byte(`{"state":"observer_binding_readback"}`))
			if before {
				if err == nil {
					t.Fatal("observer measurement bypassed runtime proof")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = f.w.Append(ctx, "lifecycle", []byte(`{"state":"held"}`)); err != nil {
				t.Fatal(err)
			}
			bundle := f.w.Export()
			if len(bundle.Events) != 4 {
				t.Fatal("bound, runtime, observer and held order differs", len(bundle.Events))
			}
		})
	}
}
func TestHistoricalRuntimeProofGapStaysIncomplete(t *testing.T) {
	f := setup(t)
	f.fill(t)
	f.seal(t)
	b := f.w.Export()
	b.Events = append(b.Events[:1], b.Events[2:]...)
	for i := range b.Events {
		if b.Events[i].Kind == "control" && b.Events[i].Observation.Sequence > 1 {
			b.Events[i].Observation.Sequence--
		}
	}
	c := b.Counters["lifecycle"]
	c.Sequence--
	b.Counters["lifecycle"] = c
	resignNode(t, f, &b)
	if v := VerifyOffline(b, f.trust); v.State != "INCOMPLETE" || v.Reason != "runtime-files-proof-missing" {
		t.Fatal(v)
	}
}
func TestOfflineRuntimeProofCannotFollowActivityOrHideEarlierEvents(t *testing.T) {
	for _, name := range []string{"arrival", "timestamp"} {
		t.Run(name, func(t *testing.T) {
			f := setup(t)
			f.fill(t)
			f.seal(t)
			b := f.w.Export()
			if name == "arrival" {
				b.Events[1], b.Events[2] = b.Events[2], b.Events[1]
			} else {
				b.Events[1].Observation.TimestampNS = b.Events[2].Observation.TimestampNS + 1
			}
			resignNode(t, f, &b)
			if v := VerifyOffline(b, f.trust); v.State != "TAMPERED" {
				t.Fatal(v)
			}
		})
	}
}

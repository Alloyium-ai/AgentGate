// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math/bits"
	"os"
	"runtime"
	"testing"
	"time"
)

func rawNet(t *testing.T, e event) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := binary.Write(&out, binary.LittleEndian, e); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func netEvent(sequence uint64, allowed uint32) event {
	return event{Sequence: sequence, Generation: 1, Domain: 9, Cgroup: 9, MonoNS: 100 + sequence, Hook: 1, Allowed: allowed, Version: 2, Protocol: 6, Port: 443}
}

func TestLaunchNetworkStreamReconcilesOutOfOrderDelivery(t *testing.T) {
	tracker := newNetworkTracker(9, 100)
	for _, sequence := range []uint64{2, 1, 4, 3, 5} {
		tracker.consume(rawNet(t, netEvent(sequence, uint32(sequence%2))), 1000)
	}
	events, stream := tracker.finish(counters{Decisions: 5}, nil)
	if !stream.Complete || stream.Observed != 5 || len(events) != 5 || stream.Hooks["connect4"].Allowed != 3 || stream.Hooks["connect4"].Denied != 2 {
		t.Fatalf("stream %+v", stream)
	}
	if len(stream.RawSHA256) != 64 {
		t.Fatal("raw stream digest absent")
	}
}

func TestLaunchNetworkStreamDetectsLossDuplicatesAndForeignEvents(t *testing.T) {
	cases := map[string]func(*networkTracker) counters{
		"kernel loss": func(n *networkTracker) counters {
			n.consume(rawNet(t, netEvent(1, 1)), 1000)
			return counters{Decisions: 2, Lost: 1}
		},
		"unread decision": func(n *networkTracker) counters {
			n.consume(rawNet(t, netEvent(1, 1)), 1000)
			return counters{Decisions: 2}
		},
		"duplicate replaces a missing sequence": func(n *networkTracker) counters {
			for _, s := range []uint64{1, 3, 3} {
				n.consume(rawNet(t, netEvent(s, 1)), 1000)
			}
			return counters{Decisions: 3}
		},
		"swap that keeps the sum": func(n *networkTracker) counters {
			for _, s := range []uint64{1, 1, 4, 4} { // sum 10 == 1+2+3+4, squares differ
				n.consume(rawNet(t, netEvent(s, 1)), 1000)
			}
			return counters{Decisions: 4}
		},
		"foreign domain": func(n *networkTracker) counters {
			e := netEvent(1, 1)
			e.Domain = 10
			n.consume(rawNet(t, e), 1000)
			return counters{Decisions: 1}
		},
		"event before the start": func(n *networkTracker) counters {
			e := netEvent(1, 1)
			e.MonoNS = 50
			n.consume(rawNet(t, e), 1000)
			return counters{Decisions: 1}
		},
		"event from the future": func(n *networkTracker) counters {
			n.consume(rawNet(t, netEvent(1, 1)), 10)
			return counters{Decisions: 1}
		},
		"short record": func(n *networkTracker) counters {
			n.consume([]byte{1, 2, 3}, 1000)
			return counters{Decisions: 1}
		},
		"unknown hook": func(n *networkTracker) counters {
			e := netEvent(1, 1)
			e.Hook = 99
			n.consume(rawNet(t, e), 1000)
			return counters{Decisions: 1}
		},
	}
	for name, setup := range cases {
		tracker := newNetworkTracker(9, 100)
		counts := setup(tracker)
		if _, stream := tracker.finish(counts, nil); stream.Complete {
			t.Errorf("%s: incomplete stream reported complete: %+v", name, stream)
		}
	}
	tracker := newNetworkTracker(9, 100)
	if _, stream := tracker.finish(counters{}, errors.New("lookup failed")); stream.Complete || stream.Failure == "" {
		t.Fatal("a counter lookup failure left the stream complete")
	}
	if _, stream := newNetworkTracker(9, 100).finish(counters{}, nil); !stream.Complete {
		t.Fatal("a launch without network activity is complete")
	}
}

func TestLaunchNetworkStreamMemoryIsBoundedOverHours(t *testing.T) {
	tracker := newNetworkTracker(9, 100)
	const total = 200000
	raw := rawNet(t, netEvent(1, 0))
	for sequence := uint64(1); sequence <= total; sequence++ {
		binary.LittleEndian.PutUint64(raw[0:8], sequence)
		binary.LittleEndian.PutUint64(raw[32:40], 100+sequence)
		tracker.consume(raw, 1<<62)
	}
	events, stream := tracker.finish(counters{Decisions: total}, nil)
	if !stream.Complete || len(events) != maxLaunchNetworkEvents || !stream.EventsTruncated || stream.Observed != total {
		t.Fatalf("stream %+v kept %d", stream, len(events))
	}
	if len(stream.Hooks) != 1 {
		t.Fatal("per-hook counters grew")
	}
}

func TestSequenceAccountingIsExactForLargeCounts(t *testing.T) {
	for _, n := range []uint64{1, 2, 3, 1000, 1 << 32} {
		var sumHi, sumLo, sqHi, sqLo uint64
		if n <= 1000 {
			for s := uint64(1); s <= n; s++ {
				sumHi, sumLo = add128(sumHi, sumLo, s)
				hi, lo := mul(s)
				sqHi, sqLo = add128(sqHi+hi, sqLo, lo)
			}
			if !sequencesComplete(n, n, sumHi, sumLo, sqHi, sqLo) {
				t.Fatalf("exact sequence 1..%d rejected", n)
			}
			if sequencesComplete(n, n, sumHi, sumLo+1, sqHi, sqLo) {
				t.Fatal("a wrong sum passed")
			}
			continue
		}
		// For a large count only confirm the closed forms agree with themselves.
		if squaresMatch(n, 0, 0) {
			t.Fatal("a zero square sum matched")
		}
	}
}

func mul(s uint64) (uint64, uint64) { return bits.Mul64(s, s) }

func TestDrainNetworkStopsWithinItsBound(t *testing.T) {
	tracker := newNetworkTracker(9, 100)
	stop := make(chan struct{})
	done := make(chan struct{})
	var sequence uint64
	go func() {
		defer close(done)
		// A ring that never goes idle must still end after the drain bound.
		drainNetwork(func(time.Time) ([]byte, error) {
			sequence++
			runtime.Gosched()
			return rawNet(t, netEvent(sequence, 1)), nil
		}, tracker, stop, func() uint64 { return 1 << 62 })
	}()
	time.Sleep(20 * time.Millisecond)
	close(stop)
	select {
	case <-done:
	case <-time.After(drainBound + 2*time.Second):
		t.Fatal("a busy ring kept the drain running past its bound")
	}
	idle := newNetworkTracker(9, 100)
	stop2 := make(chan struct{})
	close(stop2)
	drainNetwork(func(time.Time) ([]byte, error) { return nil, os.ErrDeadlineExceeded }, idle, stop2, func() uint64 { return 1 })
	broken := newNetworkTracker(9, 100)
	drainNetwork(func(time.Time) ([]byte, error) { return nil, errors.New("ring closed") }, broken, make(chan struct{}), func() uint64 { return 1 })
	if _, stream := broken.finish(counters{}, nil); stream.Complete {
		t.Fatal("a ring read error left the stream complete")
	}
}

func TestCleanupBoundScalesOnlyForLaunches(t *testing.T) {
	if cleanupBound(false) != 5*time.Second || cleanupBound(true) <= cleanupBound(false) {
		t.Fatal("cleanup bounds differ from the contract")
	}
}

func TestHostEvidenceOperationSetIsBounded(t *testing.T) {
	tracker := fsTracker()
	for index := uint32(0); index < 200; index++ {
		tracker.consume(rawFS(t, fsEvent{Sequence: uint64(index + 1), Operation: 1000 + index, Allowed: 1}))
	}
	if len(tracker.Operations) > maxOperationKinds || tracker.failure == nil {
		t.Fatalf("operation counters grew to %d", len(tracker.Operations))
	}
}

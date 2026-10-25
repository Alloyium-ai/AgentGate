// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"math/bits"
	"os"
	"sync"
	"time"
)

// A launch can run for hours. Its network evidence is therefore aggregated
// while the ring is drained, exactly like the host-control evidence: memory
// stays constant, the first events are kept verbatim, every raw record is
// hashed, and the counters must reconcile with the kernel's own counters.
const (
	maxLaunchNetworkEvents = 2000
	launchNetworkRingBytes = 4 << 20
	// The one-command SSH window keeps its five second collection bound. A
	// launch stop sends a graceful signal, waits, kills the cgroup, removes the
	// target and only then stops the guard, so its bound is larger. Neither is a
	// workload execution grant: the kernel policy has already expired.
	legacyCleanupBound = 5 * time.Second
	launchCleanupBound = 60 * time.Second
)

var networkHookNames = map[uint32]string{1: "connect4", 2: "connect6", 3: "sendmsg4", 4: "sendmsg6", 5: "egress", 6: "ingress"}

type networkStream struct {
	Observed        uint64             `json:"observed"`
	RawSHA256       string             `json:"raw_sha256"`
	Hooks           map[string]opCount `json:"hooks"`
	EventsKept      int                `json:"events_kept"`
	EventsTruncated bool               `json:"events_truncated"`
	Decisions       uint64             `json:"decisions"`
	Lost            uint64             `json:"lost"`
	Complete        bool               `json:"complete"`
	Failure         string             `json:"failure,omitempty"`
}

// networkTracker accumulates the stream. Sequence numbers come from an atomic
// counter but CPUs may submit out of order, so completeness is checked without
// order: every sequence lies in 1..decisions and the count, sum and sum of
// squares of the observed sequences equal those of 1..decisions exactly.
type networkTracker struct {
	mu                 sync.Mutex
	domain, started    uint64
	raw                hash.Hash
	events             []event
	stream             networkStream
	maxSequence        uint64
	sumHi, sumLo       uint64
	squareHi, squareLo uint64
	failure            error
}

func newNetworkTracker(domain, started uint64) *networkTracker {
	return &networkTracker{domain: domain, started: started, raw: sha256.New(), events: []event{},
		stream: networkStream{Hooks: map[string]opCount{}}}
}

func add128(hi, lo, value uint64) (uint64, uint64) {
	lo, carry := bits.Add64(lo, value, 0)
	return hi + carry, lo
}

func (n *networkTracker) consume(raw []byte, now uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.failure != nil {
		return
	}
	if len(raw) != binary.Size(event{}) {
		n.failure = errors.New("network event ABI differs")
		return
	}
	var e event
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		n.failure = err
		return
	}
	name, known := networkHookNames[e.Hook]
	if !known || e.Sequence == 0 || e.Generation != 1 || e.Domain != n.domain || e.Cgroup != n.domain ||
		e.Version != 2 || e.Allowed > 1 || e.MonoNS < n.started || (now != 0 && e.MonoNS > now) {
		n.failure = errors.New("network event differs from the owned domain stream")
		return
	}
	n.raw.Write(raw)
	n.stream.Observed++
	if e.Sequence > n.maxSequence {
		n.maxSequence = e.Sequence
	}
	n.sumHi, n.sumLo = add128(n.sumHi, n.sumLo, e.Sequence)
	hi, lo := bits.Mul64(e.Sequence, e.Sequence)
	n.squareHi, n.squareLo = add128(n.squareHi+hi, n.squareLo, lo)
	count := n.stream.Hooks[name]
	if e.Allowed == 1 {
		count.Allowed++
	} else {
		count.Denied++
	}
	n.stream.Hooks[name] = count
	if len(n.events) < maxLaunchNetworkEvents {
		n.events = append(n.events, e)
	} else {
		n.stream.EventsTruncated = true
	}
}

// sequencesComplete proves the observed multiset equals 1..count when every
// value lies in range (checked through maxSequence): equal count, sum and sum
// of squares. Computed in 128 bits, so it never overflows.
func sequencesComplete(count, maxSequence, sumHi, sumLo, squareHi, squareLo uint64) bool {
	if count == 0 {
		return maxSequence == 0 && sumHi == 0 && sumLo == 0 && squareHi == 0 && squareLo == 0
	}
	if maxSequence != count {
		return false
	}
	// sum = n(n+1)/2 ; squares = n(n+1)(2n+1)/6, in 128-bit integers.
	wantHi, wantLo := bits.Mul64(count, count+1)
	wantLo = wantLo>>1 | wantHi<<63
	wantHi >>= 1
	if wantHi != sumHi || wantLo != sumLo {
		return false
	}
	return squaresMatch(count, squareHi, squareLo)
}

func squaresMatch(n, hi, lo uint64) bool {
	// Compute n(n+1)(2n+1)/6 with 192-bit intermediates via three steps.
	aHi, aLo := bits.Mul64(n, n+1)
	// multiply (aHi,aLo) by (2n+1)
	m := 2*n + 1
	p1Hi, p1Lo := bits.Mul64(aLo, m)
	p2Hi, p2Lo := bits.Mul64(aHi, m)
	top := p2Hi
	mid, carry := bits.Add64(p1Hi, p2Lo, 0)
	top += carry
	low := p1Lo
	// divide the 192-bit (top, mid, low) by 6
	q2, r := bits.Div64(0, top, 6)
	q1, r := bits.Div64(r, mid, 6)
	q0, r := bits.Div64(r, low, 6)
	return r == 0 && q2 == 0 && q1 == hi && q0 == lo
}

// finish reconciles the stream with the kernel counters.
func (n *networkTracker) finish(counts counters, countErr error) ([]event, networkStream) {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := n.stream
	out.RawSHA256 = hex.EncodeToString(n.raw.Sum(nil))
	out.EventsKept = len(n.events)
	out.Decisions, out.Lost = counts.Decisions, counts.Lost
	failure := n.failure
	if countErr != nil {
		failure = errors.Join(failure, countErr)
	}
	out.Complete = failure == nil && counts.Lost == 0 && counts.Decisions == out.Observed &&
		sequencesComplete(out.Observed, n.maxSequence, n.sumHi, n.sumLo, n.squareHi, n.squareLo)
	if failure != nil {
		out.Failure = failure.Error()
	}
	events := append([]event(nil), n.events...)
	return events, out
}

// drainNetwork reads the ring until stop, then keeps draining until the ring
// is idle or the drain bound passes. now supplies the monotonic clock.
func drainNetwork(read func(time.Time) ([]byte, error), tracker *networkTracker, stopping <-chan struct{}, now func() uint64) {
	var cutoff time.Time
	stopped := false
	for {
		if !stopped {
			select {
			case <-stopping:
				stopped = true
				cutoff = time.Now().Add(drainBound)
			default:
			}
		}
		if stopped && time.Now().After(cutoff) {
			return
		}
		raw, err := read(time.Now().Add(50 * time.Millisecond))
		if err == nil {
			tracker.consume(raw, now())
			continue
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if stopped {
				return
			}
			continue
		}
		tracker.mu.Lock()
		if tracker.failure == nil {
			tracker.failure = err
		}
		tracker.mu.Unlock()
		return
	}
}

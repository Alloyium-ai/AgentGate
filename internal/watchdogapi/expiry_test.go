// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package watchdogapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type cutoffClock struct{ now atomic.Uint64 }

func (c *cutoffClock) NowNS() (uint64, error) { return c.now.Load(), nil }

func TestPrivateWatchdogWireEnforcesEarlierCutoff(t *testing.T) {
	clock := &cutoffClock{}
	clock.now.Store(1)
	f := apiWithClock(t, clock)
	ack := f.arm(t)
	now, _ := f.client.config.Clock.NowNS()
	cutoff := now + uint64(300*time.Millisecond)
	if err := f.client.Activate(context.Background(), ack, cutoff); err != nil {
		t.Fatal(err)
	}
	leases, err := f.store.LoadWatchdog(context.Background())
	if err != nil || len(leases) != 1 || leases[0].EffectiveDeadlineNS != cutoff || leases[0].HeartbeatDeadlineNS > cutoff || leases[0].Ack.Binding.DeadlineNS != f.binding.DeadlineNS {
		t.Fatal("the UDS activation lost its exact cutoff", err)
	}
	if err = f.client.Check(context.Background(), ack); err != nil {
		t.Fatal("the live cutoff failed its control", err)
	}
	// Real UDS and SQLite operations finish before the test advances lease time.
	clock.now.Store(cutoff)
	if f.client.Check(context.Background(), ack) == nil {
		t.Fatal("the cutoff accepted a live check")
	}
	waitFor(t, func() bool { return f.domains.stopCount() > 0 })
	f.domains.mu.Lock()
	stop := f.domains.stops[0]
	f.domains.mu.Unlock()
	if stop.Reason != "watchdog-grant-expired" || stop.Binding.DeadlineNS != f.binding.DeadlineNS || cutoff >= f.binding.DeadlineNS {
		t.Fatal("the UDS lease survived or changed its binding")
	}
}

type responseTransport func(*http.Request) (*http.Response, error)

func (f responseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestWatchdogActivationRequiresExactResponseCutoff(t *testing.T) {
	for _, name := range []string{"missing", "different", "matching"} {
		t.Run(name, func(t *testing.T) {
			f := api(t)
			ack := f.arm(t)
			now, _ := f.client.config.Clock.NowNS()
			cutoff := now + uint64(time.Second)
			client := &Client{config: f.client.config}
			client.running.Store(true)
			client.http = &http.Client{Transport: responseTransport(func(r *http.Request) (*http.Response, error) {
				var request Request
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.EffectiveDeadlineNS != cutoff {
					t.Fatal("the client omitted the exact cutoff", err)
				}
				got := uint64(0)
				if name == "different" {
					got = cutoff - 1
				}
				if name == "matching" {
					got = cutoff
				}
				raw, _ := json.Marshal(Response{Protocol: ResponseProtocol, Confirmed: true, State: "active", EffectiveDeadlineNS: got})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw))), Header: make(http.Header)}, nil
			})}
			if (client.Activate(context.Background(), ack, cutoff) == nil) != (name == "matching") {
				t.Fatal("the response cutoff did not control activation")
			}
		})
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package watchdogapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

type runTransport func(*http.Request) (*http.Response, error)

func (f runTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// These tests isolate loop shutdown. The private UDS suite covers peer custody.
func TestRunCancellationDuringHeartbeatClosesReadinessWithoutFault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 1)
	c := &Client{config: ClientConfig{HeartbeatInterval: time.Millisecond}, transport: &http.Transport{}}
	c.http = &http.Client{Transport: runTransport(func(r *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-r.Context().Done()
		return nil, r.Context().Err()
	})}
	c.leases.Store("owned", lifecycle.WatchdogAck{})
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the heartbeat request did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal("intentional cancellation became a live heartbeat fault", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the canceled heartbeat did not stop")
	}
	if c.Ready() || c.running.Load() {
		t.Fatal("the stopped client remained ready")
	}
}
func TestRunLiveHeartbeatFailureLatchesFault(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Client{config: ClientConfig{HeartbeatInterval: time.Millisecond}, transport: &http.Transport{}}
	c.http = &http.Client{Transport: runTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New("synthetic transport failure") })}
	c.leases.Store("owned", lifecycle.WatchdogAck{})
	done := make(chan error, 1)
	go func() { done <- c.Run(ctx) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a live heartbeat failure returned success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the failed heartbeat did not stop")
	}
	if c.Ready() || !c.failed.Load() {
		t.Fatal("a live heartbeat failure left release available")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package watchdogapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type domainFixture struct {
	mu      sync.Mutex
	domains map[string]lifecycle.Binding
	stops   []lifecycle.WatchdogStopEvidence
}

func (d *domainFixture) ListOwnedDomains(context.Context) ([]lifecycle.Binding, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := []lifecycle.Binding{}
	for _, b := range d.domains {
		out = append(out, b)
	}
	return out, nil
}
func (d *domainFixture) StopOwnedDomain(_ context.Context, b lifecycle.Binding, reason string) (lifecycle.WatchdogStopEvidence, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	e := lifecycle.WatchdogStopEvidence{Binding: b, Reason: reason, Terminated: true, Empty: true, PinsRetained: true, ReadbackDigest: strings.Repeat("a", 64)}
	e.Digest = lifecycle.WatchdogStopDigest(e)
	d.stops = append(d.stops, e)
	return e, nil
}
func (d *domainFixture) add(b lifecycle.Binding) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.domains[b.RunID] = b
}
func (d *domainFixture) stopCount() int { d.mu.Lock(); defer d.mu.Unlock(); return len(d.stops) }

type apiFixture struct {
	client     *Client
	server     *Server
	store      *lifecycle.SQLiteJournal
	domains    *domainFixture
	binding    lifecycle.Binding
	root       string
	clientStop context.CancelFunc
	clientDone chan error
}

func waitFor(t *testing.T, predicate func() bool) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for !predicate() {
		select {
		case <-deadline.C:
			t.Fatal("the bounded condition did not complete")
		case <-ticker.C:
		}
	}
}
func api(t *testing.T) *apiFixture {
	t.Helper()
	return apiWithClock(t, lifecycle.MonotonicClock{})
}

func apiWithClock(t *testing.T, clock lifecycle.Clock) *apiFixture {
	t.Helper()
	scratch := os.Getenv("AGENTGATE_TEST_SCRATCH")
	if scratch == "" || strings.HasPrefix(scratch, "/tmp") || os.Geteuid() != 0 {
		t.Skip("the private watchdog test requires root and an owned scratch directory")
	}
	root, err := os.MkdirTemp(scratch, "watchdog-api-")
	if err != nil {
		t.Fatal(err)
	}
	store, err := lifecycle.OpenWatchdogStore(filepath.Join(root, "watchdog.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	domains := &domainFixture{domains: map[string]lifecycle.Binding{}}
	core, err := lifecycle.NewIndependentWatchdog(lifecycle.WatchdogConfig{Identity: lifecycle.Identity{NodeID: "node-one", BootID: "boot-one"}, InstanceID: "unit-watchdog", ArtifactDigest: strings.Repeat("8", 64), HeartbeatTimeout: 500 * time.Millisecond, StopTimeout: time.Second}, key, store, domains, lifecycle.LinuxDaemonMonitor{}, clock)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{SocketPath: filepath.Join(root, "watchdog.sock"), Core: core, RequestTimeout: time.Second, StopTimeout: time.Second}
	serverCtx, serverStop := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.Serve(serverCtx) }()
	waitFor(t, func() bool { _, err := os.Lstat(server.SocketPath); return err == nil })
	ticks, err := lifecycle.ProcessStartTime(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(ClientConfig{SocketPath: server.SocketPath, Daemon: lifecycle.DaemonIdentity{PID: os.Getpid(), StartTimeTicks: ticks, InstanceID: "unit-node"}, PublicKey: key.Public().(ed25519.PublicKey), ArtifactDigest: strings.Repeat("8", 64), Clock: clock, Timeout: time.Second, HeartbeatInterval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	clientCtx, clientStop := context.WithCancel(context.Background())
	clientDone := make(chan error, 1)
	go func() { clientDone <- client.Run(clientCtx) }()
	waitFor(t, client.Ready)
	now, err := clock.NowNS()
	if err != nil {
		t.Fatal(err)
	}
	binding := lifecycle.Binding{AgentID: "agent-one", AgentKey: base64.RawURLEncoding.EncodeToString(make([]byte, 32)), JobDigest: strings.Repeat("1", 64), GrantID: "grant-one", RunID: "run-one", NodeID: "node-one", BootID: "boot-one", PolicyDigest: strings.Repeat("2", 64), SchemaDigest: strings.Repeat("3", 64), CompilerDigest: strings.Repeat("4", 64), ArtifactDigests: map[string]string{"unit": strings.Repeat("5", 64), "watchdog": strings.Repeat("8", 64)}, Generation: 1, DeadlineNS: now + uint64(30*time.Second)}
	fixture := &apiFixture{client, server, store, domains, binding, root, clientStop, clientDone}
	t.Cleanup(func() {
		clientStop()
		serverStop()
		select {
		case <-serverDone:
		case <-time.After(2 * time.Second):
			t.Error("watchdog server did not stop")
		}
		store.Close()
		os.RemoveAll(root)
	})
	return fixture
}
func (f *apiFixture) arm(t *testing.T) lifecycle.WatchdogAck {
	t.Helper()
	now, err := f.client.config.Clock.NowNS()
	if err != nil {
		t.Fatal(err)
	}
	if err = f.client.Reserve(context.Background(), f.binding, now+uint64(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	f.binding.CgroupID = 100
	f.domains.add(f.binding)
	ack, err := f.client.Arm(context.Background(), f.binding)
	if err != nil {
		t.Fatal(err)
	}
	return ack
}
func TestPrivateWatchdogWirePersistsHeartbeatAndStopsAfterClientLoss(t *testing.T) {
	f := api(t)
	ack := f.arm(t)
	if err := f.client.Activate(context.Background(), ack, f.binding.DeadlineNS); err != nil {
		t.Fatal(err)
	}
	leases, err := f.store.LoadWatchdog(context.Background())
	if err != nil || len(leases) != 1 || leases[0].State != "active" {
		t.Fatal("activation wire lacked durable readback", err)
	}
	if err := f.client.Check(context.Background(), ack); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool {
		leases, err := f.store.LoadWatchdog(context.Background())
		return err == nil && len(leases) == 1 && leases[0].Revision > 2
	})
	f.clientStop()
	select {
	case err := <-f.clientDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("client heartbeat did not stop")
	}
	waitFor(t, func() bool {
		leases, err := f.store.WatchdogHistory(context.Background())
		return err == nil && len(leases) == 1 && leases[0].State == "stopped"
	})
	f.domains.mu.Lock()
	evidence := f.domains.stops[0]
	f.domains.mu.Unlock()
	if !evidence.Empty || !evidence.Terminated || !evidence.PinsRetained {
		t.Fatal("watchdog removed pins before empty readback")
	}
}
func TestWatchdogRejectsForgedPeerAndUnknownRequestFields(t *testing.T) {
	f := api(t)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("POST", "http://watchdog/v1/watchdog/reserve", strings.NewReader("{}"))
	request.Header.Set("X-Peer-UID", "0")
	f.server.ServeHTTP(recorder, request)
	if recorder.Code != 403 {
		t.Fatal("a header forged the Unix peer")
	}
	now, _ := f.client.config.Clock.NowNS()
	body, _ := json.Marshal(Request{Protocol: RequestProtocol, Daemon: f.client.config.Daemon, Binding: &f.binding, PreparationDeadlineNS: now + uint64(time.Second)})
	var object map[string]any
	json.Unmarshal(body, &object)
	object["unknown"] = true
	body, _ = json.Marshal(object)
	wire, err := http.NewRequest("POST", "http://watchdog/v1/watchdog/reserve", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	response, err := f.client.http.Do(wire)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 422 {
		t.Fatal("unknown request field passed")
	}
	daemon := f.client.config.Daemon
	daemon.PID++
	body, _ = json.Marshal(Request{Protocol: RequestProtocol, Daemon: daemon, Binding: &f.binding, PreparationDeadlineNS: now + uint64(time.Second)})
	wire, _ = http.NewRequest("POST", "http://watchdog/v1/watchdog/reserve", bytes.NewReader(body))
	response, err = f.client.http.Do(wire)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 422 {
		t.Fatal("a different process inherited peer custody")
	}
	leases, err := f.store.LoadWatchdog(context.Background())
	if err != nil || len(leases) != 0 {
		t.Fatal("a rejected request changed durable state", err)
	}
}
func TestWatchdogClientRequiresPinnedCustodyKey(t *testing.T) {
	f := api(t)
	f.client.config.PublicKey = ed25519.NewKeyFromSeed([]byte(strings.Repeat("x", 32))).Public().(ed25519.PublicKey)
	now, _ := f.client.config.Clock.NowNS()
	if err := f.client.Reserve(context.Background(), f.binding, now+uint64(time.Second)); err == nil {
		t.Fatal("an unpinned custody signer passed")
	}
	if f.domains.stopCount() != 0 {
		t.Fatal("a reservation selected a host domain")
	}
}

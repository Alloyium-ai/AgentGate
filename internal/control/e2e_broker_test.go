// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

// The brokered-secret path end to end, in one process: the real control
// service (store, HTTP API, job queue), the real agentgate-hostd daemon over
// the real host protocol, the real secretseal relay and the real credential
// broker against a fake TLS upstream (test CA, fake resolver and dialer). Only
// the launch runtime (launch.py, Docker, the BPF guard) and the broker's
// container are stand-ins: no Docker daemon, BPF LSM kernel or VM exists in
// the build sandbox, so the guard, the network attachment and the container
// hardening are not exercised here.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/broker"
	"alloyium.local/kernel-poc/internal/hostd"
	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// e2eSecret is an obvious fake credential; every check below proves that no
// form of it escapes to the service, the sandbox or any evidence.
const (
	e2eSecret   = "sk-ant-FAKE-e2e-0123456789abcdefXYZ"
	e2eUpstream = "api.example.test"
	e2ePublic   = "1.2.3.4"
)

func secretForms(value string) []string {
	forms := []string{value, value[4:24]}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		forms = append(forms, enc.EncodeToString([]byte(value)))
	}
	return forms
}

func noSecret(t *testing.T, what string, data []byte) {
	t.Helper()
	for _, form := range secretForms(e2eSecret) {
		if bytes.Contains(data, []byte(form)) {
			t.Fatalf("a form of the secret appears in %s", what)
		}
	}
}

// recorder keeps every byte a party sent or received, for the leak checks.
type recorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.Write(p)
}

func (r *recorder) Bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf.Bytes()...)
}

type recordingTransport struct {
	next http.RoundTripper
	rec  *recorder
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		t.rec.Write(body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}
	resp, err := t.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.rec.Write(body)
	resp.Body = io.NopCloser(bytes.NewReader(body))
	return resp, nil
}

type recordedConn struct {
	net.Conn
	rec *recorder
}

func (c *recordedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.rec.Write(p[:n])
	return n, err
}

func (c *recordedConn) Write(p []byte) (int, error) {
	c.rec.Write(p)
	return c.Conn.Write(p)
}

// upstreamSeen is what the fake upstream received.
type upstreamSeen struct {
	Method, Path, Host, SNI, Key, Body string
}

type fakeUpstream struct {
	mu   sync.Mutex
	seen []upstreamSeen
	srv  *httptest.Server
	pool *x509.CertPool
}

func newFakeUpstream(t *testing.T) *fakeUpstream {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agentgate e2e test CA"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: e2eUpstream}, DNSNames: []string{e2eUpstream},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	u := &fakeUpstream{pool: x509.NewCertPool()}
	u.pool.AddCert(ca)
	u.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		key := r.Header.Get("X-Api-Key")
		u.mu.Lock()
		u.seen = append(u.seen, upstreamSeen{Method: r.Method, Path: r.URL.Path, Host: r.Host, SNI: r.TLS.ServerName, Key: key, Body: string(body)})
		u.mu.Unlock()
		// A hostile upstream echoes the credential; the broker masks it.
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"msg_1","echo":%q}`, key)
	}))
	u.srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}}}
	u.srv.StartTLS()
	t.Cleanup(u.srv.Close)
	return u
}

func (u *fakeUpstream) requests() []upstreamSeen {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upstreamSeen(nil), u.seen...)
}

type e2eResolver struct{}

func (e2eResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if host == e2eUpstream {
		return []netip.Addr{netip.MustParseAddr(e2ePublic)}, nil
	}
	return nil, errors.New("no such host")
}

// inProcessBroker runs the real broker (broker.New and Serve) in this
// process in place of its container: same configuration bytes, same digest,
// same custody checks on the secret file; only the listener, resolver, dialer
// and trust roots are the test's. It maps the in-container paths of the
// configuration to the host files Docker would bind there.
type inProcessBroker struct {
	t        *testing.T
	upstream *fakeUpstream
	logs     *recorder

	mu        sync.Mutex
	failStart bool
	calls     []string
	servers   map[string]*runningBroker
	listeners map[string]string // broker authority -> 127.0.0.1 address
}

type runningBroker struct {
	srv    *broker.Server
	cancel context.CancelFunc
	done   chan struct{}
	err    error
}

func newInProcessBroker(t *testing.T, upstream *fakeUpstream) *inProcessBroker {
	return &inProcessBroker{t: t, upstream: upstream, logs: &recorder{}, servers: map[string]*runningBroker{}, listeners: map[string]string{}}
}

func (b *inProcessBroker) record(call string) {
	b.mu.Lock()
	b.calls = append(b.calls, call)
	b.mu.Unlock()
}

func (b *inProcessBroker) Check(context.Context, hostd.BrokerConfig) error { return nil }

func (b *inProcessBroker) Start(_ context.Context, launch *hostd.BrokerLaunch) error {
	b.record("start " + launch.LaunchID)
	b.mu.Lock()
	fail := b.failStart
	b.mu.Unlock()
	if fail {
		return errors.New("docker create: the broker image failed to start")
	}
	raw, err := os.ReadFile(launch.ConfigPath)
	if err != nil || broker.ConfigDigest(raw) != launch.ConfigSHA256 {
		return errors.New("the broker configuration on disk differs from its digest")
	}
	cfg, err := broker.ParseConfig(raw)
	if err != nil {
		return err
	}
	for i := range cfg.Routes {
		for _, s := range launch.Secrets {
			if cfg.Routes[i].Credential.SecretFile == s.ContainerPath {
				cfg.Routes[i].Credential.SecretFile = s.HostPath
			}
		}
	}
	cfg.StatsPath = launch.StatsPath()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	upAddr := b.upstream.srv.Listener.Addr().String()
	srv, err := broker.New(cfg, launch.ConfigSHA256, b.logs, broker.Overrides{Listener: ln, Resolver: e2eResolver{}, RootCAs: b.upstream.pool,
		Dial: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			if addr.Addr().String() != e2ePublic {
				return nil, errors.New("the fake dialer reaches only the fake public upstream")
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", upAddr)
		},
		LocalAddrs: func() ([]net.Addr, error) { return nil, nil }})
	if err != nil {
		ln.Close()
		return err
	}
	if err = srv.Listen(); err != nil {
		srv.Close()
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &runningBroker{srv: srv, cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(run.done)
		_, run.err = srv.Serve(ctx, broker.Hardening{UID: 10002, GID: 10002, NotDumpable: true, CoreLimitZero: true, NoNewPrivs: true, NoCapabilities: true})
	}()
	b.mu.Lock()
	b.servers[launch.LaunchID] = run
	b.listeners[net.JoinHostPort(launch.Address.String(), fmt.Sprint(launch.Port))] = ln.Addr().String()
	b.mu.Unlock()
	return nil
}

func (b *inProcessBroker) Stop(_ context.Context, launch *hostd.BrokerLaunch, grace time.Duration) error {
	b.record("stop " + launch.LaunchID)
	b.mu.Lock()
	run := b.servers[launch.LaunchID]
	b.mu.Unlock()
	if run == nil {
		return nil
	}
	run.cancel() // SIGTERM in the container
	select {
	case <-run.done:
	case <-time.After(grace + 5*time.Second):
		return errors.New("the broker did not stop")
	}
	return nil
}

func (b *inProcessBroker) Remove(_ context.Context, launch *hostd.BrokerLaunch) error {
	b.record("remove " + launch.LaunchID)
	b.mu.Lock()
	defer b.mu.Unlock()
	if run := b.servers[launch.LaunchID]; run != nil {
		select {
		case <-run.done:
		default:
			return errors.New("the broker container is still running")
		}
	}
	delete(b.servers, launch.LaunchID)
	return nil
}

func (b *inProcessBroker) running() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.servers)
}

// agentClient is the sandboxed agent: it can reach only the broker authority
// it was given, and every byte it sends and receives is recorded.
func (b *inProcessBroker) agentClient(rec *recorder) *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, DisableCompression: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			b.mu.Lock()
			local, ok := b.listeners[addr]
			b.mu.Unlock()
			if !ok {
				return nil, errors.New("the guard allows only the broker endpoint")
			}
			var d net.Dialer
			conn, err := d.DialContext(ctx, network, local)
			if err != nil {
				return nil, err
			}
			return &recordedConn{Conn: conn, rec: rec}, nil
		}}}
}

// e2eRuntime is the launch runtime (launch.py) as the daemon sees it: it
// keeps the launcher job and blocks like a running session until stopped.
type e2eRuntime struct {
	mu       sync.Mutex
	jobs     [][]byte
	stops    map[string]chan struct{}
	receipts map[string]json.RawMessage
	runs     int
	started  chan []byte
	hold     chan struct{} // closed by the test to release a run that a "crash" abandoned
}

func newE2ERuntime() *e2eRuntime {
	return &e2eRuntime{stops: map[string]chan struct{}{}, receipts: map[string]json.RawMessage{}, started: make(chan []byte, 8), hold: make(chan struct{})}
}

func (r *e2eRuntime) Info(context.Context) (hostd.RuntimeInfo, error) {
	info := hostd.RuntimeInfo{Runtime: hostd.RuntimeDockerHost, Capabilities: []string{"live-mounts", "snapshots"}}
	return info, nil
}

func e2eLauncherReceipt(job map[string]any, state, reason string, clean bool) json.RawMessage {
	sum := strings.Repeat("b", 64)
	zero := 0
	raw, _ := json.Marshal(map[string]any{"version": "agentgate.launch-receipt.v1", "launch_id": job["launch_id"], "job_id": job["job_id"],
		"spec_digest": job["spec_digest"], "policy_digest": job["policy_digest"], "profile_policy_digest": job["profile_policy_digest"],
		"mode": "session", "lifetime_seconds": job["lifetime_seconds"], "image_id": "sha256:" + strings.Repeat("f", 64), "state": state, "reason": reason,
		"exit_code": &zero, "started_at": time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"), "ended_at": time.Now().UTC().Format("2006-01-02T15:04:05.000000Z"),
		"objects":  map[string]any{"network_policy.bpf.o": sum, "fs_access.bpf.o": sum, "process_guard.bpf.o": sum, "pilot-network-diagnostic": sum},
		"mounts":   []any{},
		"evidence": map[string]any{"complete": true, "host": map[string]any{"complete": true, "sockets": "connect-only", "socket_lsm_guard": false}},
		"cleanup":  map[string]any{"domain_empty": clean, "enforcement_released": clean, "errors": []string{}},
		"broker":   map[string]any{"network": "agentgate-broker", "target_joined": true}, "kernel_verified": false})
	return raw
}

func (r *e2eRuntime) Run(ctx context.Context, raw []byte, emit func(hostd.LauncherEvent)) error {
	var job map[string]any
	if err := json.Unmarshal(raw, &job); err != nil {
		return err
	}
	id := job["launch_id"].(string)
	stop := make(chan struct{})
	r.mu.Lock()
	r.jobs = append(r.jobs, append([]byte(nil), raw...))
	r.stops[id] = stop
	r.runs++
	r.mu.Unlock()
	emit(hostd.LauncherEvent{Event: "state", State: "provisioning"})
	emit(hostd.LauncherEvent{Event: "state", State: "running"})
	r.started <- raw
	reason := "stop_requested"
	select {
	case <-stop:
	case <-ctx.Done():
		reason = "supervisor_stopped"
	case <-r.hold:
		return errors.New("the host agent that ran this launch is gone")
	}
	emit(hostd.LauncherEvent{Event: "state", State: "stopping"})
	state := "stopped"
	if reason != "stop_requested" {
		state = "failed"
	}
	receipt := e2eLauncherReceipt(job, state, reason, true)
	r.mu.Lock()
	r.receipts[id] = receipt
	r.mu.Unlock()
	emit(hostd.LauncherEvent{Event: "receipt", Receipt: receipt})
	return nil
}

func (r *e2eRuntime) Stop(_ context.Context, launchID string, _ int, _ string) (hostd.StopStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if stop, ok := r.stops[launchID]; ok {
		select {
		case <-stop:
		default:
			close(stop)
		}
		return hostd.StopStatus{State: "stopping", StopRequested: true}, nil
	}
	if _, ok := r.receipts[launchID]; ok {
		return hostd.StopStatus{State: "stopped", AlreadyTerminal: true}, nil
	}
	return hostd.StopStatus{}, hostd.ErrUnknownLaunch
}

func (r *e2eRuntime) Receipt(_ context.Context, launchID string) (json.RawMessage, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if raw, ok := r.receipts[launchID]; ok {
		return raw, nil
	}
	return nil, hostd.ErrUnknownLaunch
}

func (r *e2eRuntime) Reconcile(context.Context, string) ([]hostd.ReconcileItem, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// The runtime tears down every launch it no longer supervises.
	for _, raw := range r.jobs {
		var job map[string]any
		json.Unmarshal(raw, &job)
		id := job["launch_id"].(string)
		if _, done := r.receipts[id]; !done {
			r.receipts[id] = e2eLauncherReceipt(job, "failed", "host_restarted", true)
		}
	}
	return nil, nil
}

func (r *e2eRuntime) StageProfile(context.Context, string, int, []byte) (json.RawMessage, error) {
	return json.RawMessage(`{}`), nil
}
func (r *e2eRuntime) Snapshot(context.Context, string, string, int64, int) (json.RawMessage, error) {
	return json.RawMessage(`{}`), nil
}
func (r *e2eRuntime) Pull(context.Context, string) error        { return nil }
func (r *e2eRuntime) Provision(context.Context) (string, error) { return "ready=true\n", nil }

func (r *e2eRuntime) runCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.runs
}

// e2e is one in-process deployment.
type e2e struct {
	t        *testing.T
	f        *provFixture
	admin    string
	launcher string
	approver string
	viewer   string
	targetID string
	stateDir string
	secrets  string
	cfg      hostd.Config
	service  *hostd.HTTPService
	wire     *recorder // every host protocol byte, both directions
	api      *recorder // every user API response
	hostLog  *recorder
	runtime  *e2eRuntime
	broker   *inProcessBroker
	upstream *fakeUpstream
	daemon   *hostd.Daemon
	known    *secretseal.KnownTargets
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the host agent's secret store and broker stats directory need root ownership")
	}
	f := newProv(t)
	f.s.Now = time.Now
	e := &e2e{t: t, f: f, wire: &recorder{}, api: &recorder{}, hostLog: &recorder{}, runtime: newE2ERuntime()}
	e.upstream = newFakeUpstream(t)
	e.broker = newInProcessBroker(t, e.upstream)
	e.admin, e.launcher, e.approver, e.viewer = f.token(f.admin(), "admin"), f.token(f.launcher(), "launcher"), f.token(f.approver(), "approver"), f.token(f.viewer(), "viewer")
	body := e.call("POST", "/api/v1/targets", e.admin, map[string]any{"name": "local", "reason": "Enroll the in-process host"}, 200)
	token := body["enrollment"].(map[string]any)["token"].(string)
	e.targetID = body["target"].(map[string]any)["id"].(string)
	base := t.TempDir()
	e.stateDir, e.secrets = filepath.Join(base, "hostd"), filepath.Join(base, "secrets")
	if err := os.Mkdir(e.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	e.cfg = hostd.Config{ServiceURL: f.http.URL, AllowLoopbackHTTP: true, Runtime: hostd.RuntimeDockerHost, Instance: "e2e",
		Launcher: []string{"/usr/bin/python3", "-I", "/var/lib/agentgate-poc-e2e/launch.py"}, SecretRoot: e.secrets,
		Broker: &hostd.BrokerConfig{Image: "agentgate-broker@sha256:" + strings.Repeat("b", 64), UID: 10002, GID: 10002, EgressNetwork: "agentgate-egress"}}
	raw, _ := json.Marshal(e.cfg)
	if err := os.WriteFile(filepath.Join(e.stateDir, "config.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	e.service = &hostd.HTTPService{Origin: f.http.URL, Client: &http.Client{Timeout: 30 * time.Second,
		Transport: &recordingTransport{next: http.DefaultTransport, rec: e.wire}}}
	id, err := hostd.Enroll(context.Background(), e.stateDir, e.cfg, e.service, token, "e2e-host", []string{hostproto.CapabilityDocker, hostproto.CapabilityPOCPolicyV2}, time.Now, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// The administrator compares the fingerprint the host printed.
	e.call("POST", "/api/v1/targets/"+e.targetID+"/approve-key", e.admin, map[string]any{"host_key_id": id.HostKeyID, "reason": "Matches the host console"}, 200)
	e.open()
	known, err := secretseal.LoadKnownTargets(filepath.Join(base, "known-targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	// The operator pins the host key fingerprint out of band (the host console).
	if err = known.Pin(e.targetID, secretseal.HostKeyFingerprint(e.daemon.Keys.Signing.Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
	e.known = known
	e.cycle()
	return e
}

// open starts a host agent on the state directory, as after a (re)start.
func (e *e2e) open() {
	d, err := hostd.Open(e.stateDir, e.service, e.runtime, log.New(e.hostLog, "agentgate-hostd: ", 0))
	if err != nil {
		e.t.Fatal(err)
	}
	d.Broker = e.broker
	d.Recover(context.Background())
	e.daemon = d
}

func (e *e2e) call(method, path, token string, body any, want int) map[string]any {
	e.t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r, _ := http.NewRequest(method, e.f.http.URL+path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	resp, err := e.f.http.Client().Do(r)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	e.api.Write(data)
	if resp.StatusCode != want {
		e.t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, data)
	}
	var out map[string]any
	json.Unmarshal(data, &out)
	return out
}

// cycle is one round of the daemon's loop without waiting for launches.
func (e *e2e) cycle() {
	ctx := context.Background()
	_ = e.daemon.FlushOutbox(ctx)
	if err := e.daemon.PollOnce(ctx); err != nil {
		e.t.Logf("poll: %v", err)
	}
	_ = e.daemon.FlushOutbox(ctx)
}

func (e *e2e) until(what string, done func() bool) {
	e.t.Helper()
	for i := 0; i < 200; i++ {
		e.cycle()
		if done() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.t.Fatalf("timed out waiting for %s", what)
}

func (e *e2e) sealKey() (*secretseal.SignedKeyRecord, ed25519.PublicKey) {
	e.t.Helper()
	body := e.call("GET", "/api/v1/targets/"+e.targetID+"/seal-key", e.viewer, nil, 200)
	raw, _ := json.Marshal(body["record"])
	rec, err := secretseal.ParseSignedKeyRecord(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	pub, err := hostproto.DecodeKey(body["host_public_key"].(string))
	if err != nil {
		e.t.Fatal(err)
	}
	return rec, ed25519.PublicKey(pub)
}

func (e *e2e) seal(name string, at time.Time) *secretseal.Sealed {
	e.t.Helper()
	rec, pub := e.sealKey()
	sealed, status, err := secretseal.SealForTarget(e.known, false, rec, pub, e.targetID, name, e2ePolicyDigest(e.t), []byte(e2eSecret), at)
	if err != nil || status != secretseal.PinMatch {
		e.t.Fatalf("seal: %v %v", status, err)
	}
	return sealed
}

func (e *e2e) putSecret(name string, sealed *secretseal.Sealed, launchers []string, rules []any) map[string]any {
	e.t.Helper()
	return e.call("POST", "/api/v1/secrets", e.admin, map[string]any{"name": name, "target": "local", "upstreams": []string{e2eUpstream},
		"header": "x-api-key", "ciphertext": sealed.Envelope.Encode(), "rules": rules, "extra_headers": map[string]string{"anthropic-version": "2023-06-01"},
		"allowed_profiles": []string{"dev"}, "allowed_launchers": launchers, "reason": "Model access for the coding agent"}, 200)
}

// e2ePolicyDigest is the policy putSecret's settings with messageRules make:
// what the operator's client computes and seals with the value.
func e2ePolicyDigest(t testing.TB) string {
	return inputPolicyDigest(t, SecretInput{Upstreams: []string{e2eUpstream}, Header: "x-api-key",
		Rules:        []SecretRuleInput{{Methods: []string{"POST"}, Path: "/v1/messages", Match: "exact"}, {Methods: []string{"GET"}, Path: "/v1/models", Match: "prefix"}},
		ExtraHeaders: map[string]string{"anthropic-version": "2023-06-01"}})
}

func messageRules() []any {
	return []any{map[string]any{"methods": []string{"POST"}, "path": "/v1/messages", "match": "exact"},
		map[string]any{"methods": []string{"GET"}, "path": "/v1/models", "match": "prefix"}}
}

func (e *e2e) secretState(id string) string {
	for _, item := range e.call("GET", "/api/v1/secrets", e.admin, nil, 200)["items"].([]any) {
		if s := item.(map[string]any); s["id"] == id {
			return s["state"].(string)
		}
	}
	return ""
}

// storedSecret seals, uploads and waits for the host's receipt, which the
// client verifies.
func (e *e2e) storedSecret(name string) map[string]any {
	e.t.Helper()
	sealed := e.seal(name, time.Now())
	sec := e.putSecret(name, sealed, []string{"oidc:lin"}, messageRules())
	id := sec["id"].(string)
	e.until("the secret to be stored", func() bool { return e.secretState(id) == "stored" })
	relayed := e.call("GET", "/api/v1/secrets/"+id+"/receipt", e.admin, nil, 200)
	raw, _ := json.Marshal(relayed["receipt"])
	receipt, err := secretseal.ParseReceipt(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	fp, err := sealed.VerifyReceipt(receipt)
	if err != nil || fp != relayed["value_fingerprint"] {
		e.t.Fatalf("the client cannot verify the host's receipt: %v", err)
	}
	return sec
}

func (e *e2e) spec(ref string) map[string]any {
	m := specMap("dev")
	m["secrets"] = []any{map[string]any{"ref": ref, "expose": map[string]any{"env": "ANTHROPIC_BASE_URL"}}}
	return m
}

func (e *e2e) launchState(id string) map[string]any {
	return e.call("GET", "/api/v1/launches/"+id, e.viewer, nil, 200)["launch"].(map[string]any)
}

// approvedLaunch creates a launch, has a different human approve it, and
// returns it with its plan.
func (e *e2e) approvedLaunch(ref string) (string, map[string]any) {
	e.t.Helper()
	created := e.call("POST", "/api/v1/launches", e.launcher, e.spec(ref), 200)
	l, plan := created["launch"].(map[string]any), created["plan"].(map[string]any)
	if l["state"] != StateApprovalPending {
		e.t.Fatalf("a launch with secrets skipped approval: %v", l["state"])
	}
	e.call("POST", "/api/v1/launches/"+l["id"].(string)+"/approve", e.launcher, map[string]any{"reason": "Approving my own launch"}, 403)
	e.call("POST", "/api/v1/launches/"+l["id"].(string)+"/approve", e.approver, map[string]any{"reason": "Reviewed the broker rules"}, 200)
	return l["id"].(string), plan
}

func TestBrokeredSecretEndToEnd(t *testing.T) {
	e := newE2E(t)
	f := e.f
	f.profile("dev", false)
	if e.call("GET", "/api/v1/targets/"+e.targetID, e.viewer, nil, 200)["seal_key_id"] == nil {
		t.Fatal("the target does not show its published seal key")
	}
	caps := e.call("GET", "/api/v1/targets/"+e.targetID, e.viewer, nil, 200)["capabilities"].([]any)
	if !strings.Contains(fmt.Sprint(caps), hostproto.CapabilityBrokeredSecrets) {
		t.Fatalf("the host does not report brokered-secrets: %v", caps)
	}
	sec := e.storedSecret("anthropic")
	launchID, plan := e.approvedLaunch("anthropic")
	planBroker := plan["broker"].(map[string]any)
	baseURL := "http://" + planBroker["address"].(string) + ":8443/anthropic"
	if plan["secrets"].([]any)[0].(map[string]any)["base_url"] != baseURL || plan["kernel_verified"] != false {
		t.Fatalf("plan %v", plan)
	}
	var launcher []byte
	select {
	case launcher = <-func() chan []byte {
		e.until("the launch to run", func() bool { return e.runtime.runCount() == 1 })
		return e.runtime.started
	}():
	case <-time.After(10 * time.Second):
		t.Fatal("the launch never ran")
	}
	if e.broker.running() != 1 {
		t.Fatal("the agent runs without its broker")
	}
	var job struct {
		Broker struct {
			Network, Address, TargetAddress string
			Port                            int
			Env                             map[string]string
		} `json:"broker"`
		Policy json.RawMessage `json:"policy"`
	}
	if err := json.Unmarshal(launcher, &job); err != nil {
		t.Fatal(err)
	}
	if job.Broker.Env["ANTHROPIC_BASE_URL"] != baseURL || len(job.Broker.Env) != 1 || job.Broker.Address != planBroker["address"] {
		t.Fatalf("the agent's broker environment %+v", job.Broker)
	}
	if !bytes.Contains(job.Policy, []byte(`"broker":{"address":"`+planBroker["address"].(string)+`","protocol":"tcp","port":8443}`)) || bytes.Contains(job.Policy, []byte(`"taskboard"`)) {
		t.Fatalf("the effective launch policy does not hold exactly the broker endpoint: %s", job.Policy)
	}
	noSecret(t, "the launcher job (the agent's environment and policy)", launcher)

	// The agent: plain HTTP to the broker, no credential of its own.
	agentBytes := &recorder{}
	agent := e.broker.agentClient(agentBytes)
	req, _ := http.NewRequest("POST", job.Broker.Env["ANTHROPIC_BASE_URL"]+"/v1/messages", strings.NewReader(`{"model":"m","max_tokens":1}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", "agent-tries-its-own-key")
	resp, err := agent.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"id":"msg_1"`) {
		t.Fatalf("agent request: %d %s", resp.StatusCode, body)
	}
	denied, err := agent.Get(job.Broker.Env["ANTHROPIC_BASE_URL"] + "/v1/admin/keys")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, denied.Body)
	denied.Body.Close()
	if denied.StatusCode != 403 {
		t.Fatalf("a path outside the rules was forwarded: %d", denied.StatusCode)
	}
	if _, err := agent.Get("http://10.0.0.5:8080/"); err == nil {
		t.Fatal("the agent reached a private address other than the broker")
	}
	seen := e.upstream.requests()
	if len(seen) != 1 || seen[0].Key != e2eSecret || seen[0].Path != "/v1/messages" || seen[0].Host != e2eUpstream || seen[0].SNI != e2eUpstream {
		t.Fatalf("the upstream saw %+v", seen)
	}
	noSecret(t, "the agent's request and response bytes", agentBytes.Bytes())
	if !bytes.Contains(agentBytes.Bytes(), []byte(`"echo":"`+strings.Repeat("*", len(e2eSecret))+`"`)) {
		t.Fatal("the upstream's echo of the credential was not masked")
	}

	// Stop: the broker stops after the agent, its stats become the receipt.
	e.call("POST", "/api/v1/launches/"+launchID+"/stop", e.launcher, map[string]any{"reason": "Done"}, 200)
	e.until("the launch to stop", func() bool { return e.launchState(launchID)["state"] == StateStopped })
	if e.broker.running() != 0 {
		t.Fatal("the broker outlived its launch")
	}
	detail := e.launchState(launchID)
	receiptRaw, _ := json.Marshal(detail["receipt"])
	var receipt hostproto.Receipt
	if err := json.Unmarshal(receiptRaw, &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.KernelVerified || detail["kernel_verified"] != false || receipt.BrokerCounts[e2eUpstream] != 1 || receipt.BrokerEvidence == nil ||
		receipt.BrokerEvidence.Missing != "" || receipt.BrokerEvidence.Requests.Denied != 1 || receipt.BrokerEvidence.Denied["path_not_allowed"] != 1 ||
		receipt.BrokerEvidence.Listen != "tcp:"+planBroker["address"].(string)+":8443" || receipt.BrokerEvidence.Routes["anthropic"].Redactions == 0 ||
		!receipt.DomainEmpty || !receipt.EnforcementReleased {
		t.Fatalf("receipt %s", receiptRaw)
	}
	calls := strings.Join(e.broker.calls, ",")
	if calls != "start "+launchID+",stop "+launchID+",remove "+launchID {
		t.Fatalf("broker lifecycle %s", calls)
	}

	// Nowhere but the host's store and the upstream: the wire (only sealed),
	// the database, the audit, the logs, the receipt, the stats, the state.
	noSecret(t, "the host protocol traffic", e.wire.Bytes())
	noSecret(t, "the user API responses", e.api.Bytes())
	noSecret(t, "the host agent log", e.hostLog.Bytes())
	noSecret(t, "the broker log", e.broker.logs.Bytes())
	noSecret(t, "the receipt", receiptRaw)
	dump := &bytes.Buffer{}
	tables, _ := f.s.DB.Query("SELECT name FROM sqlite_master WHERE type='table'")
	var names []string
	for tables.Next() {
		var name string
		tables.Scan(&name)
		names = append(names, name)
	}
	tables.Close()
	for _, table := range names {
		rows, _ := f.s.DB.Query("SELECT * FROM " + table)
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			rows.Scan(ptrs...)
			dump.WriteString(jsonText(vals))
		}
		rows.Close()
	}
	noSecret(t, "the service database (every table, including audit)", dump.Bytes())
	// Job envelopes on the wire are base64url of JSON: decode every one the
	// host received or sent and check the plaintext is absent; the secret-put
	// job among them carries only the sealed envelope.
	sawPut := false
	for _, raw := range bytes.Split(e.wire.Bytes(), []byte(`"payload":"`)) {
		if end := bytes.IndexByte(raw, '"'); end > 0 {
			if decoded, err := base64.RawURLEncoding.DecodeString(string(raw[:end])); err == nil {
				noSecret(t, "a decoded job or request payload", decoded)
				sawPut = sawPut || bytes.Contains(decoded, []byte(`"type":"secret-put"`))
			}
		}
	}
	if !sawPut {
		t.Fatal("the secret-put job was not seen on the wire")
	}
	filepath.Walk(e.stateDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			data, _ := os.ReadFile(path)
			noSecret(t, "host agent state file "+filepath.Base(path), data)
		}
		return nil
	})
	evidence, err := os.ReadFile(filepath.Join(e.stateDir, "brokers", launchID, "evidence.json"))
	if err != nil || !bytes.Contains(evidence, []byte(`"forwarded":1`)) {
		t.Fatalf("broker evidence on the host: %v %s", err, evidence)
	}
	if _, err := os.Stat(filepath.Join(e.stateDir, "brokers", launchID, "broker.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the broker configuration outlived the launch")
	}
	// The value exists exactly once on the host: its 0600 store record (the
	// broker's copy is removed once it runs).
	if stored, ok := e.hostValue("anthropic"); !ok || stored != e2eSecret {
		t.Fatal("the host store does not hold the value")
	}
	if _, err := os.Stat(filepath.Join(e.stateDir, "brokers", launchID, "secrets")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the broker's secret copy outlived the launch")
	}
	if e.secretState(sec["id"].(string)) != "stored" {
		t.Fatal("the secret changed state")
	}
}

func TestBrokeredSecretRefusesASubstitutedSealKey(t *testing.T) {
	e := newE2E(t)
	rec, pub := e.sealKey()
	// The service substitutes the record with one signed by its own key.
	_, service, _ := ed25519.GenerateKey(rand.Reader)
	own, _ := secretseal.GenerateHostKey(e.targetID, service, time.Now(), time.Hour)
	forged := own.Published()
	if _, _, err := secretseal.SealForTarget(e.known, false, &forged, pub, e.targetID, "anthropic", e2ePolicyDigest(e.t), []byte(e2eSecret), time.Now()); !errors.Is(err, secretseal.ErrSignature) {
		t.Fatalf("a record not signed by the pinned host key was sealed to: %v", err)
	}
	// ... or substitutes the host key as well, signing with its own.
	if _, _, err := secretseal.SealForTarget(e.known, false, &forged, service.Public().(ed25519.PublicKey), e.targetID, "anthropic", e2ePolicyDigest(e.t), []byte(e2eSecret), time.Now()); !errors.Is(err, secretseal.ErrFingerprint) {
		t.Fatalf("a substituted host key passed the pin: %v", err)
	}
	// A tampered record (another public key, same signature) fails too.
	tampered := *rec
	tampered.Record.PublicKey = forged.Record.PublicKey
	tampered.Record.KeyID = forged.Record.KeyID
	if _, _, err := secretseal.SealForTarget(e.known, false, &tampered, pub, e.targetID, "anthropic", e2ePolicyDigest(e.t), []byte(e2eSecret), time.Now()); err == nil {
		t.Fatal("a tampered seal key record was sealed to")
	}
	// The service cannot store a forged record as the host's either: the
	// next poll's record is the host's own and a forged one is never served.
	raw, _ := json.Marshal(forged)
	if _, err := e.f.s.DB.Exec("UPDATE targets SET seal_key=? WHERE id=?", string(raw), e.targetID); err != nil {
		t.Fatal(err)
	}
	rec2, pub2 := e.sealKey()
	if _, _, err := secretseal.SealForTarget(e.known, false, rec2, pub2, e.targetID, "anthropic", e2ePolicyDigest(e.t), []byte(e2eSecret), time.Now()); err == nil {
		t.Fatal("a client sealed to a record the database substituted")
	}
	e.cycle()
	rec3, pub3 := e.sealKey()
	if _, _, err := secretseal.SealForTarget(e.known, false, rec3, pub3, e.targetID, "anthropic", e2ePolicyDigest(e.t), []byte(e2eSecret), time.Now()); err != nil {
		t.Fatalf("the host's own record is not served after its next poll: %v", err)
	}
}

func TestBrokeredSecretRefusesReplayAndRollbackOfSecretPut(t *testing.T) {
	e := newE2E(t)
	e.f.profile("dev", false)
	older := e.seal("anthropic", time.Now().Add(-time.Minute))
	sec := e.storedSecret("anthropic")
	// The service relays the same envelope again after a delete: a replay.
	e.call("DELETE", "/api/v1/secrets/"+sec["id"].(string), e.admin, map[string]any{"reason": "Rotate the key"}, 200)
	e.until("the secret to be deleted", func() bool { return e.secretState(sec["id"].(string)) == "deleted" })
	if e.hostHolds("anthropic") {
		t.Fatal("the deleted value remains on the host")
	}
	// An older envelope (sealed before the stored one) is a rollback.
	rolled := e.putSecret("anthropic", older, []string{"oidc:lin"}, messageRules())
	e.until("the rollback to be refused", func() bool { return e.secretState(rolled["id"].(string)) == "failed" })
	if e.hostHolds("anthropic") {
		t.Fatal("a rolled-back envelope set the deleted secret again")
	}
	var reason string
	e.f.s.DB.QueryRow("SELECT after_json FROM audit WHERE action='secret.store.failed' ORDER BY id DESC LIMIT 1").Scan(&reason)
	if !strings.Contains(reason, "replayed_or_rolled_back") {
		t.Fatalf("the refusal reason %s", reason)
	}
	// A fresh envelope is accepted.
	fresh := e.storedSecret("anthropic")
	if e.secretState(fresh["id"].(string)) != "stored" {
		t.Fatal("a fresh envelope after the refusals was not stored")
	}
}

func TestBrokeredSecretScopeBrokerFailureAndHostCrash(t *testing.T) {
	e := newE2E(t)
	f := e.f
	f.profile("dev", false)
	f.profile("other", false)
	e.storedSecret("anthropic")
	// A launcher the secret is not scoped to, and a profile it is not scoped to.
	other := f.token(f.human("oidc:mallory", "launchers"), "launcher")
	if body := e.call("POST", "/api/v1/launches", other, e.spec("anthropic"), 403); body["error"].(map[string]any)["code"] != "secret_scope" {
		t.Fatalf("an unauthorized launcher: %v", body)
	}
	m := e.spec("anthropic")
	m["access"] = map[string]any{"profile": "other", "version": 1}
	if body := e.call("POST", "/api/v1/launches", e.launcher, m, 403); body["error"].(map[string]any)["code"] != "secret_scope" {
		t.Fatalf("an unauthorized profile: %v", body)
	}
	// The broker fails to start: the launch fails closed and nothing runs.
	e.broker.mu.Lock()
	e.broker.failStart = true
	e.broker.mu.Unlock()
	failed, _ := e.approvedLaunch("anthropic")
	e.until("the launch to fail", func() bool { return e.launchState(failed)["state"] == StateFailed })
	if l := e.launchState(failed); l["evidence_missing"] != "not_started" || e.runtime.runCount() != 0 || e.broker.running() != 0 {
		t.Fatalf("a broker start failure: %v runs %d", l, e.runtime.runCount())
	}
	if !strings.Contains(strings.Join(e.broker.calls, ","), "remove "+failed) {
		t.Fatalf("the failed broker was not removed: %v", e.broker.calls)
	}
	e.broker.mu.Lock()
	e.broker.failStart = false
	e.broker.mu.Unlock()
	// The host agent dies mid-launch with the broker running; the next start
	// stops and removes the broker and reports the launch with its evidence.
	crashed, _ := e.approvedLaunch("anthropic")
	e.until("the launch to run", func() bool { return e.runtime.runCount() == 1 })
	<-e.runtime.started
	if e.broker.running() != 1 {
		t.Fatal("no broker before the crash")
	}
	abandoned := e.daemon
	t.Cleanup(func() {
		close(e.runtime.hold)
		abandoned.Wait()
	})
	e.open() // a new agentgate-hostd process on the same state directory
	if e.broker.running() != 0 {
		t.Fatal("the broker a crash left behind still runs after recovery")
	}
	e.until("the crashed launch to end", func() bool { return e.launchState(crashed)["state"] == StateFailed })
	detail := e.launchState(crashed)
	raw, _ := json.Marshal(detail["receipt"])
	var receipt hostproto.Receipt
	json.Unmarshal(raw, &receipt)
	if receipt.BrokerEvidence == nil || receipt.BrokerEvidence.Missing != "" || receipt.KernelVerified || !strings.Contains(fmt.Sprint(detail["terminal_reason"]), "host_restarted") {
		t.Fatalf("crashed launch %v receipt %s", detail, raw)
	}
	noSecret(t, "the crashed launch's receipt", raw)
	noSecret(t, "the host agent log", e.hostLog.Bytes())
}

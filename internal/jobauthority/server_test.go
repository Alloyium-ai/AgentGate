// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/requestproof"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func (f *testFixture) call(method, path, subject string, key ed25519.PrivateKey, value any) *httptest.ResponseRecorder {
	raw := []byte{}
	if value != nil {
		raw, _ = json.Marshal(value)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(raw))
	r.Header.Set("Authorization", "Alloyium-Proof "+requestproof.Sign(subject, method, path, "agentgate-authority.v1:authority", f.store.Epoch(), raw, key))
	w := httptest.NewRecorder()
	f.s.ServeHTTP(w, r)
	return w
}
func (f *testFixture) issue(t *testing.T) lifecycle.Authorization {
	t.Helper()
	w := f.call("POST", "/v1/grants/issue", "agent-one", f.agent, f.request)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var r IssueResponse
	if json.Unmarshal(w.Body.Bytes(), &r) != nil || r.Protocol != IssuedProtocol {
		t.Fatal(w.Body.String())
	}
	return r.Authorization
}
func TestIssueUsesSignedNodeClockAndExactGrant(t *testing.T) {
	f := newFixture(t)
	a := f.issue(t)
	envelope, e := jobgrant.Decode(a.Grant)
	if e != nil {
		t.Fatal(e)
	}
	claims, e := jobgrant.VerifySigned(envelope, f.s.authorityKeys(), f.request.Document)
	if e != nil || claims.IssuedMonoNS != 500 || claims.Binding.CgroupID != 42 {
		t.Fatal(claims, e)
	}
	if _, _, e = f.store.Grant(context.Background(), a.Binding.GrantID); e != nil {
		t.Fatal(e)
	}
}
func TestIssueRejectsChangedCustodyAndUnavailableTrust(t *testing.T) {
	cases := map[string]func(*testFixture){"header": func(f *testFixture) { f.request.Prepared.AuditHeader = append(f.request.Prepared.AuditHeader, ' ') }, "manifest": func(f *testFixture) { f.request.Manifest.Arguments = []string{"changed"} }, "node-clock": func(f *testFixture) { f.request.Prepared.PreparedAtUnix -= 60 }, "enrollment": func(f *testFixture) { f.deps.reject = true }, "preparation": func(f *testFixture) { f.request.Prepared.Evidence.MandatoryHooks = false }, "document": func(f *testFixture) { f.request.Document.Lifecycle.DurationSeconds++ }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			change(f)
			w := f.call("POST", "/v1/grants/issue", "agent-one", f.agent, f.request)
			if w.Code == 200 {
				t.Fatal("untrusted request issued")
			}
			if _, _, e := f.store.Grant(context.Background(), "grant-one"); e == nil {
				t.Fatal("invalid grant persisted")
			}
		})
	}
}
func TestProofReplaySurvivesRestartAndRequestChanges(t *testing.T) {
	f := newFixture(t)
	raw, _ := json.Marshal(f.request)
	token := requestproof.Sign("agent-one", "POST", "/v1/grants/issue", "agentgate-authority.v1:authority", f.store.Epoch(), raw, f.agent)
	send := func(body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/v1/grants/issue", bytes.NewReader(body))
		r.Header.Set("Authorization", "Alloyium-Proof "+token)
		w := httptest.NewRecorder()
		f.s.ServeHTTP(w, r)
		return w
	}
	if send(append(append([]byte{}, raw...), ' ')).Code != 401 {
		t.Fatal("changed body proof accepted")
	}
	if send(raw).Code != 200 {
		t.Fatal("valid issue failed")
	}
	if e := f.store.Close(); e != nil {
		t.Fatal(e)
	}
	store, e := OpenStore(filepath.Join(f.dir, "authority.db"), "fixture-epoch")
	if e != nil {
		t.Fatal(e)
	}
	f.store = store
	t.Cleanup(func() { store.Close() })
	f.config.Store = store
	f.s, e = New(f.config)
	if e != nil {
		t.Fatal(e)
	}
	if w := send(raw); w.Code != 401 {
		t.Fatal("proof replay accepted", w.Code)
	}
}
func TestConcurrentNonceAndGrantCustody(t *testing.T) {
	f := newFixture(t)
	var wg sync.WaitGroup
	results := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- f.store.Consume(context.Background(), "agent-one", "same", time.Now().Unix()+65, time.Now().Unix())
		}()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
}
func TestNodeStateAndRevocationFailClosed(t *testing.T) {
	f := newFixture(t)
	f.issue(t)
	path := "/v1/grants/state?grant_id=grant-one"
	w := f.call("GET", path, "node-one", f.node, nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var state StateResponse
	json.Unmarshal(w.Body.Bytes(), &state)
	if !state.Known || state.Revoked {
		t.Fatal(state)
	}
	if f.call("GET", path, "agent-one", f.agent, nil).Code != 401 {
		t.Fatal("agent queried node state")
	}
	if e := f.store.Revoke(context.Background(), "grant-one"); e != nil {
		t.Fatal(e)
	}
	w = f.call("GET", path, "node-one", f.node, nil)
	json.Unmarshal(w.Body.Bytes(), &state)
	if !state.Known || !state.Revoked {
		t.Fatal(state)
	}
	w = f.call("GET", "/v1/grants/state?grant_id=unknown", "node-one", f.node, nil)
	json.Unmarshal(w.Body.Bytes(), &state)
	if state.Known {
		t.Fatal(state)
	}
}

type monoClock struct{ now uint64 }

func (c *monoClock) NowNS() (uint64, error) { return c.now, nil }

type nodeSigner struct{ key ed25519.PrivateKey }

func (nodeSigner) KeyID() string { return "node-key" }
func (s nodeSigner) Sign(_ context.Context, raw []byte) ([]byte, error) {
	return ed25519.Sign(s.key, raw), nil
}
func (f *testFixture) bundle(t *testing.T, a lifecycle.Authorization) jobaudit.Bundle {
	return f.bundleSize(t, a, 1)
}
func (f *testFixture) bundleSize(t *testing.T, a lifecycle.Authorization, fileCount uint64) jobaudit.Bundle {
	t.Helper()
	var h jobaudit.Header
	json.Unmarshal(f.request.Prepared.AuditHeader, &h)
	clock := &monoClock{now: 1000}
	writer, e := jobaudit.Open(jobaudit.Config{Path: filepath.Join(f.dir, "audit.jsonl"), Header: h, Registry: testRegistry(h.Binding), Clock: clock, Document: f.request.Document, AuthorityKeys: f.s.authorityKeys(), NodeKeys: f.config.NodeKeys, MaxRecords: 10000, MaxBytes: 32 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer writer.Close()
	grant, _ := jobgrant.Decode(a.Grant)
	if e = writer.AttachGrant(context.Background(), grant); e != nil {
		t.Fatal(e)
	}
	bound := jobaudit.GrantExpiry{ExpiresAt: grant.Claims.ExpiresAt, WallSampleUnixNS: f.deps.wall.UnixNano(), MonoSampleNS: 900, MonoAfterNS: 950}
	bound.KernelDeadlineNS = bound.MonoSampleNS + uint64(bound.ExpiresAt*int64(time.Second)-bound.WallSampleUnixNS)
	if bound.KernelDeadlineNS > h.Binding.DeadlineNS {
		bound.KernelDeadlineNS = h.Binding.DeadlineNS
	}
	frame, e := nodecontrol.Encode(h.Binding, "grant_expiry_bound", bound)
	if e != nil {
		t.Fatal(e)
	}
	if e = writer.Append(context.Background(), nodecontrol.Stream, frame); e != nil {
		t.Fatal(e)
	}
	set, setErr := runtimeclosure.New([]runtimeclosure.File{})
	if setErr != nil {
		t.Fatal(setErr)
	}
	measurement, setErr := set.Verify(context.Background())
	if setErr != nil {
		t.Fatal(setErr)
	}
	proof, proofErr := nodecontrol.Encode(h.Binding, "runtime_files_verified", nodecontrol.RuntimeFiles{Manifest: f.request.Manifest, Measurement: measurement})
	if proofErr != nil {
		t.Fatal(proofErr)
	}
	if e = writer.Append(context.Background(), nodecontrol.Stream, proof); e != nil {
		t.Fatal(e)
	}
	clock.now = 2000
	for _, stream := range h.RequiredStreams {
		count := uint64(1)
		if stream.Name == "files" {
			count = fileCount
		}
		for i := uint64(1); i <= count; i++ {
			var raw []byte
			if stream.Kind == "control" {
				raw, e = nodecontrol.Encode(h.Binding, "fixture-terminal", map[string]bool{"synthetic": true})
				if e != nil {
					t.Fatal(e)
				}
			} else {
				raw = fixture(stream.Name + "/" + stream.Version)
				put64(raw, 0, i)
			}
			if e = writer.Append(context.Background(), stream.Name, raw); e != nil {
				t.Fatal(stream.Name, e)
			}
		}
		c := jobaudit.FinalCounters{Sequence: count, Available: true}
		if stream.Kind == "control" {
			c.Sequence += 2
		}
		if stream.Kind == "resource" {
			c.Decisions = count
		}
		if e = writer.FinishStream(context.Background(), stream.Name, c); e != nil {
			t.Fatal(e)
		}
	}
	_, e = writer.Seal(context.Background(), jobaudit.Terminal{State: "completed", Empty: true, RightsRemoved: true, OutputDigest: strings.Repeat("4", 64), CountersAvailable: true}, nodeSigner{f.node})
	if e != nil {
		t.Fatal(e)
	}
	return writer.Export()
}
func TestReceiptRequiresExactNodeSealAndSeparateAuthority(t *testing.T) {
	f := newFixture(t)
	a := f.issue(t)
	bundle := f.bundle(t, a)
	bad := bundle
	bad.Seal = &jobaudit.NodeSeal{}
	if w := f.call("POST", "/v1/audit/receipt", "node-one", f.node, bad); w.Code == 200 {
		t.Fatal("unsigned seal accepted")
	}
	w := f.call("POST", "/v1/audit/receipt", "node-one", f.node, bundle)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var reply ReceiptResponse
	if json.Unmarshal(w.Body.Bytes(), &reply) != nil {
		t.Fatal(w.Body.String())
	}
	bundle.Authority = &reply.Receipt
	if verdict := jobaudit.VerifyOffline(bundle, jobaudit.Trust{NodeKeys: f.config.NodeKeys, AuthorityKeys: f.s.authorityKeys(), Registry: testRegistry(bundle.Header.Binding), Document: f.request.Document}); verdict.State != "VALID_COMPLETE" {
		t.Fatal(verdict)
	}
}
func TestPrivateUDSUsesActualProofRequest(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.dir, "authority.sock")
	listener, e := ListenUnix(path, nil)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: f.s, ReadHeaderTimeout: time.Second}
	done := make(chan struct{})
	go func() { server.Serve(listener); close(done) }()
	defer func() { server.Close(); <-done }()
	// This test checks the real proof and durable grant. Concurrent race suites
	// can spend more than one second in SQLite before they return the headers.
	client := &http.Client{Timeout: 5*time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	raw, _ := json.Marshal(f.request)
	req, _ := http.NewRequest("POST", "http://authority/v1/grants/issue", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Alloyium-Proof "+requestproof.Sign("agent-one", "POST", "/v1/grants/issue", "agentgate-authority.v1:authority", f.store.Epoch(), raw, f.agent))
	reply, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer reply.Body.Close()
	if reply.StatusCode != 200 {
		t.Fatal(reply.StatusCode)
	}
}

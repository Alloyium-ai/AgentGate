// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
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
)

// testSecret is an obvious fake. Every test that can observe output checks
// that no form of it escapes.
const testSecret = "sk-test-FAKE-broker-0123456789abcdefXYZ"

// fakePublic is the address the fake resolver returns for the upstream. It is
// never contacted: the test dialer maps it onto the local fake upstream.
var fakePublic = netip.MustParseAddr("1.2.3.4")

type testCA struct {
	pool *x509.CertPool
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestCA(t testing.TB) *testCA {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agentgate broker test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{pool: pool, cert: cert, key: key}
}

func (ca *testCA) leaf(t testing.TB, names ...string) (tls.Certificate, string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: names[0]},
		DNSNames: names, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, base64.StdEncoding.EncodeToString(sum[:])
}

// seen records what the fake upstream received.
type seen struct {
	Method, Path, RequestURI, Query, Host, SNI string
	Header                                     http.Header
	Body                                       []byte
	ContentLength                              int64
	TransferEncoding                           []string
}

type env struct {
	t          *testing.T
	ca         *testCA
	pin        string
	upstream   *httptest.Server
	handler    http.HandlerFunc
	mu         sync.Mutex
	got        []seen
	resolver   *fakeResolver
	dialed     []netip.AddrPort
	cfg        *Config
	srv        *Server
	addr       string
	dir        string
	logs       *lockedBuffer
	cancel     context.CancelFunc
	done       chan struct{}
	reason     string
	serveErr   error
	authority  string
	clientConn int
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type envOption func(m map[string]any, e *env)

func withLimits(l map[string]any) envOption {
	return func(m map[string]any, _ *env) { m["limits"] = l }
}

func withRules(rules ...map[string]any) envOption {
	return func(m map[string]any, _ *env) {
		var list []any
		for _, r := range rules {
			list = append(list, r)
		}
		m["routes"].([]any)[0].(map[string]any)["rules"] = list
	}
}

func withCredential(c map[string]any) envOption {
	return func(m map[string]any, _ *env) {
		cred := m["routes"].([]any)[0].(map[string]any)["credential"].(map[string]any)
		for k, v := range c {
			cred[k] = v
		}
	}
}

func withUpstream(u map[string]any) envOption {
	return func(m map[string]any, _ *env) {
		up := m["routes"].([]any)[0].(map[string]any)["upstream"].(map[string]any)
		for k, v := range u {
			up[k] = v
		}
	}
}

func withDeadline(d time.Duration) envOption {
	return func(m map[string]any, _ *env) { m["deadline"] = time.Now().Add(d).UTC().Format(time.RFC3339Nano) }
}

// withCAPin pins the test CA's key, which is in every verified chain.
func withCAPin() envOption {
	return func(m map[string]any, e *env) {
		sum := sha256.Sum256(e.ca.cert.RawSubjectPublicKeyInfo)
		m["routes"].([]any)[0].(map[string]any)["upstream"].(map[string]any)["pin_spki_sha256"] =
			[]any{base64.StdEncoding.EncodeToString(sum[:])}
	}
}

// betaSecret is the second route's fake credential.
const betaSecret = "ghp_FAKEbetaTOKEN0123456789abcdefghijkl"

// withSecondRoute adds route "beta" with its own secret and upstream name.
func withSecondRoute() envOption {
	return func(m map[string]any, e *env) {
		path := filepath.Join(e.dir, "beta.secret")
		if err := os.WriteFile(path, []byte(betaSecret), 0o600); err != nil {
			e.t.Fatal(err)
		}
		m["routes"] = append(m["routes"].([]any), map[string]any{
			"name":       "beta",
			"upstream":   map[string]any{"host": "beta.example.test"},
			"credential": map[string]any{"secret_file": path, "header": "authorization", "scheme": "Bearer"},
			"rules":      []any{allRule()},
		})
	}
}

func allRule() map[string]any {
	return map[string]any{"methods": []any{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}, "path": "/", "match": "prefix"}
}

func newEnv(t *testing.T, opts ...envOption) *env {
	t.Helper()
	e := &env{t: t, ca: newTestCA(t), resolver: newFakeResolver(), dir: t.TempDir(), logs: &lockedBuffer{}}
	leaf, pin := e.ca.leaf(t, "api.example.test", "beta.example.test")
	e.pin = pin
	e.handler = func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }
	e.upstream = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		e.mu.Lock()
		e.got = append(e.got, seen{Method: r.Method, Path: r.URL.Path, RequestURI: r.RequestURI, Query: r.URL.RawQuery,
			Host: r.Host, SNI: r.TLS.ServerName, Header: r.Header.Clone(), Body: body, ContentLength: r.ContentLength,
			TransferEncoding: r.TransferEncoding})
		h := e.handler
		e.mu.Unlock()
		h(w, r)
	}))
	e.upstream.TLS = &tls.Config{Certificates: []tls.Certificate{leaf}}
	e.upstream.StartTLS()
	t.Cleanup(e.upstream.Close)
	e.resolver.set("api.example.test", []string{fakePublic.String()})
	e.resolver.set("beta.example.test", []string{fakePublic.String()})

	secretPath := filepath.Join(e.dir, "anthropic.secret")
	if err := os.WriteFile(secretPath, []byte(testSecret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := validConfigJSON()
	m["deadline"] = time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	m["stats_path"] = filepath.Join(e.dir, "stats.json")
	m["routes"].([]any)[0].(map[string]any)["credential"].(map[string]any)["secret_file"] = secretPath
	m["routes"].([]any)[0].(map[string]any)["rules"] = []any{
		map[string]any{"methods": []any{"POST"}, "path": "/v1/messages", "match": "exact"},
		map[string]any{"methods": []any{"GET"}, "path": "/v1/models", "match": "prefix"},
	}
	for _, o := range opts {
		o(m, e)
	}
	raw := encode(t, m)
	cfg, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upAddr := e.upstream.Listener.Addr().String()
	srv, err := New(cfg, ConfigDigest(raw), e.logs, Overrides{
		Listener: ln,
		Resolver: e.resolver,
		RootCAs:  e.ca.pool,
		Dial: func(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
			e.mu.Lock()
			e.dialed = append(e.dialed, addr)
			e.mu.Unlock()
			if addr.Addr() != fakePublic {
				return nil, &upstreamError{errKindConnect}
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", upAddr)
		},
		LocalAddrs: func() ([]net.Addr, error) { return nil, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	e.srv = srv
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	e.authority = cfg.Listen.ListenAuthority()
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan struct{})
	go func() {
		defer close(e.done)
		e.reason, e.serveErr = srv.Serve(ctx, Hardening{})
	}()
	t.Cleanup(func() {
		e.stop()
		e.assertNoSecretLeak()
	})
	return e
}

func (e *env) stop() {
	e.cancel()
	select {
	case <-e.done:
	case <-time.After(10 * time.Second):
		e.t.Fatal("broker did not stop")
	}
}

func (e *env) requests() []seen {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]seen(nil), e.got...)
}

func (e *env) setHandler(h http.HandlerFunc) {
	e.mu.Lock()
	e.handler = h
	e.mu.Unlock()
}

func (e *env) client() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, DisableCompression: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (e *env) do(method, path string, body io.Reader, headers ...string) *http.Response {
	e.t.Helper()
	req, err := http.NewRequest(method, "http://"+e.addr+path, body)
	if err != nil {
		e.t.Fatal(err)
	}
	req.Host = e.authority
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Add(headers[i], headers[i+1])
	}
	resp, err := e.client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	return resp
}

func (e *env) text(resp *http.Response) string {
	e.t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		e.t.Fatalf("body: %v", err)
	}
	return string(b)
}

// raw sends bytes on a fresh connection, half-closes it so a truncated body
// ends, and returns everything read back.
func (e *env) raw(payload string) string { return e.rawConn(payload, true) }

// rawConn is raw without the half-close: net/http treats a half-close after a
// complete request as the client going away and cancels the request.
func (e *env) rawConn(payload string, halfClose bool) string {
	e.t.Helper()
	c, err := net.Dial("tcp", e.addr)
	if err != nil {
		e.t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.WriteString(c, payload); err != nil {
		e.t.Fatal(err)
	}
	if tc, ok := c.(*net.TCPConn); ok && halfClose {
		tc.CloseWrite()
	}
	out, _ := io.ReadAll(bufio.NewReader(c))
	return string(out)
}

func (e *env) stats() *StatsDocument {
	e.t.Helper()
	raw, err := e.srv.Snapshot()
	if err != nil {
		e.t.Fatal(err)
	}
	doc, err := ParseStats(raw)
	if err != nil {
		e.t.Fatalf("stats: %v\n%s", err, raw)
	}
	return doc
}

func secretForms() []string {
	forms := []string{testSecret}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		forms = append(forms, enc.EncodeToString([]byte(testSecret)))
	}
	return forms
}

// assertNoSecretLeak greps everything the broker produced that a sandbox or
// operator can see: logs, the stats file and the in-memory stats.
func (e *env) assertNoSecretLeak() {
	e.t.Helper()
	var sources []string
	sources = append(sources, e.logs.String())
	if raw, err := os.ReadFile(e.cfg.StatsPath); err == nil {
		sources = append(sources, string(raw))
	}
	if raw, err := e.srv.Snapshot(); err == nil {
		sources = append(sources, string(raw))
	}
	if e.serveErr != nil {
		sources = append(sources, e.serveErr.Error())
	}
	for _, s := range sources {
		for _, f := range secretForms() {
			if strings.Contains(s, f) || strings.Contains(s, testSecret[4:20]) {
				e.t.Fatalf("secret form leaked into broker output")
			}
		}
	}
}

func mustNotContainSecret(t *testing.T, what, s string) {
	t.Helper()
	for _, f := range secretForms() {
		if strings.Contains(s, f) {
			t.Fatalf("secret leaked into %s", what)
		}
	}
}

func (e *env) dialRaw() net.Conn {
	e.t.Helper()
	c, err := net.Dial("tcp", e.addr)
	if err != nil {
		e.t.Fatal(err)
	}
	return c
}

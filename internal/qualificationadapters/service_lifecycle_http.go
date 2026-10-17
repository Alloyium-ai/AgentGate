// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"golang.org/x/sys/unix"
)

type serviceLifecycleHTTPCall struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Request  []byte `json:"request"`
	Status   int    `json:"status"`
	Response []byte `json:"response"`
	MonoNS   uint64 `json:"mono_ns,string"`
}
type serviceLifecycleHTTPClient struct {
	connection net.Conn
	client     *http.Client
	transport  *http.Transport
	mu         sync.Mutex
	calls      []serviceLifecycleHTTPCall
}

func serviceLifecycleSocketpair() (*os.File, *os.File, error) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(pair[0]), "qualification-parent"), os.NewFile(uintptr(pair[1]), "qualification-node"), nil
}
func newServiceLifecycleHTTPClient(file *os.File) (*serviceLifecycleHTTPClient, error) {
	connection, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return nil, err
	}
	var mu sync.Mutex
	used := false
	transport := &http.Transport{MaxConnsPerHost: 1, MaxIdleConnsPerHost: 1, DialContext: func(context.Context, string, string) (net.Conn, error) {
		mu.Lock()
		defer mu.Unlock()
		if used {
			return nil, errors.New("the private fixture connection cannot reconnect")
		}
		used = true
		return connection, nil
	}}
	return &serviceLifecycleHTTPClient{client: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("fixture redirects are unavailable") }}, transport: transport, connection: connection}, nil
}
func (c *serviceLifecycleHTTPClient) close() {
	c.transport.CloseIdleConnections()
	_ = c.connection.Close()
}
func (c *serviceLifecycleHTTPClient) request(ctx context.Context, method, path string, body any, out any) error {
	if path != "/fixture/prepare" && path != "/fixture/start" && path != "/fixture/status" && path != "/fixture/stop" {
		return errors.New("the private fixture command path differs")
	}
	var raw []byte
	if body != nil {
		raw = serviceJSON(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://qualification-fixture"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, (8<<20)+1))
	if err != nil || len(data) > 8<<20 {
		return errors.New("the private fixture response exceeds its bound")
	}
	c.mu.Lock()
	c.calls = append(c.calls, serviceLifecycleHTTPCall{Method: method, Path: path, Request: raw, Status: response.StatusCode, Response: data, MonoNS: serviceMono()})
	c.mu.Unlock()
	if response.StatusCode != 200 {
		return errors.New("the private fixture command rejected: " + string(data))
	}
	if out == nil {
		return nil
	}
	return lifecycle.DecodeTransport(bytes.NewReader(data), out)
}

type serviceLifecycleListener struct {
	connection net.Conn
	once       sync.Once
	closeOnce  sync.Once
	closed     chan struct{}
}

func (l *serviceLifecycleListener) Accept() (net.Conn, error) {
	var connection net.Conn
	l.once.Do(func() { connection = l.connection })
	if connection != nil {
		return connection, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *serviceLifecycleListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed); _ = l.connection.Close() })
	return nil
}

func (l *serviceLifecycleListener) Addr() net.Addr { return l.connection.LocalAddr() }

type serviceLifecycleAuthorityHTTP struct {
	server   *http.Server
	listener *serviceLifecycleListener
	done     chan error
}

func serveServiceLifecycleAuthority(file *os.File, authority *serviceLifecycleAuthority) (*serviceLifecycleAuthorityHTTP, error) {
	connection, err := net.FileConn(file)
	file.Close()
	if err != nil {
		return nil, err
	}
	listener := &serviceLifecycleListener{connection: connection, closed: make(chan struct{})}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serviceLifecycleAuthorityRequest(w, r, authority) }), ReadHeaderTimeout: 30 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16384}
	service := &serviceLifecycleAuthorityHTTP{server: server, listener: listener, done: make(chan error, 1)}
	go func() { service.done <- server.Serve(listener) }()
	return service, nil
}
func (s *serviceLifecycleAuthorityHTTP) close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := s.server.Shutdown(ctx)
	if err != nil {
		_ = s.server.Close()
	}
	serveErr := <-s.done
	if errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, net.ErrClosed) {
		serveErr = nil
	}
	return errors.Join(err, serveErr)
}
func serviceLifecycleAuthorityRequest(w http.ResponseWriter, r *http.Request, authority *serviceLifecycleAuthority) {
	reject := func(code int) { http.Error(w, "qualification_authority_rejected", code) }
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.Fragment != "" {
		reject(400)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, jobauthority.MaxAuditBytes+1))
	if err != nil || len(raw) > jobauthority.MaxAuditBytes {
		reject(413)
		return
	}
	var response any
	switch r.URL.Path {
	case "/fixture/state":
		var request noderuntime.QualificationStateRequest
		if len(raw) > 32768 || lifecycle.DecodeTransport(bytes.NewReader(raw), &request) != nil || request.Protocol != noderuntime.QualificationStateProtocol {
			reject(422)
			return
		}
		state, e := authority.state(r.Context(), request.GrantID)
		if e != nil {
			reject(503)
			return
		}
		response = noderuntime.QualificationStateResponse{Protocol: noderuntime.QualificationStateProtocol, GrantID: state.GrantID, Known: state.Known, Revoked: state.Revoked}
	case "/fixture/receipt":
		bundle, e := jobauthority.DecodeAuditBundle(raw)
		if e != nil {
			reject(422)
			return
		}
		receipt, e := authority.countersign(r.Context(), bundle)
		if e != nil {
			reject(403)
			return
		}
		response = receipt
	default:
		reject(404)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(response)
}

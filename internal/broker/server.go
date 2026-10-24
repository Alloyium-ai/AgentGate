// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Package broker is the AgentGate credential broker: a per-launch host-side
// HTTP service that holds a secret outside the sandbox, forwards only allowed
// requests to an exact HTTPS upstream allowlist, injects the credential, and
// records bounded evidence. The sandbox reaches one exact endpoint and never
// receives the secret. See docs/BROKER.md.
package broker

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Overrides are test seams. The agentgate-broker command never sets them, and
// each one replaces a production safeguard only inside tests.
type Overrides struct {
	// Listener replaces binding (and the interface check of) the configured
	// endpoint. Connections are still limited and inspected.
	Listener net.Listener
	// Resolver replaces the system resolver.
	Resolver Resolver
	// Dial replaces the socket dialer after address validation.
	Dial DialFunc
	// RootCAs replaces the system trust roots.
	RootCAs *x509.CertPool
	// Interfaces replaces interface enumeration for the listen check.
	Interfaces InterfaceAddrs
	// LocalAddrs replaces the host address list the SSRF guard refuses.
	LocalAddrs func() ([]net.Addr, error)
	// Now replaces the clock for config validation.
	Now func() time.Time
}

// Server is one broker instance for one launch.
type Server struct {
	cfg       *Config
	set       Settings
	digest    string
	deadline  time.Time
	authority string
	routes    map[string]*route
	stats     *statsCollector
	bucket    *tokenBucket
	inflight  chan struct{}
	ov        Overrides
	log       io.Writer

	listener net.Listener
	srv      *http.Server
	baseCtx  context.Context
	cancel   context.CancelFunc
	handlers sync.WaitGroup
	closing  atomic.Bool
	once     sync.Once
}

// Stop reasons recorded in the stats document.
const (
	StopDeadline = "deadline"
	StopSignal   = "signal"
	StopError    = "error"
)

// New validates cfg and loads every route's secret. It must run before the
// process drops privileges, because the secret files are root-owned. digest
// is the SHA-256 of the exact configuration bytes. log receives fixed event
// codes only.
func New(cfg *Config, digest string, log io.Writer, ov Overrides) (*Server, error) {
	now := time.Now
	if ov.Now != nil {
		now = ov.Now
	}
	set, err := cfg.Validate(now())
	if err != nil {
		return nil, err
	}
	deadline, _ := cfg.DeadlineTime()
	if log == nil {
		log = io.Discard
	}
	s := &Server{cfg: cfg, set: set, digest: digest, deadline: deadline, authority: cfg.Listen.ListenAuthority(),
		routes: map[string]*route{}, inflight: make(chan struct{}, set.MaxConcurrentRequests), ov: ov, log: log}
	s.stats = newStatsCollector(cfg, digest, set.MaxDenialRecords, time.Now)
	s.bucket = newTokenBucket(set.RequestsPerMinute, set.Burst, time.Now)
	var resolver Resolver = net.DefaultResolver
	if ov.Resolver != nil {
		resolver = ov.Resolver
	}
	subnet := cfg.Listen.Subnet
	denied := localDenied(subnet, ov.LocalAddrs)
	for _, rc := range cfg.Routes {
		var src secretSource
		if rc.Credential.SecretFile != "" {
			src = fileSource(rc.Credential.SecretFile)
		} else {
			src = fdSource(*rc.Credential.SecretFD)
		}
		cred, err := loadCredential(rc.Name, rc.Credential, src)
		if err != nil {
			s.destroy()
			return nil, err
		}
		g := &addressGuard{host: rc.Upstream.Host, port: uint16(rc.Upstream.Port), resolver: resolver, ttl: set.DNSCache,
			denied: denied, now: time.Now}
		if len(rc.Upstream.PrivateAddresses) > 0 {
			g.exact = map[netip.Addr]bool{}
			for _, a := range rc.Upstream.PrivateAddresses {
				g.exact[netip.MustParseAddr(a)] = true
			}
		}
		g.dial = systemDial(set.ConnectTimeout, g.check)
		if ov.Dial != nil {
			g.dial = ov.Dial
		}
		s.routes[rc.Name] = &route{name: rc.Name, upstream: rc.Upstream, rules: rc.Rules, cred: cred, guard: g,
			transport: newTransport(rc.Upstream, g, set, ov.RootCAs)}
	}
	return s, nil
}

// BaseURL is the URL an agent uses for one route, e.g. for ANTHROPIC_BASE_URL.
func BaseURL(cfg *Config, routeName string) string {
	return "http://" + cfg.Listen.ListenAuthority() + "/" + routeName
}

// RouteNames lists the configured routes in order.
func (s *Server) RouteNames() []string {
	names := make([]string, 0, len(s.routes))
	for n := range s.routes {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// MemoryLocked reports whether every secret arena is locked against swap.
func (s *Server) MemoryLocked() bool {
	for _, r := range s.routes {
		if !r.cred.memoryLocks {
			return false
		}
	}
	return len(s.routes) > 0
}

// Listen binds the configured endpoint. For tcp it first proves the address is
// the launch's broker address: exactly one up, non-loopback interface holds it
// with the configured subnet. It binds that exact address, never a wildcard.
func (s *Server) Listen() error {
	var ln net.Listener
	switch {
	case s.ov.Listener != nil:
		ln = s.ov.Listener
	case s.cfg.Listen.Network == "tcp":
		list := s.ov.Interfaces
		if list == nil {
			list = systemInterfaces
		}
		if err := checkListenInterface(s.cfg.Listen, list); err != nil {
			return err
		}
		var err error
		if ln, err = listenTCP(s.cfg.Listen); err != nil {
			return err
		}
	default:
		var err error
		if ln, err = listenUnix(s.cfg.Listen); err != nil {
			return err
		}
	}
	s.listener = &limitListener{Listener: ln, slots: make(chan struct{}, s.set.MaxConnections),
		maxHeaderBytes: s.set.MaxHeaderBytes, maxHeaderCount: s.set.MaxHeaderCount, onAccept: s.stats.connection}
	return nil
}

func (s *Server) logf(code string) { fmt.Fprintf(s.log, "agentgate-broker: %s\n", code) }

// Serve runs until the deadline, until ctx is cancelled (a stop signal), or
// until the server fails. It always writes final stats and wipes the secrets.
// The returned reason is one of StopDeadline, StopSignal or StopError.
func (s *Server) Serve(ctx context.Context, h Hardening) (string, error) {
	if s.listener == nil {
		s.destroy()
		return StopError, errors.New("broker is not listening")
	}
	h.MemoryLocked = s.MemoryLocked()
	s.stats.setHardening(h)
	s.baseCtx, s.cancel = context.WithDeadline(context.Background(), s.deadline)
	defer s.cancel()
	s.srv = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: s.set.HeaderTimeout,
		MaxHeaderBytes:    s.set.MaxHeaderBytes,
		ErrorLog:          log.New(io.Discard, "", 0),
		BaseContext:       func(net.Listener) context.Context { return s.baseCtx },
		ConnContext:       func(ctx context.Context, c net.Conn) context.Context { return context.WithValue(ctx, connKey{}, c) },
		// Let the handler refuse "OPTIONS *" instead of net/http answering it.
		DisableGeneralOptionsHandler: true,
	}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	s.srv.Protocols = &protocols
	// One request per connection: no pipelining, no reuse of a connection
	// whose framing the broker would have to trust across requests.
	s.srv.SetKeepAlivesEnabled(false)

	serveErr := make(chan error, 1)
	go func() { serveErr <- s.srv.Serve(s.listener) }()
	s.stats.setState("running", "", false)
	statsErr := s.writeStats()
	s.logf("running routes=" + fmt.Sprint(len(s.routes)))

	ticker := time.NewTicker(s.set.StatsInterval)
	defer ticker.Stop()
	deadline := time.NewTimer(time.Until(s.deadline))
	defer deadline.Stop()
	reason := ""
	var failure error
	for reason == "" {
		select {
		case <-ticker.C:
			if err := s.writeStats(); err != nil {
				statsErr = err
			}
		case <-deadline.C:
			reason = StopDeadline
		case <-ctx.Done():
			reason = StopSignal
		case err := <-serveErr:
			reason, failure = StopError, err
		}
	}
	complete := s.shutdown(reason)
	s.stats.setState("stopped", reason, complete && failure == nil)
	if err := s.writeStats(); err != nil {
		statsErr = err
	}
	s.destroy()
	s.logf("stopped reason=" + reason)
	if failure == nil && statsErr != nil {
		failure = statsErr
	}
	if reason == StopError && failure == nil {
		failure = errors.New("broker server stopped unexpectedly")
	}
	return reason, failure
}

// shutdown stops accepting, gives in-flight requests a grace period on a
// signal (never past the deadline), then cancels everything. At the deadline
// it cancels at once. It reports whether every handler returned.
func (s *Server) shutdown(reason string) bool {
	s.closing.Store(true)
	if reason == StopSignal && s.set.ShutdownGrace > 0 {
		grace, cancel := context.WithTimeout(s.baseCtx, s.set.ShutdownGrace)
		_ = s.srv.Shutdown(grace)
		cancel()
	}
	s.cancel()
	_ = s.srv.Close()
	for _, r := range s.routes {
		r.transport.CloseIdleConnections()
	}
	done := make(chan struct{})
	go func() { s.handlers.Wait(); close(done) }()
	select {
	case <-done:
		return true
	case <-time.After(2 * time.Second):
		return false
	}
}

func (s *Server) writeStats() error {
	data, err := s.stats.snapshot()
	if err != nil {
		return err
	}
	return writeStatsFile(s.cfg.StatsPath, data)
}

// Snapshot returns the current stats document.
func (s *Server) Snapshot() ([]byte, error) { return s.stats.snapshot() }

// destroy wipes every secret arena. The mappings stay mapped (zeroed) until
// the process exits, so no late reference can fault.
func (s *Server) destroy() {
	s.once.Do(func() {
		for _, r := range s.routes {
			r.cred.destroy()
		}
	})
}

// Close releases the secrets of a server that never served.
func (s *Server) Close() {
	if s.listener != nil && s.srv == nil {
		s.listener.Close()
	}
	s.destroy()
}

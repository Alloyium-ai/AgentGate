// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"alloyium.local/kernel-poc/internal/policy"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Server struct {
	Store                    *Store
	Auth                     *Auth
	Spool, Web, FixtureLabel string
	// TrustedProxies are the networks of the reverse proxies in front of the
	// service (settings trusted_proxies). A request whose peer is one of
	// them is keyed by the client address it forwarded in X-Forwarded-For;
	// every other request by its peer. Empty trusts no proxy.
	TrustedProxies []netip.Prefix
	mu             sync.Mutex
	clients        map[chan int64]bool
	// limits holds one bounded rate table per client-keyed family
	// (ratelimit.go); hostLimits the buckets of authenticated host requests,
	// apart from them, so no flood of other keys can crowd them out.
	limits     map[string]*rateTable
	hostLimits *rateTable
	inflight   chan struct{}
	// StreamWriteTimeout, StreamHeartbeat and StreamLifetime bound the launch
	// log stream; zero means the defaults (20 s, 15 s and 5 minutes).
	StreamWriteTimeout, StreamHeartbeat, StreamLifetime time.Duration
	// logLinesFetched and logLinesDelivered count log stream lines read from
	// the store and written to clients.
	logLinesFetched, logLinesDelivered atomic.Int64
}
type call struct {
	Actor     Actor
	Operation Operation
	Body      []byte
}

var safeMeta = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,100}$`)

func NewServer(s *Store, a *Auth, spool, web string) *Server {
	app := &Server{Store: s, Auth: a, Spool: spool, Web: web, clients: map[chan int64]bool{}, limits: map[string]*rateTable{}, hostLimits: newRateTable(hostTableSize), inflight: make(chan struct{}, 32)}
	s.Changed = app.changed
	return app
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /api/v1/machine-challenge", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]string{"audience": strings.TrimRight(s.Auth.Config.PublicURL, "/"), "epoch": s.Auth.Epoch})
	})
	mux.HandleFunc("GET /auth/login", s.authRoute("login"))
	mux.HandleFunc("GET /auth/callback", s.authRoute("callback"))
	mux.HandleFunc("POST /auth/logout", s.authRoute("logout"))
	mux.HandleFunc("GET /auth/options", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, 200, map[string]bool{"local": s.Auth.LocalEnabled(), "oidc": s.Auth.Verifier != nil, "community": s.Auth.Config.Instance != ""})
	})
	mux.HandleFunc("GET /auth/local/challenge", s.authRoute("local-challenge"))
	mux.HandleFunc("POST /auth/local/login", s.authRoute("local-login"))
	for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		mux.HandleFunc(method+" /api/v1/", s.api)
	}
	mux.HandleFunc("POST /api/v1/hostd/", s.hostd)
	mux.HandleFunc("GET /", s.static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !safeMeta.MatchString(id) {
			id = newID()
		}
		r.Header.Set("X-Request-ID", id)
		w.Header().Set("X-Request-ID", id)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		if s.Store.CheckConfiguration != nil {
			if err := s.Store.CheckConfiguration(); err != nil {
				op := Operation{Actor: Actor{Subject: "unknown", Kind: "unknown"}, Action: "configuration.denied", Resource: "deployment", Reason: "Current signed authority unavailable", RequestID: id}
				s.problem(w, r, err, op, r.Method != "GET")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(value)
}
func (s *Server) problem(w http.ResponseWriter, r *http.Request, err error, op Operation, auditDenied bool) {
	if auditDenied {
		if e := s.Store.Denied(op, err); e != nil {
			err = e
		}
	}
	status, code, message := errorResult(err)
	jsonResponse(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}, "request_id": r.Header.Get("X-Request-ID")})
}
func (s *Server) authRoute(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		select {
		case s.inflight <- struct{}{}:
			defer func() { <-s.inflight }()
		default:
			s.problem(w, r, fail(503, "request_capacity", "The sign-in capacity is full."), Operation{}, false)
			return
		}
		host, ferr := s.clientIP(r)
		if ferr != nil {
			s.problem(w, r, ferr, Operation{Actor: Actor{Subject: "anonymous", Kind: "unknown"}, Action: "auth.denied", Resource: "session", Reason: "Malformed forwarding header", RequestID: r.Header.Get("X-Request-ID"), Source: host}, true)
			return
		}
		if s.limited("auth", host) {
			s.problem(w, r, fail(429, "rate_limited", "The sign-in request rate exceeds its limit."), Operation{Actor: Actor{Subject: "anonymous", Kind: "unknown"}, Action: "auth.denied", Resource: "session", Reason: "Sign-in rate limit", RequestID: r.Header.Get("X-Request-ID"), Source: host}, true)
			return
		}
		switch name {
		case "local-challenge":
			err = s.Auth.LocalChallenge(w, r)
		case "local-login":
			if s.limited("password", host) {
				err = fail(429, "rate_limited", "The local sign-in rate exceeds its limit.")
			} else {
				err = s.Auth.LocalLogin(w, r)
			}
		case "login":
			err = s.Auth.Login(w, r)
		case "callback":
			err = s.Auth.Callback(w, r)
		case "logout":
			err = s.Auth.Logout(w, r)
			if err == nil {
				jsonResponse(w, 200, map[string]string{"result": "signed out"})
			}
		}
		if err != nil {
			op := Operation{Actor: Actor{Subject: "anonymous", Kind: "unknown"}, Action: "auth.denied", Resource: "session", Reason: "SSO or session request denied", RequestID: r.Header.Get("X-Request-ID"), Source: host}
			var denied *callbackDenial
			if name == "callback" && errors.As(err, &denied) {
				op.Actor = denied.Actor
			}
			if strings.HasPrefix(name, "local-") {
				s.problem(w, r, err, op, true)
			} else if name != "logout" {
				if e := s.Store.Denied(op, err); e != nil {
					err = e
				}
				_, code, _ := errorResult(err)
				http.Redirect(w, r, "/?signin_error="+code, http.StatusSeeOther)
			} else {
				s.problem(w, r, err, op, true)
			}
		}
	}
}

// clientIP is the address a request is limited and its anonymous denials
// sampled by. Without a trusted proxy it is the TCP peer. When the peer is
// a trusted proxy, it is the rightmost X-Forwarded-For entry that is not
// itself a trusted proxy: the proxies append the address they received from,
// so entries to its left are whatever the client chose to send. A trusted
// proxy that sends no X-Forwarded-For, or a malformed one, is refused. An
// IPv6 client is keyed by its /56 (ratelimit.go). The peer is returned with
// an error.
func (s *Server) clientIP(r *http.Request) (string, error) {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host, nil
	}
	peer = peer.Unmap()
	if !s.trusted(peer) {
		return clientKey(peer), nil
	}
	values := r.Header.Values("X-Forwarded-For")
	entries := []string{}
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			entries = append(entries, strings.TrimSpace(part))
		}
	}
	if len(entries) == 0 || len(entries) > 16 {
		return clientKey(peer), fail(400, "invalid_forwarded_for", "A request through a trusted proxy needs one X-Forwarded-For list of at most 16 addresses.")
	}
	addrs := make([]netip.Addr, len(entries))
	for i, e := range entries {
		a, err := netip.ParseAddr(e)
		if err != nil || a.Zone() != "" {
			return clientKey(peer), fail(400, "invalid_forwarded_for", "X-Forwarded-For holds an entry that is not an IP address.")
		}
		addrs[i] = a.Unmap()
	}
	for i := len(addrs) - 1; i >= 0; i-- {
		if !s.trusted(addrs[i]) {
			return clientKey(addrs[i]), nil
		}
	}
	return clientKey(addrs[0]), nil
}

func (s *Server) trusted(a netip.Addr) bool {
	for _, p := range s.TrustedProxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func clientKey(a netip.Addr) string {
	if a.Is6() {
		p, _ := a.Prefix(56)
		return p.String()
	}
	return a.String()
}

// ParseTrustedProxies reads the trusted_proxies setting: at most 16
// canonical CIDR networks.
func ParseTrustedProxies(values []string) ([]netip.Prefix, error) {
	if len(values) > 16 {
		return nil, errors.New("trusted_proxies holds at most 16 networks")
	}
	out := []netip.Prefix{}
	for _, v := range values {
		p, err := netip.ParsePrefix(v)
		if err != nil || p.Masked() != p || p.String() != v {
			return nil, errors.New("trusted_proxies entries are canonical CIDR networks such as 10.231.207.2/32")
		}
		out = append(out, p)
	}
	return out, nil
}
func (s *Server) prepare(r *http.Request) (call, error) {
	var c call
	c.Operation = Operation{Actor: Actor{Subject: "anonymous", Kind: "unknown"}, Action: "api.denied", Resource: "api", Reason: "API authorization or validation denied", RequestID: r.Header.Get("X-Request-ID")}
	host, err := s.clientIP(r)
	c.Operation.Source = host
	if err != nil {
		return c, err
	}
	if s.limited("ip", host) {
		return c, fail(429, "rate_limited", "The request rate exceeds this node's limit.")
	}
	if r.Method != "GET" {
		var err error
		c.Body, err = io.ReadAll(io.LimitReader(r.Body, (4<<20)+1))
		if err != nil || len(c.Body) > 4<<20 {
			return c, fail(413, "body_too_large", "The request exceeds the four MiB limit.")
		}

	}
	var nonce string
	if strings.HasPrefix(r.Header.Get("Authorization"), "Alloyium-Proof ") {
		c.Actor, nonce, err = s.Auth.Machine(r, c.Body)
	} else if _, ok := bearerToken(r); ok {
		c.Actor, c.Operation.TokenHash, err = s.Auth.Token(r)
		if err == nil && !tokenAllowed[apiArea(r.URL.Path)] {
			err = fail(403, "token_scope", "API tokens cannot call this endpoint. Use a browser session.")
		}
	} else {
		var session Session
		session, err = s.Auth.Session(r)
		c.Actor = session.Actor
		c.Operation.SessionHash = session.Binding
		if err == nil && r.Method != "GET" {
			err = s.Auth.CSRF(r, session)
		}
	}
	c.Operation.ProofNonce = nonce
	c.Operation.Actor = c.Actor
	if c.Actor.Subject == "" {
		c.Operation.Actor = Actor{Subject: "anonymous", Kind: "unknown"}
	}
	if err != nil {
		return c, err
	}
	if r.Method != "GET" && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return c, fail(415, "json_required", "Use an application/json request.")
	}
	if s.limited("actor", c.Actor.Subject) {
		return c, fail(429, "rate_limited", "The actor request rate exceeds its limit.")
	}
	key := r.Header.Get("Idempotency-Key")
	if key != "" && !safeMeta.MatchString(key) {
		return c, fail(422, "invalid_idempotency_key", "Use a short stable idempotency key.")
	}
	corr := r.Header.Get("X-Correlation-ID")
	if !safeMeta.MatchString(corr) {
		corr = r.Header.Get("X-Request-ID")
	}
	c.Operation.CorrelationID = corr
	c.Operation.Idempotency = key
	c.Operation.BodyDigest = digest(append([]byte(r.Method+" "+r.URL.RequestURI()+"\n"), c.Body...))
	c.Operation.ProofNonce = nonce
	return c, nil
}
func decodeBody(data []byte, dst any) error {
	if err := validateRequiredBody(data, dst); err != nil {
		return err
	}
	return decodeBodyUnchecked(data, dst)
}
func decodeBodyUnchecked(data []byte, dst any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return fail(422, "invalid_json", "The request fields or types do not match the API contract.")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return fail(422, "invalid_json", "Supply one JSON object.")
	}
	return nil
}
func requireIdempotency(c call) error {
	if c.Operation.Idempotency == "" {
		return fail(428, "idempotency_required", "Supply an Idempotency-Key for this operation.")
	}
	return nil
}
func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	if (r.Method != "GET" || strings.TrimSuffix(r.URL.Path, "/") != "/api/v1/events") && !isLaunchStream(r) {
		select {
		case s.inflight <- struct{}{}:
			defer func() { <-s.inflight }()
		default:
			s.problem(w, r, fail(503, "request_capacity", "The request capacity is full. Retry after active requests finish."), Operation{Actor: Actor{Subject: "anonymous", Kind: "unknown"}, Action: "api.denied", Resource: "api", Reason: "Bounded request capacity", RequestID: r.Header.Get("X-Request-ID")}, true)
			return
		}
	}
	c, err := s.prepare(r)
	if err != nil {
		s.problem(w, r, err, c.Operation, true)
		return
	}
	if r.Method != "GET" && s.provisioning(w, r, c) {
		return
	}
	if r.Method == "GET" {
		if c.Operation.ProofNonce != "" {
			actor, e := s.Store.UseReadProof(c.Operation)
			if e != nil {
				s.problem(w, r, e, c.Operation, false)
				return
			}
			c.Actor = actor
		}
		if s.provisioning(w, r, c) {
			return
		}
		value, status, e := s.read(w, r, c.Actor)
		if e != nil {
			s.problem(w, r, e, c.Operation, true)
		} else if status != 0 {
			jsonResponse(w, status, value)
		}
		return
	}
	value, err := s.write(r, c)
	if err != nil {
		s.problem(w, r, err, c.Operation, false)
		return
	}
	jsonResponse(w, 200, value)
}
func (s *Server) read(w http.ResponseWriter, r *http.Request, a Actor) (any, int, error) {
	f, err := ParseFilter(r.URL.Query())
	if err != nil {
		return nil, 0, err
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	tail := parts[2:]
	if len(tail) == 0 {
		return nil, 0, fail(404, "not_found", "The endpoint does not exist.")
	}
	name := tail[0]
	valid := len(tail) == 1 && name != "versions"
	if len(tail) == 2 {
		valid = name == "target-reports" || name == "policy-documents" || name == "policies" || name == "versions" || name == "requests" || name == "admissions" || name == "runs" || (name == "audit" && tail[1] == "export")
	}
	if len(tail) == 3 {
		valid = (name == "policies" && tail[2] == "versions") || (name == "runs" && tail[2] == "verification")
	}
	if !valid {
		return nil, 0, fail(404, "not_found", "The API endpoint does not exist.")
	}
	scope := map[string]string{"users": "users:write", "overview": "policy:read", "session": "policy:read", "policies": "policy:read", "versions": "policy:read", "requests": "request:read", "runs": "run:read", "audit": "audit:read", "agents": "agents:read", "admissions": "admission:read", "trust": "policy:read", "policy-schema": "policy:read", "policy-documents": "policy:read", "target-reports": "target:read", "openapi.json": "policy:read", "events": "policy:read"}[name]
	if scope == "" {
		return nil, 0, fail(404, "not_found", "The API endpoint does not exist.")
	}
	if err = require(a, scope, false); err != nil {
		return nil, 0, err
	}
	switch name {
	case "target-reports":
		if len(tail) != 2 {
			return nil, 0, fail(404, "not_found", "Choose an exact target report digest.")
		}
		value, err := s.Store.TargetReport(tail[1], a)
		return value, 200, err
	case "policy-documents":
		if len(tail) != 2 {
			return nil, 0, fail(404, "not_found", "Choose an immutable policy document version.")
		}
		value, err := s.Store.PolicyDocument(tail[1])
		return value, 200, err
	case "users":
		if !s.Store.LocalIdentity || a.Kind != "human" || !strings.HasPrefix(a.Subject, "local:") {
			return nil, 0, fail(403, "forbidden", "Local user administration requires a human administrator.")
		}
		v, e := s.Store.Users()
		return map[string]any{"items": v}, 200, e
	case "session":
		session, e := s.Auth.Session(r)
		return map[string]any{"actor": session.Actor, "csrf_token": session.CSRF, "expires": session.Expires, "fixture_label": s.FixtureLabel, "local_identity": s.Store.LocalIdentity && strings.HasPrefix(session.Actor.Subject, "local:"), "customer_policy": s.Store.CustomerPolicy}, 200, e
	case "overview":
		v, e := s.Store.Overview()
		if v != nil {
			v["fixture_label"] = s.FixtureLabel
		}
		return v, 200, e
	case "policies":
		if len(tail) == 1 {
			v, e := s.Store.Policies(f)
			return v, 200, e
		}
		if len(tail) == 3 && tail[2] == "versions" {
			v, e := s.Store.Versions(tail[1], f)
			return v, 200, e
		}
		var p Policy
		e := s.Store.DB.QueryRow("SELECT * FROM policies WHERE id=?", tail[1]).Scan(&p.ID, &p.Name, &p.Description, &p.Created)
		return p, 200, notFound(e)
	case "versions":
		if len(tail) != 2 {
			return nil, 0, fail(404, "not_found", "Choose a policy version.")
		}
		v, e := versionFrom(s.Store.DB, tail[1])
		if e == nil {
			w.Header().Set("ETag", etag(v.Revision))
		}
		return v, 200, e
	case "requests":
		if len(tail) == 1 {
			v, e := s.Store.Requests(f, a)
			return v, 200, e
		}
		q, e := scanRequest(s.Store.DB.QueryRow("SELECT * FROM requests WHERE id=?", tail[1]))
		if e == nil && a.Kind == "agent" && q.AgentID != a.Subject {
			return nil, 0, fail(403, "forbidden", "The request belongs to another agent.")
		}
		if e == nil {
			w.Header().Set("ETag", etag(q.Revision))
		}
		return q, 200, e
	case "runs":
		if len(tail) == 1 {
			v, e := s.Store.Runs(f, a)
			return v, 200, e
		}
		if len(tail) == 3 && tail[2] == "verification" {
			v, e := s.Store.VerifyRun(tail[1], a, s.Spool)
			return v, 200, e
		}
		v, e := s.Store.RunDetail(tail[1], a)
		return v, 200, e
	case "audit":
		if len(tail) == 2 && tail[1] == "export" {
			if e := require(a, "audit:export", false); e != nil {
				return nil, 0, e
			}
			v, e := s.Store.Audit(f)
			if e != nil {
				return nil, 0, e
			}
			w.Header().Set("Content-Type", "application/x-ndjson")
			if v.Next != "" {
				w.Header().Set("X-Next-Cursor", v.Next)
			}
			w.Header().Set("Content-Disposition", "attachment; filename=alloyium-audit.jsonl")
			for _, entry := range v.Items {
				json.NewEncoder(w).Encode(entry)
			}
			return nil, 0, nil
		}
		v, e := s.Store.Audit(f)
		return v, 200, e
	case "admissions":
		if len(tail) == 1 {
			v, e := s.Store.Admissions(f, a)
			return v, 200, e
		}
		v, e := s.Store.AdmissionDetail(tail[1], a)
		return v, 200, e
	case "agents":
		v, e := s.Store.Services(f)
		return v, 200, e
	case "trust":
		return map[string]string{"authority": b64.EncodeToString(s.Store.Authority.Public().(ed25519.PublicKey))}, 200, nil
	case "openapi.json":
		if s.Store.CustomerPolicy {
			value, err := CommunityOpenAPI()
			return value, 200, err
		}
		return OpenAPI(), 200, nil
	case "policy-schema":
		if !s.Store.CustomerPolicy {
			return nil, 0, fail(404, "not_found", "The versioned Community policy schema is unavailable in fixture mode.")
		}
		value, err := policy.APIContract()
		return value, 200, err
	case "events":
		s.events(w, r, a)
		return nil, 0, nil
	}
	return nil, 0, fail(404, "not_found", "The endpoint does not exist.")
}
func (s *Server) write(r *http.Request, c call) (any, error) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	tail := parts[2:]
	if r.Method != "POST" {
		err := fail(405, "method_not_allowed", "Create a version or decision instead of editing history.")
		if e := s.Store.Denied(c.Operation, err); e != nil {
			return nil, e
		}
		return nil, err
	}
	var value any
	var err error
	op := c.Operation
	handled := false
	switch {
	case len(tail) == 1 && tail[0] == "target-challenges" && s.Store.CustomerPolicy:
		var in TargetChallengeInput
		err = decodeTargetBody(c.Body, &in)
		if err == nil {
			handled = true
			value, err = s.Store.CreateTargetChallenge(op, in)
		}
	case len(tail) == 1 && tail[0] == "target-reports" && s.Store.CustomerPolicy:
		var in TargetReportInput
		err = decodeTargetBody(c.Body, &in)
		if err == nil {
			handled = true
			value, err = s.Store.PutTargetReport(op, in)
		}
	case len(tail) == 1 && tail[0] == "policy-documents" && s.Store.CustomerPolicy:
		var in CreatePolicyDocument
		err = decodePolicyDocument(c.Body, &in)
		if err == nil {
			handled = true
			value, err = s.Store.CreatePolicyDocument(op, in)
		}
	case len(tail) == 1 && tail[0] == "policy-preview" && s.Store.CustomerPolicy:
		var in PolicyPreviewInput
		err = decodeTargetBody(c.Body, &in)
		if err == nil {
			handled = true
			value, err = s.Store.PreviewPolicyDocument(op, in)
		}
	case len(tail) == 1 && tail[0] == "policy-validate" && s.Store.CustomerPolicy:
		var in PolicyValidateInput
		err = decodePolicyValidate(c.Body, &in)
		if err == nil {
			handled = true
			value, err = s.Store.ValidatePolicyDocument(op, in)
		}
	case len(tail) == 1 && tail[0] == "users":
		var in UserInput
		err = decodeBody(c.Body, &in)
		if err == nil {
			handled = true
			value, err = s.Store.PutUser(op, in)
		}
	case len(tail) == 1 && tail[0] == "policies":
		var in CreatePolicy
		if s.Store.CustomerPolicy {
			err = decodeCustomerBody(c.Body, &in)
		} else {
			err = decodeBody(c.Body, &in)
		}
		if err == nil {
			handled = true
			value, err = s.Store.CreatePolicy(op, in)
		}
	case len(tail) == 3 && tail[0] == "policies" && tail[2] == "versions":
		var in EditVersion
		if s.Store.CustomerPolicy {
			err = decodeCustomerBody(c.Body, &in)
		} else {
			err = decodeBody(c.Body, &in)
		}
		if err == nil {
			handled = true
			value, err = s.Store.EditVersion(op, tail[1], in)
		}
	case len(tail) == 3 && tail[0] == "versions" && tail[2] == "transition":
		var in Decision
		err = decodeBody(c.Body, &in)
		if err == nil {
			err = requireIdempotency(c)
		}
		if err == nil {
			handled = true
			value, err = s.Store.Transition(op, tail[1], r.Header.Get("If-Match"), in)
		}
	case len(tail) == 1 && tail[0] == "requests":
		var in RequestPolicy
		err = decodeBody(c.Body, &in)
		if err == nil {
			handled = true
			value, err = s.Store.RequestPolicy(op, in)
		}
	case len(tail) == 3 && tail[0] == "requests" && tail[2] == "decision":
		var in Decision
		err = decodeBody(c.Body, &in)
		if err == nil {
			err = requireIdempotency(c)
		}
		if err == nil {
			handled = true
			value, err = s.Store.DecideRequest(op, tail[1], r.Header.Get("If-Match"), in)
		}
	case len(tail) == 1 && tail[0] == "admissions":
		if s.Store.CustomerPolicy {
			var in WorkloadAdmission
			err = decodeCustomerBody(c.Body, &in)
			if err == nil {
				err = requireIdempotency(c)
			}
			if err == nil {
				handled = true
				value, err = s.Store.AdmitWorkload(op, in)
			}
			break
		}
		var in AdmitInput
		err = decodeBody(c.Body, &in)
		if err == nil {
			err = requireIdempotency(c)
		}
		if err == nil {
			handled = true
			value, err = s.Store.Admit(op, in)
		}
	case len(tail) == 3 && tail[0] == "admissions" && tail[2] == "activate":
		var in ActivateInput
		err = decodeBody(c.Body, &in)
		if err == nil {
			err = requireIdempotency(c)
		}
		if err == nil {
			handled = true
			value, err = s.Store.Activate(op, tail[1], in)
		}
	case len(tail) == 3 && tail[0] == "admissions" && (tail[2] == "release" || tail[2] == "revoke"):
		var in Decision
		err = decodeBody(c.Body, &in)
		if err == nil {
			err = requireIdempotency(c)
		}
		if err == nil && ((tail[2] == "release" && in.State != "released") || (tail[2] == "revoke" && in.State != "revoked")) {
			err = fail(422, "invalid_state", "The admission state must match the requested operation.")
		}
		if err == nil {
			handled = true
			value, err = s.Store.Release(op, tail[1], in)
		}
	case len(tail) == 2 && tail[0] == "evidence" && tail[1] == "receipt":
		var in IngestInput
		err = decodeBody(c.Body, &in)
		if err == nil {
			err = requireIdempotency(c)
		}
		if err == nil {
			handled = true
			value, err = s.Store.Receipt(op, in, s.Spool)
		}
	case len(tail) == 1 && tail[0] == "evidence":
		var in IngestInput
		err = decodeBody(c.Body, &in)
		if err == nil {
			err = requireIdempotency(c)
		}
		if err == nil {
			handled = true
			value, err = s.Store.Ingest(op, in, s.Spool)
		}
	case len(tail) == 3 && tail[0] == "agents" && tail[2] == "status":
		var in ServiceStatus
		err = decodeBody(c.Body, &in)
		if err == nil {
			handled = true
			value, err = s.Store.SetServiceStatus(op, tail[1], in)
		}
	case len(tail) == 1 && tail[0] == "agents":
		var in Service
		err = decodeBody(c.Body, &in)
		if err == nil {
			handled = true
			value, err = s.Store.RegisterService(op, in)
		}
	default:
		err = fail(404, "not_found", "The mutation endpoint does not exist.")
	}
	if err != nil && !handled {
		if e := s.Store.Denied(op, err); e != nil {
			return nil, e
		}
	}
	return value, err
}
func (s *Server) static(w http.ResponseWriter, r *http.Request) {
	name := filepath.Clean(r.URL.Path)
	if name == "/" || filepath.Ext(name) == "" {
		name = "/index.html"
	}
	if strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, filepath.Join(s.Web, strings.TrimPrefix(name, "/")))
}
func (s *Server) changed(id int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		select {
		case c <- id:
		default:
			close(c)
			delete(s.clients, c)
		}
	}
}
func (s *Server) events(w http.ResponseWriter, r *http.Request, a Actor) {
	f, ok := w.(http.Flusher)
	if !ok {
		return
	}
	s.mu.Lock()
	if len(s.clients) >= 64 {
		s.mu.Unlock()
		http.Error(w, "stream capacity reached", 503)
		return
	}
	c := make(chan int64, 16)
	s.clients[c] = true
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.clients[c] {
			delete(s.clients, c)
			close(c)
		}
		s.mu.Unlock()
	}()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Second))
	fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	f.Flush()
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	end := time.NewTimer(5 * time.Minute)
	defer end.Stop()
	for {
		select {
		case id, ok := <-c:
			if !ok {
				return
			}
			if !s.streamAuthorized(r, a) {
				return
			}
			http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Second))
			fmt.Fprintf(w, "id: %d\nevent: changed\ndata: {\"id\":%d}\n\n", id, id)
			f.Flush()
		case <-tick.C:
			if !s.streamAuthorized(r, a) {
				return
			}
			http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Second))
			fmt.Fprint(w, ": keepalive\n\n")
			f.Flush()
		case <-end.C:
			return
		case <-r.Context().Done():
			return
		}
	}
}
func CheckWeb(dir string) error { _, err := os.Stat(filepath.Join(dir, "index.html")); return err }

func (s *Server) streamAuthorized(r *http.Request, a Actor) bool {
	if s.Store.CheckConfiguration != nil && s.Store.CheckConfiguration() != nil {
		return false
	}
	if a.Kind == "human" {
		session, err := s.Auth.Session(r)
		return err == nil && require(session.Actor, "policy:read", false) == nil
	}
	svc, err := serviceFrom(s.Store.DB, a.Subject)
	return err == nil && svc.Enabled && require(Actor{Subject: svc.Subject, Kind: svc.Kind, Scopes: svc.Scopes}, "policy:read", false) == nil
}

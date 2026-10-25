// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/hostproto"
)

// provisioningAreas are the API areas this file routes.
var provisioningAreas = map[string]bool{"targets": true, "profiles": true, "launches": true, "launch-plans": true, "secrets": true, "launch-spec-schema": true, "access-presets": true, "api-tokens": true, "audit-catalog": true}

func apiArea(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

func apiTail(path string) []string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 {
		return nil
	}
	return parts[2:]
}

// isLaunchStream reports a launch event or log stream; streams hold their
// own bounded capacity instead of a request slot.
func isLaunchStream(r *http.Request) bool {
	tail := apiTail(r.URL.Path)
	return r.Method == "GET" && len(tail) == 3 && tail[0] == "launches" && (tail[2] == "events" || tail[2] == "logs") && strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

// provisioning serves the provisioning API. It returns false for paths it
// does not own.
func (s *Server) provisioning(w http.ResponseWriter, r *http.Request, c call) bool {
	tail := apiTail(r.URL.Path)
	if len(tail) == 0 || !provisioningAreas[tail[0]] {
		return false
	}
	if r.Method == "GET" {
		value, err := s.provisioningRead(w, r, c.Actor, tail)
		if err != nil {
			s.problem(w, r, err, c.Operation, true)
		} else if value != nil {
			jsonResponse(w, 200, value)
		}
		return true
	}
	value, err := s.provisioningWrite(r, c, tail)
	if err != nil {
		s.problem(w, r, err, c.Operation, false)
		return true
	}
	jsonResponse(w, 200, value)
	return true
}

func listParam(r *http.Request, name string, fallback int) int {
	v, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return fallback
	}
	return v
}

func (s *Server) provisioningRead(w http.ResponseWriter, r *http.Request, a Actor, tail []string) (any, error) {
	area := tail[0]
	scope := map[string]string{"targets": "target:read", "profiles": "policy:read", "launches": "launch:read", "secrets": "secrets:admin", "launch-spec-schema": "", "access-presets": "policy:read", "api-tokens": "auth:write", "audit-catalog": "audit:read", "launch-plans": "launch:write"}[area]
	if scope != "" {
		if err := require(a, scope, false); err != nil {
			return nil, err
		}
	} else if a.Subject == "" {
		return nil, fail(401, "authentication_required", "Sign in to continue.")
	}
	n := len(tail)
	switch {
	case area == "launch-spec-schema" && n == 1:
		return LaunchSpecSchema(), nil
	case area == "audit-catalog" && n == 1:
		return map[string]any{"items": AuditCatalog}, nil
	case area == "access-presets" && n == 1:
		presets, err := access.Presets()
		if err != nil {
			return nil, err
		}
		items := []access.Preset{}
		for _, name := range access.PresetNames() {
			items = append(items, presets[name])
		}
		return map[string]any{"items": items, "actions": access.Actions, "revoke_kinds": access.RevokeKinds}, nil
	case area == "targets" && n == 1:
		v, err := s.Store.Targets()
		return map[string]any{"items": v}, err
	case area == "targets" && n == 2:
		return s.Store.TargetDetail(tail[1])
	case area == "targets" && n == 3 && tail[2] == "seal-key":
		return s.Store.TargetSealKey(tail[1])
	case area == "targets" && n == 3 && tail[2] == "secrets":
		if err := require(a, "launch:write", false); err != nil {
			return nil, err
		}
		q := r.URL.Query()
		if len(q["profile"]) > 1 || len(r.URL.RawQuery) > 256 {
			return nil, fail(422, "invalid_filter", "Give at most one profile.")
		}
		return s.Store.TargetSecrets(a, tail[1], q.Get("profile"))
	case area == "profiles" && n == 1:
		v, err := s.Store.Profiles()
		return map[string]any{"items": v}, err
	case area == "profiles" && n == 2:
		return s.Store.ProfileDetail(tail[1])
	case area == "profiles" && n == 3 && tail[2] == "versions":
		v, err := s.Store.ProfileVersions(tail[1])
		return map[string]any{"items": v}, err
	case area == "profiles" && n == 4 && tail[2] == "versions":
		return s.Store.ProfileVersionDetail(tail[1], tail[3])
	case area == "launches" && n == 1:
		if len(r.URL.RawQuery) > 1024 {
			return nil, fail(422, "invalid_filter", "The query exceeds 1024 bytes.")
		}
		q, err := ParseLaunchQuery(r.URL.Query(), a)
		if err != nil {
			return nil, err
		}
		return s.Store.LaunchPage(q)
	case area == "launches" && n == 2 && tail[1] == "summary":
		if r.URL.RawQuery != "" {
			return nil, fail(422, "invalid_filter", "The summary takes no filters.")
		}
		return s.Store.LaunchSummary(a)
	case area == "launches" && n == 2:
		l, err := s.Store.LaunchDetail(tail[1])
		if err != nil {
			return nil, err
		}
		jobs, err := s.Store.LaunchJobs(tail[1])
		return map[string]any{"launch": l, "jobs": jobs}, err
	case area == "launches" && n == 3 && tail[2] == "events":
		if isLaunchStream(r) {
			s.launchStream(w, r, a, tail[1])
			return nil, nil
		}
		v, err := s.Store.LaunchEvents(tail[1], listParam(r, "after", 0), listParam(r, "limit", 200))
		return map[string]any{"items": v}, err
	case area == "launches" && n == 3 && tail[2] == "logs":
		if isLaunchStream(r) {
			after, err := streamAfter(r)
			if err != nil {
				return nil, err
			}
			if _, err = launchFrom(s.Store.DB, tail[1]); err != nil {
				return nil, err
			}
			s.logStream(w, r, a, tail[1], after)
			return nil, nil
		}
		return s.Store.LaunchLogs(tail[1], listParam(r, "after", 0), listParam(r, "limit", 500))
	case area == "secrets" && n == 1:
		v, err := s.Store.Secrets()
		return map[string]any{"items": v}, err
	case area == "secrets" && n == 3 && tail[2] == "receipt":
		return s.Store.SecretReceipt(tail[1])
	case area == "api-tokens" && n == 1:
		if a.Kind != "human" {
			return nil, fail(403, "forbidden", "API tokens belong to humans.")
		}
		v, err := s.Store.APITokens(a)
		return map[string]any{"items": v}, err
	}
	return nil, fail(404, "not_found", "The API endpoint does not exist.")
}

func (s *Server) provisioningWrite(r *http.Request, c call, tail []string) (any, error) {
	op := c.Operation
	area, n, method := tail[0], len(tail), r.Method
	deny := func(err error) (any, error) {
		if e := s.Store.Denied(op, err); e != nil {
			return nil, e
		}
		return nil, err
	}
	decode := func(dst any) error { return decodeBody(c.Body, dst) }
	switch {
	case area == "targets" && n == 1 && method == "POST":
		var in TargetInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.CreateTarget(op, in)
	case area == "targets" && n == 3 && tail[2] == "enrollment" && method == "POST":
		var in ReasonInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.IssueEnrollment(op, tail[1], in)
	case area == "targets" && n == 3 && tail[2] == "approve-key" && method == "POST":
		var in KeyApprovalInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.ApproveTargetKey(op, tail[1], in)
	case area == "targets" && n == 3 && tail[2] == "mount-roots" && method == "POST":
		var in TargetMountRootsInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.SetTargetMountRoots(op, tail[1], in)
	case area == "targets" && n == 2 && method == "PATCH":
		var in TargetInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.RenameTarget(op, tail[1], in)
	case area == "targets" && n == 2 && method == "DELETE":
		var in TargetRetireInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.RetireTarget(op, tail[1], in)
	case area == "profiles" && n == 1 && method == "POST":
		var in ProfileInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.CreateProfile(op, in)
	case area == "profiles" && n == 2 && method == "PATCH":
		var in ProfileSettingsInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.SetProfileApproval(op, tail[1], in)
	case area == "profiles" && n == 3 && tail[2] == "versions" && method == "POST":
		var in ProfileVersionInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.CreateProfileVersion(op, tail[1], in)
	case area == "profiles" && n == 5 && tail[2] == "versions" && tail[4] == "grants" && method == "POST":
		var in GrantInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.ApplyGrants(op, tail[1], tail[3], in)
	case area == "launches" && n == 1 && method == "POST":
		return s.Store.CreateLaunch(op, c.Body)
	case area == "launch-plans" && n == 1 && method == "POST":
		return s.Store.PlanLaunch(op, c.Body)
	case area == "launches" && n == 3 && (tail[2] == "approve" || tail[2] == "reject") && method == "POST":
		var in DecisionInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.DecideLaunch(op, tail[1], tail[2] == "approve", in)
	case area == "launches" && n == 3 && tail[2] == "stop" && method == "POST":
		var in DecisionInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.StopLaunch(op, tail[1], in)
	case area == "secrets" && n == 1 && method == "POST":
		var in SecretInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.CreateSecret(op, in)
	case area == "secrets" && n == 2 && method == "DELETE":
		var in ReasonInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.DeleteSecret(op, tail[1], in)
	case area == "api-tokens" && n == 1 && method == "POST":
		var in APITokenInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.CreateAPIToken(op, in)
	case area == "api-tokens" && n == 2 && method == "DELETE":
		var in ReasonInput
		if err := decode(&in); err != nil {
			return deny(err)
		}
		return s.Store.RevokeAPIToken(op, tail[1], in)
	}
	return deny(fail(404, "not_found", "The mutation endpoint does not exist."))
}

// launchStream sends launch events as Server-Sent Events. Each event's id is
// its sequence number; a client resumes with Last-Event-ID.
func (s *Server) launchStream(w http.ResponseWriter, r *http.Request, a Actor, id string) {
	f, ok := w.(http.Flusher)
	if !ok {
		return
	}
	after, _ := strconv.Atoi(r.Header.Get("Last-Event-ID"))
	if v := listParam(r, "after", -1); v >= 0 {
		after = v
	}
	if _, err := s.Store.LaunchEvents(id, 0, 1); err != nil {
		s.problem(w, r, err, Operation{Actor: a, Action: "api.denied", Resource: "launch:" + id, RequestID: r.Header.Get("X-Request-ID")}, false)
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
	send := func() bool {
		if !s.launchStreamAuthorized(r, a) {
			return false
		}
		events, err := s.Store.LaunchEvents(id, after, 200)
		if err != nil {
			return false
		}
		http.NewResponseController(w).SetWriteDeadline(time.Now().Add(20 * time.Second))
		for _, e := range events {
			raw, _ := json.Marshal(e)
			fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.Seq, e.Kind, raw)
			after = e.Seq
		}
		f.Flush()
		return true
	}
	fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	if !send() {
		return
	}
	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()
	end := time.NewTimer(5 * time.Minute)
	defer end.Stop()
	for {
		select {
		case _, ok := <-c:
			if !ok || !send() {
				return
			}
		case <-tick.C:
			if !s.launchStreamAuthorized(r, a) {
				return
			}
			fmt.Fprint(w, ": keepalive\n\n")
			f.Flush()
		case <-end.C:
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) launchStreamAuthorized(r *http.Request, a Actor) bool {
	if s.Store.CheckConfiguration != nil && s.Store.CheckConfiguration() != nil {
		return false
	}
	if _, ok := bearerToken(r); ok {
		actor, _, err := s.Auth.Token(r)
		return err == nil && require(actor, "launch:read", false) == nil
	}
	if a.Kind == "human" {
		session, err := s.Auth.Session(r)
		return err == nil && require(session.Actor, "launch:read", false) == nil
	}
	svc, err := serviceFrom(s.Store.DB, a.Subject)
	return err == nil && svc.Enabled && require(Actor{Subject: svc.Subject, Kind: svc.Kind, Scopes: svc.Scopes}, "launch:read", false) == nil
}

// Stream bounds. A stream is ended after streamLifetime (the client
// reconnects and resumes), a keepalive comment is sent every streamHeartbeat,
// and a write that cannot complete within streamWriteTimeout (a client that
// stopped reading) ends the stream.
const (
	defaultStreamWriteTimeout = 20 * time.Second
	defaultStreamHeartbeat    = 15 * time.Second
	defaultStreamLifetime     = 5 * time.Minute
	logStreamBatch            = 64
	maxStreams                = 64
)

func (s *Server) streamTimings() (write, heartbeat, lifetime time.Duration) {
	write, heartbeat, lifetime = s.StreamWriteTimeout, s.StreamHeartbeat, s.StreamLifetime
	if write <= 0 {
		write = defaultStreamWriteTimeout
	}
	if heartbeat <= 0 {
		heartbeat = defaultStreamHeartbeat
	}
	if lifetime <= 0 {
		lifetime = defaultStreamLifetime
	}
	return
}

// streamAfter reads the resume point: ?after= wins over Last-Event-ID; both
// are sequence numbers.
func streamAfter(r *http.Request) (int, error) {
	value := r.Header.Get("Last-Event-ID")
	if v := r.URL.Query().Get("after"); v != "" {
		value = v
	}
	if value == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 0 || n > 1<<30 || len(value) > 10 {
		return 0, fail(422, "invalid_filter", "after and Last-Event-ID are a line sequence number.")
	}
	return n, nil
}

// logStream sends a launch's agent output as Server-Sent Events: one "log"
// event per stored line, id = the line's sequence, data = the line as JSON
// (so control characters and newlines are escaped and an event never spans
// more than one data line). It resumes after Last-Event-ID or ?after=,
// fetches at most logStreamBatch lines before it has written them (a slow
// client holds back the reads, never memory), sends keepalives, and ends
// with an "end" event once the launch is terminal and every line was sent.
func (s *Server) logStream(w http.ResponseWriter, r *http.Request, a Actor, id string, after int) {
	f, ok := w.(http.Flusher)
	if !ok {
		return
	}
	writeTimeout, heartbeat, lifetime := s.streamTimings()
	s.mu.Lock()
	if len(s.clients) >= maxStreams {
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
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	write := func(format string, args ...any) bool {
		rc.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, err := fmt.Fprintf(w, format, args...)
		return err == nil
	}
	// send writes every line after the resume point, one bounded batch at a
	// time, and reports whether the stream should go on.
	send := func() (more bool) {
		if !s.launchStreamAuthorized(r, a) {
			return false
		}
		for {
			page, err := s.Store.LaunchLogs(id, after, logStreamBatch)
			if err != nil {
				return false
			}
			lines := page["items"].([]LogLine)
			s.logLinesFetched.Add(int64(len(lines)))
			for _, line := range lines {
				raw, _ := json.Marshal(line)
				rc.SetWriteDeadline(time.Now().Add(writeTimeout))
				if _, err := fmt.Fprintf(w, "id: %d\nevent: log\ndata: %s\n\n", line.Seq, raw); err != nil {
					return false
				}
				after = line.Seq
				s.logLinesDelivered.Add(1)
			}
			rc.SetWriteDeadline(time.Now().Add(writeTimeout))
			if rc.Flush() != nil || r.Context().Err() != nil {
				return false
			}
			if len(lines) < logStreamBatch {
				break
			}
		}
		l, err := launchFrom(s.Store.DB, id)
		if err != nil {
			return false
		}
		if TerminalState(l.State) {
			raw, _ := json.Marshal(map[string]any{"state": l.State, "last_seq": after, "truncated": l.logBytes >= maxLaunchLogBytes || l.logSeq >= maxLaunchLogLines})
			write("event: end\ndata: %s\n\n", raw)
			f.Flush()
			return false
		}
		return true
	}
	ready, _ := json.Marshal(map[string]int{"after": after})
	if !write("retry: 2000\nevent: ready\ndata: %s\n\n", ready) {
		return
	}
	f.Flush()
	if !send() {
		return
	}
	tick := time.NewTicker(heartbeat)
	defer tick.Stop()
	end := time.NewTimer(lifetime)
	defer end.Stop()
	for {
		select {
		case _, ok := <-c:
			if !ok || !send() {
				return
			}
		case <-tick.C:
			if !s.launchStreamAuthorized(r, a) || !write(": keepalive\n\n") {
				return
			}
			f.Flush()
		case <-end.C:
			return
		case <-r.Context().Done():
			return
		}
	}
}

// hostd serves /api/v1/hostd/*. A host authenticates every request with its
// own signature, so these routes take no session, token or CSRF header.
func (s *Server) hostd(w http.ResponseWriter, r *http.Request) {
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		s.hostProblem(w, r, fail(503, "request_capacity", "The request capacity is full."))
		return
	}
	// Host requests are not limited by the shared client address bucket: an
	// unauthenticated flood from the same address (behind a proxy, every
	// client's) must never starve an honest host's signed polls, or its
	// running launches would fail lost_host. Each signed request is first
	// checked against the host's enrolled key (one row read and one Ed25519
	// verification; the body and the concurrent requests are bounded), and
	// then limited per host. Only failed checks count against the client
	// address (and are refused once over its limit), and their audit rows
	// are sampled.
	host, ferr := s.clientIP(r)
	id := r.Header.Get("X-Request-ID")
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/hostd/")
	if ferr != nil {
		s.hostProblem(w, r, ferr)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		s.hostProblem(w, r, fail(415, "json_required", "Use an application/json request."))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, hostproto.MaxEnvelopeBytes+1))
	if err != nil || len(body) > hostproto.MaxEnvelopeBytes {
		s.hostProblem(w, r, fail(413, "body_too_large", "The host request exceeds the one MiB limit."))
		return
	}
	if domain := hostDomain(path); domain != "" {
		hostID, perr := s.Store.PreauthenticateHost(body, domain)
		if perr != nil {
			if s.limited("hostfail:" + host) {
				s.hostProblem(w, r, fail(429, "rate_limited", "Too many host requests from this address failed authentication."))
				return
			}
			op := hostOp(id, map[string]string{hostproto.DomainPoll: "hostd.poll.denied", hostproto.DomainResync: "hostd.resync.denied", hostproto.DomainEvents: "hostd.events.denied"}[domain], "target")
			op.Source = host
			if e := s.Store.Denied(op, perr); e != nil {
				perr = e
			}
			s.hostProblem(w, r, perr)
			return
		}
		if s.limitedHost(hostID) {
			s.hostProblem(w, r, fail(429, "rate_limited", "The request rate of this host exceeds its limit."))
			return
		}
	}
	var value any
	switch {
	case path == "enroll":
		if s.limited("ip:"+host) || s.limited("enroll:"+host) {
			s.hostProblem(w, r, fail(429, "rate_limited", "The enrollment rate exceeds its limit."))
			return
		}
		value, err = s.Store.EnrollHost(body, id)
	case path == "poll":
		value, err = s.Store.HostPoll(body, id)
		if err == nil {
			s.Store.Sweep()
		}
	case path == "resync":
		if s.limited("enroll:resync:" + host) {
			s.hostProblem(w, r, fail(429, "rate_limited", "The resync rate exceeds its limit."))
			return
		}
		value, err = s.Store.HostResync(body, id)
	case strings.HasPrefix(path, "jobs/") && strings.HasSuffix(path, "/events") && strings.Count(path, "/") == 2:
		value, err = s.Store.HostEvents(strings.TrimSuffix(strings.TrimPrefix(path, "jobs/"), "/events"), body, id)
	default:
		err = fail(404, "not_found", "The host endpoint does not exist.")
	}
	if err != nil {
		s.hostProblem(w, r, err)
		return
	}
	jsonResponse(w, 200, value)
}

// hostDomain is the signing domain of a host endpoint that authenticates
// with an enrolled key ("" for enrollment, which binds a new key).
func hostDomain(path string) string {
	switch {
	case path == "poll":
		return hostproto.DomainPoll
	case path == "resync":
		return hostproto.DomainResync
	case strings.HasPrefix(path, "jobs/") && strings.HasSuffix(path, "/events") && strings.Count(path, "/") == 2:
		return hostproto.DomainEvents
	}
	return ""
}

func (s *Server) hostProblem(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := errorResult(err)
	body := map[string]any{"error": map[string]string{"code": code, "message": message}, "request_id": r.Header.Get("X-Request-ID")}
	var hf *hostFailure
	if errors.As(err, &hf) && hf.sequence {
		body["last_accepted_sequence"] = hf.lastSequence
	}
	jsonResponse(w, status, body)
}

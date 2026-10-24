// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// route is one validated upstream with its credential and transport.
type route struct {
	name      string
	upstream  Upstream
	rules     []Rule
	cred      *credential
	guard     *addressGuard
	transport *http.Transport
}

func (r *Route) upstreamAuthority() string {
	port := r.Upstream.Port
	if port == 0 {
		port = 443
	}
	return net.JoinHostPort(r.Upstream.Host, strconv.Itoa(port))
}

// hostHeader is the authority the upstream sees; it always equals the SNI name.
func (r *route) hostHeader() string {
	if r.upstream.Port == 443 {
		return r.upstream.Host
	}
	return net.JoinHostPort(r.upstream.Host, strconv.Itoa(r.upstream.Port))
}

var errPin = errors.New("upstream certificate does not match a configured pin")

func newTransport(up Upstream, guard *addressGuard, set Settings, roots *x509.CertPool) *http.Transport {
	pins := map[string]bool{}
	for _, p := range up.PinSPKISHA256 {
		pins[p] = true
	}
	conf := &tls.Config{
		ServerName:         up.Host,
		RootCAs:            roots, // nil selects the system roots
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"http/1.1"},
		ClientSessionCache: tls.NewLRUClientSessionCache(16),
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.NegotiatedProtocol != "" && cs.NegotiatedProtocol != "http/1.1" {
				return errors.New("upstream negotiated an unexpected protocol")
			}
			if len(pins) == 0 {
				return nil
			}
			for _, chain := range cs.VerifiedChains {
				for _, cert := range chain {
					sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
					if pins[base64.StdEncoding.EncodeToString(sum[:])] {
						return nil
					}
				}
			}
			return errPin
		},
	}
	var protocols http.Protocols
	protocols.SetHTTP1(true)
	return &http.Transport{
		Proxy:                  nil, // never honour HTTP(S)_PROXY from the environment
		DialContext:            guard.DialContext,
		TLSClientConfig:        conf,
		TLSHandshakeTimeout:    10 * time.Second,
		DisableCompression:     true,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    4,
		MaxConnsPerHost:        set.MaxUpstreamConnections,
		IdleConnTimeout:        60 * time.Second,
		ResponseHeaderTimeout:  set.UpstreamHeaderTimeout,
		MaxResponseHeaderBytes: 64 << 10,
		ForceAttemptHTTP2:      false,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
		Protocols:              &protocols,
	}
}

type connKey struct{}

// errorBody is the only body the broker itself writes: a fixed reason code.
func writeError(w http.ResponseWriter, status int, reason string) {
	h := w.Header()
	for k := range h {
		delete(h, k)
	}
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `{"error":"agentgate_broker","reason":"`+reason+`"}`+"\n")
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handlers.Add(1)
	defer s.handlers.Done()
	defer func() {
		if v := recover(); v != nil {
			if v != http.ErrAbortHandler {
				s.stats.deny(reasonInternal, r.Method, "", "")
			}
			panic(http.ErrAbortHandler)
		}
	}()
	s.stats.request()
	deny := func(status int, reason string) {
		s.stats.deny(reason, r.Method, r.Host, r.RequestURI)
		// net/http drains an unread body after the handler returns; bound that
		// drain so a denied client cannot hold its connection slot.
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(time.Second))
		writeError(w, status, reason)
	}
	if s.closing.Load() {
		deny(http.StatusServiceUnavailable, reasonShuttingDown)
		return
	}
	ic, _ := r.Context().Value(connKey{}).(*inspectedConn)
	if ic == nil {
		deny(http.StatusBadRequest, reasonHeaderIncomplete)
		return
	}
	if v := ic.verdict(); v != "" {
		status := http.StatusBadRequest
		if v == reasonHeaderTooLarge || v == reasonHeaderCount {
			status = http.StatusRequestHeaderFieldsTooLarge
		}
		deny(status, v)
		return
	}
	if !s.bucket.allow() {
		deny(http.StatusTooManyRequests, reasonRateLimited)
		return
	}
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
		deny(http.StatusHTTPVersionNotSupported, reasonHTTPVersion)
		return
	}
	if r.Method == http.MethodConnect {
		deny(http.StatusMethodNotAllowed, reasonConnect)
		return
	}
	if !strings.HasPrefix(r.RequestURI, "/") || r.URL.IsAbs() || r.URL.Host != "" {
		deny(http.StatusBadRequest, reasonAbsoluteForm)
		return
	}
	if r.Host != s.authority {
		deny(http.StatusMisdirectedRequest, reasonHostMismatch)
		return
	}
	if wantsUpgrade(r.Header) {
		deny(http.StatusBadRequest, reasonUpgrade)
		return
	}
	if len(r.Trailer) > 0 || len(r.Header.Values("Trailer")) > 0 {
		deny(http.StatusBadRequest, reasonTrailerNotAllowed)
		return
	}
	rawPath, rawQuery, hasQuery := strings.Cut(r.RequestURI, "?")
	decoded, ok := decodePath(rawPath)
	if !ok {
		deny(http.StatusBadRequest, reasonPathInvalid)
		return
	}
	if hasQuery && !validQuery(rawQuery) {
		deny(http.StatusBadRequest, reasonQueryInvalid)
		return
	}
	name, restRaw, rest, ok := splitRoute(rawPath, decoded)
	rt := s.routes[name]
	if !ok || rt == nil {
		deny(http.StatusNotFound, reasonRouteUnknown)
		return
	}
	s.stats.routeRequest(name)
	known, allowed := ruleAllows(rt.rules, r.Method, rest)
	if !allowed {
		if known {
			deny(http.StatusMethodNotAllowed, reasonMethodNotAllowed)
		} else {
			deny(http.StatusForbidden, reasonPathNotAllowed)
		}
		return
	}
	select {
	case s.inflight <- struct{}{}:
		defer func() { <-s.inflight }()
	default:
		deny(http.StatusServiceUnavailable, reasonConcurrency)
		return
	}
	body, status, reason := s.readBody(w, r)
	if reason != "" {
		deny(status, reason)
		return
	}
	s.forward(w, r, rt, restRaw, rest, rawQuery, hasQuery, body)
}

// readBody buffers the whole request body, bounded in size and time, so the
// upstream request is always sent with an exact Content-Length and a truncated
// or malformed chunked body never reaches the upstream.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, int, string) {
	if r.ContentLength > s.set.MaxRequestBytes {
		return nil, http.StatusRequestEntityTooLarge, reasonRequestTooLarge
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(s.set.BodyTimeout))
	size := int64(0)
	if r.ContentLength > 0 {
		size = r.ContentLength
	}
	buf := bytes.NewBuffer(make([]byte, 0, size))
	_, err := io.Copy(buf, io.LimitReader(r.Body, s.set.MaxRequestBytes+1))
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return nil, http.StatusRequestTimeout, reasonBodyTimeout
		}
		return nil, http.StatusBadRequest, reasonBodyInvalid
	}
	if int64(buf.Len()) > s.set.MaxRequestBytes {
		return nil, http.StatusRequestEntityTooLarge, reasonRequestTooLarge
	}
	// The body is complete: clear the deadline so a long streamed response is
	// not cut by it (net/http would cancel the request on a read timeout).
	_ = rc.SetReadDeadline(time.Time{})
	return buf.Bytes(), 0, ""
}

func classify(err error, idle bool) string {
	var ue *upstreamError
	var ne net.Error
	var cv *tls.CertificateVerificationError
	var hn x509.HostnameError
	var ua x509.UnknownAuthorityError
	var ci x509.CertificateInvalidError
	var rh tls.RecordHeaderError
	switch {
	case idle:
		return errKindStreamIdle
	case errors.As(err, &ue):
		return ue.kind
	case errors.Is(err, errPin), errors.As(err, &cv), errors.As(err, &hn), errors.As(err, &ua), errors.As(err, &ci), errors.As(err, &rh):
		return errKindTLS
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return errKindTimeout
	case errors.Is(err, context.Canceled):
		return errKindAborted
	}
	if strings.Contains(err.Error(), "tls:") {
		return errKindTLS
	}
	return errKindOther
}

func (s *Server) forward(w http.ResponseWriter, r *http.Request, rt *route, restRaw, rest, rawQuery string, hasQuery bool, body []byte) {
	ctx, cancel := context.WithTimeout(r.Context(), s.set.RequestTimeout)
	defer cancel()
	base := rt.upstream.BasePath
	u := &url.URL{Scheme: "https", Host: rt.hostHeader(), Path: base + rest, RawPath: base + restRaw}
	if hasQuery {
		u.RawQuery = rawQuery
		u.ForceQuery = rawQuery == ""
	}
	var reader io.Reader = http.NoBody
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	out, err := http.NewRequestWithContext(ctx, r.Method, u.String(), reader)
	if err != nil {
		s.stats.routeError(rt.name, errKindOther)
		writeError(w, http.StatusBadGateway, "upstream_request_invalid")
		return
	}
	if len(body) > 0 {
		out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	out.Header = outboundHeaders(r.Header, rt.cred.strip)
	out.Header[rt.cred.header] = []string{rt.cred.value}
	for k, v := range rt.cred.extra {
		out.Header[k] = v
	}
	out.Header["Accept-Encoding"] = []string{"identity"}
	if len(out.Header.Values("User-Agent")) == 0 {
		out.Header["User-Agent"] = []string{""} // suppress the Go default
	}
	out.Host = rt.hostHeader()

	resp, err := rt.transport.RoundTrip(out)
	if err != nil {
		kind := classify(err, false)
		s.stats.routeError(rt.name, kind)
		status := http.StatusBadGateway
		if kind == errKindTimeout {
			status = http.StatusGatewayTimeout
		}
		writeError(w, status, "upstream_"+kind)
		return
	}
	defer resp.Body.Close()
	s.stats.forwarded(rt.name, len(body))
	s.stats.status(rt.name, resp.StatusCode)
	if resp.StatusCode == http.StatusSwitchingProtocols {
		s.stats.routeError(rt.name, errKindSwitch)
		writeError(w, http.StatusBadGateway, "upstream_"+errKindSwitch)
		return
	}
	if ce := resp.Header.Values("Content-Encoding"); len(ce) > 1 || (len(ce) == 1 && !strings.EqualFold(strings.TrimSpace(ce[0]), "identity")) {
		// Redaction needs the plain body; the broker asked for identity.
		s.stats.routeError(rt.name, errKindEncoded)
		writeError(w, http.StatusBadGateway, "upstream_"+errKindEncoded)
		return
	}
	if resp.ContentLength > s.set.MaxResponseBytes {
		s.stats.routeError(rt.name, errKindTooLarge)
		writeError(w, http.StatusBadGateway, "upstream_"+errKindTooLarge)
		return
	}
	s.stats.responseBytes(rt.name, 0, s.copyResponseHeaders(w.Header(), resp.Header, rt))
	if resp.ContentLength >= 0 && r.Method != http.MethodHead {
		w.Header().Set("Content-Length", strconv.FormatInt(resp.ContentLength, 10))
	}
	w.WriteHeader(resp.StatusCode)
	s.stream(ctx, cancel, w, resp.Body, rt)
}

// copyResponseHeaders drops hop-by-hop, cookie and protocol-advertising
// headers and any header whose value carries a credential form. It returns the
// number of headers dropped for carrying a credential.
func (s *Server) copyResponseHeaders(dst, src http.Header, rt *route) int {
	listed := connectionListed(src)
	redacted := 0
	for k, vv := range src {
		ck := http.CanonicalHeaderKey(k)
		if responseStripped[ck] || listed[ck] {
			continue
		}
		carries := false
		for _, v := range vv {
			if containsCredential(rt.cred.patterns, v) {
				carries = true
				break
			}
		}
		if carries {
			redacted++
			continue
		}
		if ck == "Location" && len(vv) == 1 {
			dst[ck] = []string{rewriteLocation(vv[0], rt)}
			continue
		}
		dst[ck] = append([]string(nil), vv...)
	}
	return redacted
}

// stream copies the upstream body with redaction, a size cap, an idle timeout
// between upstream reads and a deadline on every client write. It flushes after
// every write so Server-Sent Events arrive promptly. A failure after the status
// line aborts the connection, so a truncated body is never presented as complete.
func (s *Server) stream(ctx context.Context, cancel context.CancelFunc, w http.ResponseWriter, body io.Reader, rt *route) {
	var idleFired atomic.Bool
	idle := time.AfterFunc(s.set.StreamIdleTimeout, func() { idleFired.Store(true); cancel() })
	defer idle.Stop()
	rc := http.NewResponseController(w)
	red := newRedactor(rt.cred.patterns)
	defer red.release()
	written := int64(0)
	counted := 0
	abort := func(kind string) {
		s.stats.routeError(rt.name, kind)
		panic(http.ErrAbortHandler)
	}
	emit := func(p []byte) {
		if len(p) == 0 {
			return
		}
		if written+int64(len(p)) > s.set.MaxResponseBytes {
			abort(errKindTooLarge)
		}
		// Count before writing, so the evidence is never behind what the
		// client has already received.
		s.stats.responseBytes(rt.name, len(p), red.count-counted)
		counted = red.count
		_ = rc.SetWriteDeadline(time.Now().Add(s.set.WriteTimeout))
		n, err := w.Write(p)
		written += int64(n)
		if err == nil {
			err = rc.Flush()
		}
		if err != nil {
			abort(errKindClientWrite)
		}
	}
	buf := make([]byte, 32<<10)
	for {
		n, err := body.Read(buf)
		idle.Reset(s.set.StreamIdleTimeout)
		if n > 0 {
			emit(red.process(buf[:n], false))
		}
		if err == io.EOF {
			emit(red.process(nil, true))
			return
		}
		if err != nil {
			if ctx.Err() != nil && !idleFired.Load() && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				abort(errKindTimeout)
			}
			abort(classify(err, idleFired.Load()))
		}
	}
}

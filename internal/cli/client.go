// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mathrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Bounds on what the client sends and accepts.
const (
	maxResponseBytes  = 8 << 20
	maxErrorBytes     = 64 << 10
	maxAttempts       = 4
	backoffBase       = 300 * time.Millisecond
	backoffCap        = 5 * time.Second
	maxRetryAfter     = 30 * time.Second
	defaultTimeout    = 30 * time.Second
	maxCAFileBytes    = 1 << 20
	apiPrefix         = "/api/v1"
	userAgentTemplate = "agentgate-cli/%s"
)

var errPinMismatch = errors.New("certificate pin mismatch")

// Client calls the service API. It never follows redirects, retries only
// requests that are safe to repeat, and bounds every response.
type Client struct {
	base        *url.URL
	origin      string
	token       string
	hc          *http.Client
	timeout     time.Duration
	verbose     io.Writer
	sleep       func(context.Context, time.Duration) error
	jitter      func() float64
	userAgent   string
	correlation string
}

// request is one API call.
type request struct {
	method   string
	path     string
	query    url.Values
	body     []byte
	retry    bool
	idemKey  string
	noAuth   bool
	accept   string
	cookie   string
	csrf     string
	origin   bool
	maxBytes int64
}

type response struct {
	status    int
	header    http.Header
	body      []byte
	requestID string
}

// serverURL validates and normalizes a service origin.
func serverURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, usageError("the service URL must be an origin such as https://agentgate.example:9443 (got %q)", redactText(raw))
	}
	u.Path = ""
	u.Host = strings.ToLower(u.Host)
	return u, nil
}

func isLoopbackHost(host string) bool {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// normalizePin accepts sha256:HEX, HEX or colon-separated HEX.
func normalizePin(pin string) (string, error) {
	p := strings.ToLower(strings.TrimSpace(pin))
	p = strings.TrimPrefix(p, "sha256:")
	p = strings.ReplaceAll(p, ":", "")
	if raw, err := hex.DecodeString(p); err != nil || len(raw) != sha256.Size {
		return "", usageError("a certificate pin is the SHA-256 of the server certificate: sha256: and 64 hex characters")
	}
	return "sha256:" + p, nil
}

// transportOptions are the trust settings for one service.
type transportOptions struct {
	caFile            string
	pin               string
	allowLoopbackHTTP bool
}

func newTransport(server *url.URL, o transportOptions) (*http.Transport, error) {
	if server.Scheme == "http" {
		if !o.allowLoopbackHTTP {
			return nil, usageError("plain http is refused; use https, or --insecure for a service on this machine's loopback address")
		}
		if !isLoopbackHost(server.Host) {
			return nil, usageError("--insecure allows plain http only to a loopback address (127.0.0.1, ::1, localhost), not %s", server.Host)
		}
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if o.caFile != "" {
		raw, err := readBounded(o.caFile, maxCAFileBytes)
		if err != nil {
			return nil, usageError("cannot read --ca-file %s: %v", o.caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, usageError("--ca-file %s holds no PEM certificate", o.caFile)
		}
		cfg.RootCAs = pool
	}
	if o.pin != "" {
		want, err := normalizePin(o.pin)
		if err != nil {
			return nil, err
		}
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errPinMismatch
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare([]byte("sha256:"+hex.EncodeToString(sum[:])), []byte(want)) != 1 {
				return errPinMismatch
			}
			return nil
		}
	}
	return &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		TLSClientConfig:        cfg,
		TLSHandshakeTimeout:    10 * time.Second,
		IdleConnTimeout:        30 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
		ForceAttemptHTTP2:      true,
	}, nil
}

func readBounded(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, max+1))
	if err == nil && int64(len(raw)) > max {
		err = fmt.Errorf("larger than %d bytes", max)
	}
	return raw, err
}

func newCorrelationID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "cli-" + hex.EncodeToString(b)
}

func newIdempotencyKey() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "cli-" + hex.EncodeToString(b)
}

func newClient(server *url.URL, token string, rt http.RoundTripper, timeout time.Duration, verbose io.Writer, version string) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		base:    server,
		origin:  server.Scheme + "://" + server.Host,
		token:   token,
		hc:      &http.Client{Transport: rt, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		timeout: timeout,
		verbose: verbose,
		sleep: func(ctx context.Context, d time.Duration) error {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		jitter:      func() float64 { return 0.5 + mathrand.Float64()/2 },
		userAgent:   fmt.Sprintf(userAgentTemplate, version),
		correlation: newCorrelationID(),
	}
}

func (c *Client) logf(format string, args ...any) {
	if c.verbose != nil {
		fmt.Fprintf(c.verbose, "* "+format+"\n", args...)
	}
}

func (c *Client) target(r request) string {
	u := c.origin + r.path
	if len(r.query) > 0 {
		u += "?" + r.query.Encode()
	}
	return u
}

func (c *Client) newHTTPRequest(ctx context.Context, r request) (*http.Request, error) {
	var body io.Reader
	if r.body != nil {
		body = bytes.NewReader(r.body)
	}
	req, err := http.NewRequestWithContext(ctx, r.method, c.target(r), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("X-Correlation-ID", c.correlation)
	accept := r.accept
	if accept == "" {
		accept = "application/json"
	}
	req.Header.Set("Accept", accept)
	if r.body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if !r.noAuth && r.cookie == "" && c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if r.cookie != "" {
		req.Header.Set("Cookie", r.cookie)
	}
	if r.csrf != "" {
		req.Header.Set("X-CSRF-Token", r.csrf)
	}
	if r.origin || r.csrf != "" {
		req.Header.Set("Origin", c.origin)
	}
	if r.idemKey != "" {
		req.Header.Set("Idempotency-Key", r.idemKey)
	}
	if c.verbose != nil {
		names := []string{}
		for name, values := range req.Header {
			if name == "User-Agent" || name == "Accept" {
				continue
			}
			names = append(names, name+": "+redactHeader(name, strings.Join(values, ",")))
		}
		c.logf("> %s %s [%s]", r.method, c.target(r), strings.Join(sortedStrings(names), "; "))
	}
	return req, nil
}

func (c *Client) once(ctx context.Context, r request) (*response, error) {
	actx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := c.newHTTPRequest(actx, r)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	max := r.maxBytes
	if max == 0 {
		max = maxResponseBytes
	}
	if resp.StatusCode >= 400 {
		max = maxErrorBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	out := &response{status: resp.StatusCode, header: resp.Header, body: body, requestID: resp.Header.Get("X-Request-ID")}
	c.logf("< %d %s request-id=%s %dms %d bytes", resp.StatusCode, http.StatusText(resp.StatusCode), out.requestID, time.Since(start).Milliseconds(), len(body))
	if int64(len(body)) > max {
		if resp.StatusCode < 400 {
			return nil, &Error{Exit: ExitServer, Code: "response_too_large", Message: fmt.Sprintf("The service response exceeds %d bytes.", max), RequestID: out.requestID}
		}
		out.body = body[:max]
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, &Error{Exit: ExitServer, Code: "redirect_refused", Message: "The service answered with a redirect; agentgate does not follow redirects.", Hint: "Use the service's final public URL.", Status: resp.StatusCode, RequestID: out.requestID}
	}
	return out, nil
}

func retryableStatus(status int) bool {
	return status == 429 || status == 502 || status == 503 || status == 504
}

func retryAfter(h http.Header, now time.Time) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	if n, err := strconv.Atoi(v); err == nil && n >= 0 {
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := t.Sub(now); d > 0 {
			return d
		}
	}
	return 0
}

func (c *Client) backoff(attempt int) time.Duration {
	d := backoffBase << attempt
	if d > backoffCap || d <= 0 {
		d = backoffCap
	}
	return time.Duration(float64(d) * c.jitter())
}

// do sends r, retrying it when r.retry is set, and returns the response or
// an Error with the service's code and message.
func (c *Client) do(ctx context.Context, r request) (*response, error) {
	attempts := 1
	if r.retry {
		attempts = maxAttempts
	}
	for i := 0; ; i++ {
		resp, err := c.once(ctx, r)
		var reason string
		switch {
		case err != nil:
			var e *Error
			if errors.As(err, &e) || ctx.Err() != nil {
				return nil, classifyTransport(ctx, err)
			}
			cls := classifyTransport(ctx, err)
			if cls.Exit == ExitTrust || cls.Exit == ExitInterrupted {
				return nil, cls
			}
			if i+1 >= attempts {
				return nil, cls
			}
			reason = cls.Code
		case resp.status < 300:
			return resp, nil
		default:
			apiErr := decodeAPIError(resp)
			if !retryableStatus(resp.status) || i+1 >= attempts {
				return resp, apiErr
			}
			reason = fmt.Sprintf("%d %s", resp.status, apiErr.Code)
		}
		delay := c.backoff(i)
		if resp != nil {
			if ra := retryAfter(resp.header, time.Now()); ra > 0 {
				if ra > maxRetryAfter {
					e := decodeAPIError(resp)
					e.Hint = fmt.Sprintf("The service asks to retry after %s; try again then.", ra.Round(time.Second))
					return resp, e
				}
				delay = ra
			}
		}
		c.logf("retry %d/%d in %s after %s", i+1, attempts-1, delay.Round(time.Millisecond), reason)
		if err := c.sleep(ctx, delay); err != nil {
			return nil, &Error{Exit: ExitInterrupted, Code: "interrupted", Message: "Interrupted."}
		}
	}
}

func sanitizeMessage(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	if len(s) > 512 {
		s = s[:512] + "..."
	}
	return redactText(strings.TrimSpace(s))
}

// decodeAPIError reads the service error envelope.
func decodeAPIError(resp *response) *Error {
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
		RequestID string `json:"request_id"`
	}
	json.Unmarshal(resp.body, &envelope)
	e := &Error{Exit: exitForStatus(resp.status), Status: resp.status, Code: envelope.Error.Code, Message: sanitizeMessage(envelope.Error.Message), RequestID: envelope.RequestID}
	if e.RequestID == "" {
		e.RequestID = resp.requestID
	}
	if e.Code == "" {
		e.Code = "http_" + strconv.Itoa(resp.status)
		e.Message = sanitizeMessage(strings.TrimSpace(string(resp.body)))
		if e.Message == "" {
			e.Message = http.StatusText(resp.status)
		}
	}
	if h, ok := codeHints[e.Code]; ok {
		e.Hint = h
	} else {
		e.Hint = hintForClass(e.Exit)
	}
	return e
}

// call sends a JSON request and decodes a JSON answer into out (unless nil).
// It returns the raw body for --json output.
func (c *Client) call(ctx context.Context, r request, out any) ([]byte, error) {
	resp, err := c.do(ctx, r)
	if err != nil {
		return nil, err
	}
	if out != nil {
		if err := json.Unmarshal(resp.body, out); err != nil {
			return nil, &Error{Exit: ExitServer, Code: "invalid_response", Message: "The service answered with JSON the CLI does not understand.", RequestID: resp.requestID, Hint: "Check that the CLI and the service versions match (agentgate version)."}
		}
	}
	return resp.body, nil
}

func (c *Client) get(ctx context.Context, path string, query url.Values, out any) ([]byte, error) {
	return c.call(ctx, request{method: "GET", path: path, query: query, retry: true}, out)
}

// mutate sends a write. When idempotent is set, the request carries an
// Idempotency-Key, so the service replays the recorded answer if a retry
// arrives after the first attempt committed.
func (c *Client) mutate(ctx context.Context, method, path string, body any, idempotent bool, out any) ([]byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	r := request{method: method, path: path, body: raw}
	if idempotent {
		r.retry, r.idemKey = true, newIdempotencyKey()
	}
	return c.call(ctx, r, out)
}

func sortedStrings(v []string) []string {
	out := append([]string{}, v...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func pathEscape(v string) string { return url.PathEscape(v) }

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// StatsVersion identifies the evidence document the host agent collects.
const StatsVersion = "agentgate.broker-stats.v1"

// MaxStatsBytes bounds a stats document.
const MaxStatsBytes = 1 << 20

// StatsDocument is the bounded evidence block for one launch. It holds counts,
// fixed reason codes and sanitized path prefixes only: never a header value,
// query string, body, address of the client or secret.
type StatsDocument struct {
	Version          string                 `json:"version"`
	LaunchID         string                 `json:"launch_id"`
	TargetID         string                 `json:"target_id"`
	ConfigSHA256     string                 `json:"config_sha256"`
	Listen           string                 `json:"listen"`
	StartedAt        string                 `json:"started_at"`
	UpdatedAt        string                 `json:"updated_at"`
	Deadline         string                 `json:"deadline"`
	State            string                 `json:"state"`
	StopReason       string                 `json:"stop_reason,omitempty"`
	Complete         bool                   `json:"complete"`
	Hardening        Hardening              `json:"hardening"`
	Connections      ConnectionStats        `json:"connections"`
	Requests         RequestTotals          `json:"requests"`
	Denied           map[string]uint64      `json:"denied"`
	Routes           map[string]*RouteStats `json:"routes"`
	Denials          []DenialRecord         `json:"denials"`
	DenialsTruncated bool                   `json:"denials_truncated"`
}

// Hardening records the process state the broker achieved before serving.
type Hardening struct {
	UID            int  `json:"uid"`
	GID            int  `json:"gid"`
	NotDumpable    bool `json:"not_dumpable"`
	CoreLimitZero  bool `json:"core_limit_zero"`
	NoNewPrivs     bool `json:"no_new_privs"`
	NoCapabilities bool `json:"no_effective_capabilities"`
	MemoryLocked   bool `json:"secret_memory_locked"`
}

// ConnectionStats counts inbound connections.
type ConnectionStats struct {
	Accepted uint64 `json:"accepted"`
	Rejected uint64 `json:"rejected_over_limit"`
}

// RequestTotals counts requests across routes.
type RequestTotals struct {
	Total     uint64 `json:"total"`
	Denied    uint64 `json:"denied"`
	Forwarded uint64 `json:"forwarded"`
}

// RouteStats counts one route's upstream traffic.
type RouteStats struct {
	Upstream   string            `json:"upstream"`
	Requests   uint64            `json:"requests"`
	Forwarded  uint64            `json:"forwarded"`
	Status     map[string]uint64 `json:"status"`
	Errors     map[string]uint64 `json:"errors"`
	BytesIn    uint64            `json:"bytes_in"`
	BytesOut   uint64            `json:"bytes_out"`
	Redactions uint64            `json:"redactions"`
}

// DenialRecord is one early denial: method, sanitized Host and the first two
// path segments. Never a query string, header or body.
type DenialRecord struct {
	At     string `json:"at"`
	Reason string `json:"reason"`
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
}

// Denial reasons outside the raw header check.
const (
	reasonAbsoluteForm      = "absolute_form"
	reasonConnect           = "connect_method"
	reasonHostMismatch      = "host_mismatch"
	reasonUpgrade           = "upgrade"
	reasonPathInvalid       = "path_invalid"
	reasonQueryInvalid      = "query_invalid"
	reasonRouteUnknown      = "route_unknown"
	reasonPathNotAllowed    = "path_not_allowed"
	reasonMethodNotAllowed  = "method_not_allowed"
	reasonRateLimited       = "rate_limited"
	reasonConcurrency       = "concurrency_limit"
	reasonRequestTooLarge   = "request_too_large"
	reasonBodyInvalid       = "body_invalid"
	reasonBodyTimeout       = "body_timeout"
	reasonShuttingDown      = "shutting_down"
	reasonInternal          = "internal_error"
	reasonTrailerNotAllowed = "request_trailer"
)

var knownReasons = map[string]bool{}

func init() {
	for _, r := range []string{reasonHeaderIncomplete, reasonHeaderTooLarge, reasonHeaderCount, reasonBareLF, reasonBareCR,
		reasonObsFold, reasonHeaderSyntax, reasonRequestLine, reasonHTTPVersion, reasonDuplicateCL, reasonInvalidCL, reasonTEAndCL,
		reasonBadTE, reasonHost, reasonAbsoluteForm, reasonConnect, reasonHostMismatch, reasonUpgrade, reasonPathInvalid,
		reasonQueryInvalid, reasonRouteUnknown, reasonPathNotAllowed, reasonMethodNotAllowed, reasonRateLimited, reasonConcurrency,
		reasonRequestTooLarge, reasonBodyInvalid, reasonBodyTimeout, reasonShuttingDown, reasonInternal, reasonTrailerNotAllowed} {
		knownReasons[r] = true
	}
}

// Upstream error kinds.
const (
	errKindTLS          = "tls"
	errKindTimeout      = "timeout"
	errKindOther        = "other"
	errKindTooLarge     = "response_too_large"
	errKindEncoded      = "response_encoded"
	errKindSwitch       = "response_protocol_switch"
	errKindStreamIdle   = "stream_idle_timeout"
	errKindClientWrite  = "client_write"
	errKindAborted      = "aborted"
	errKindHeaderTooBig = "response_header_too_large"
)

var knownErrorKinds = map[string]bool{errKindResolve: true, errKindAddressDenied: true, errKindConnect: true, errKindTLS: true,
	errKindTimeout: true, errKindOther: true, errKindTooLarge: true, errKindEncoded: true, errKindSwitch: true, errKindStreamIdle: true,
	errKindClientWrite: true, errKindAborted: true, errKindHeaderTooBig: true}

type statsCollector struct {
	mu         sync.Mutex
	doc        StatsDocument
	maxDenials int
	now        func() time.Time
}

func newStatsCollector(cfg *Config, digest string, maxDenials int, now func() time.Time) *statsCollector {
	c := &statsCollector{maxDenials: maxDenials, now: now}
	c.doc = StatsDocument{Version: StatsVersion, LaunchID: cfg.LaunchID, TargetID: cfg.TargetID, ConfigSHA256: digest,
		Listen: cfg.Listen.describe(), StartedAt: stamp(now()), Deadline: cfg.Deadline, State: "starting",
		Denied: map[string]uint64{}, Routes: map[string]*RouteStats{}, Denials: []DenialRecord{}}
	for _, r := range cfg.Routes {
		c.doc.Routes[r.Name] = &RouteStats{Upstream: r.upstreamAuthority(), Status: map[string]uint64{}, Errors: map[string]uint64{}}
	}
	return c
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func (l *Listen) describe() string {
	if l.Network == "unix" {
		return "unix:" + l.Path
	}
	return "tcp:" + l.ListenAuthority()
}

func (c *statsCollector) connection(accepted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if accepted {
		c.doc.Connections.Accepted++
	} else {
		c.doc.Connections.Rejected++
	}
}

func (c *statsCollector) request() {
	c.mu.Lock()
	c.doc.Requests.Total++
	c.mu.Unlock()
}

func (c *statsCollector) deny(reason, method, host, path string) {
	if !knownReasons[reason] {
		reason = reasonInternal
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.doc.Requests.Denied++
	c.doc.Denied[reason]++
	if len(c.doc.Denials) < c.maxDenials {
		c.doc.Denials = append(c.doc.Denials, DenialRecord{At: stamp(c.now()), Reason: reason, Method: sanitizeMethod(method),
			Host: sanitizeHost(host), Path: pathPrefix(path)})
	} else {
		c.doc.DenialsTruncated = true
	}
}

func (c *statsCollector) route(name string, f func(*RouteStats)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if r := c.doc.Routes[name]; r != nil {
		f(r)
	}
}

func (c *statsCollector) routeRequest(name string) {
	c.route(name, func(r *RouteStats) { r.Requests++ })
}

func (c *statsCollector) forwarded(name string, bytesIn int) {
	c.mu.Lock()
	c.doc.Requests.Forwarded++
	c.mu.Unlock()
	c.route(name, func(r *RouteStats) { r.Forwarded++; r.BytesIn += uint64(bytesIn) })
}

func (c *statsCollector) status(name string, code int) {
	class := "other"
	if code >= 100 && code < 600 {
		class = string(rune('0'+code/100)) + "xx"
	}
	c.route(name, func(r *RouteStats) { r.Status[class]++ })
}

func (c *statsCollector) routeError(name, kind string) {
	if !knownErrorKinds[kind] {
		kind = errKindOther
	}
	c.route(name, func(r *RouteStats) { r.Errors[kind]++ })
}

func (c *statsCollector) responseBytes(name string, n int, redactions int) {
	c.route(name, func(r *RouteStats) { r.BytesOut += uint64(n); r.Redactions += uint64(redactions) })
}

func (c *statsCollector) setHardening(h Hardening) {
	c.mu.Lock()
	c.doc.Hardening = h
	c.mu.Unlock()
}

func (c *statsCollector) setState(state, reason string, complete bool) {
	c.mu.Lock()
	c.doc.State, c.doc.StopReason, c.doc.Complete = state, reason, complete
	c.mu.Unlock()
}

// snapshot returns the document as JSON.
func (c *statsCollector) snapshot() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.doc.UpdatedAt = stamp(c.now())
	return json.MarshalIndent(&c.doc, "", "  ")
}

func sanitizeMethod(m string) string {
	switch m {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "TRACE":
		return m
	}
	return "OTHER"
}

func sanitizeHost(h string) string {
	if h == "" {
		return ""
	}
	if len(h) > 64 {
		return "invalid"
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte(".:-[]", c) >= 0) {
			return "invalid"
		}
	}
	return strings.ToLower(h)
}

// pathPrefix keeps at most the first two segments of the path, without the
// query, limited to 64 safe characters.
func pathPrefix(target string) string {
	if i := strings.IndexAny(target, "?#"); i >= 0 {
		target = target[:i]
	}
	if !strings.HasPrefix(target, "/") {
		return "(not-origin-form)"
	}
	parts := strings.SplitN(target[1:], "/", 3)
	if len(parts) > 2 {
		parts = parts[:2]
	}
	p := "/" + strings.Join(parts, "/")
	if len(p) > 64 {
		p = p[:64]
	}
	b := []byte(p)
	for i, c := range b {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("/._~-", c) >= 0) {
			b[i] = '_'
		}
	}
	return string(b)
}

// writeStatsFile replaces path atomically with a 0600 file.
func writeStatsFile(path string, data []byte) error {
	if len(data) > MaxStatsBytes {
		return errors.New("broker stats exceed their size bound")
	}
	var nonce [8]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmp := filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".tmp-"+hex.EncodeToString(nonce[:]))
	fd, err := unix.Open(tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return errors.New("broker stats file cannot be created")
	}
	f := os.NewFile(uintptr(fd), tmp)
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		os.Remove(tmp)
		return errors.New("broker stats file cannot be written")
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return errors.New("broker stats file cannot be replaced")
	}
	return nil
}

// ParseStats strictly decodes a stats document for the host agent.
func ParseStats(raw []byte) (*StatsDocument, error) {
	var d StatsDocument
	if err := decodeStrict(raw, MaxStatsBytes, &d); err != nil {
		return nil, err
	}
	if d.Version != StatsVersion || (d.State != "starting" && d.State != "running" && d.State != "stopped") ||
		len(d.Routes) > 16 || len(d.Denials) > 256 || len(d.Denied) > len(knownReasons) {
		return nil, errors.New("broker stats do not match " + StatsVersion)
	}
	for k := range d.Denied {
		if !knownReasons[k] {
			return nil, errors.New("broker stats hold an unknown denial reason")
		}
	}
	return &d, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ConfigVersion is the only accepted configuration version.
const ConfigVersion = "agentgate.broker.v1"

// MaxConfigBytes bounds the configuration document.
const MaxConfigBytes = 64 << 10

// MaxLifetime is the longest launch lifetime in the provisioning contract
// (a session allows 86400 seconds); the slack covers queueing before start.
const MaxLifetime = 86400*time.Second + 10*time.Minute

// Config is the complete, immutable broker configuration for one launch. It
// never contains a secret value: credentials are referenced by file or by an
// inherited descriptor.
type Config struct {
	Version   string    `json:"version"`
	LaunchID  string    `json:"launch_id"`
	TargetID  string    `json:"target_id"`
	Deadline  string    `json:"deadline"`
	Listen    Listen    `json:"listen"`
	StatsPath string    `json:"stats_path"`
	RunAs     *Identity `json:"run_as,omitempty"`
	Limits    *Limits   `json:"limits,omitempty"`
	Routes    []Route   `json:"routes"`
}

// Listen names the one endpoint the sandbox reaches.
type Listen struct {
	// Network is "tcp" (one exact private IPv4 address and port on the
	// launch's broker network) or "unix" (a socket on a per-launch volume).
	Network string `json:"network"`
	Address string `json:"address,omitempty"`
	Port    int    `json:"port,omitempty"`
	// Subnet is the per-launch broker network. The broker refuses to start
	// unless exactly one non-loopback interface holds Address with this prefix.
	Subnet    string `json:"subnet,omitempty"`
	Path      string `json:"path,omitempty"`
	SocketGID *int   `json:"socket_gid,omitempty"`
	// Authority is the exact Host header a unix-mode client sends.
	Authority string `json:"authority,omitempty"`
}

// Identity is the unprivileged user the broker serves as.
type Identity struct {
	UID int `json:"uid"`
	GID int `json:"gid"`
}

// Limits are optional; an absent field takes its documented default.
type Limits struct {
	MaxConnections         *int64 `json:"max_connections,omitempty"`
	MaxConcurrentRequests  *int64 `json:"max_concurrent_requests,omitempty"`
	RequestsPerMinute      *int64 `json:"requests_per_minute,omitempty"`
	Burst                  *int64 `json:"burst,omitempty"`
	MaxRequestBytes        *int64 `json:"max_request_bytes,omitempty"`
	MaxResponseBytes       *int64 `json:"max_response_bytes,omitempty"`
	MaxHeaderBytes         *int64 `json:"max_header_bytes,omitempty"`
	MaxHeaderCount         *int64 `json:"max_header_count,omitempty"`
	HeaderTimeoutSeconds   *int64 `json:"header_timeout_seconds,omitempty"`
	BodyTimeoutSeconds     *int64 `json:"body_timeout_seconds,omitempty"`
	UpstreamHeaderSeconds  *int64 `json:"upstream_header_timeout_seconds,omitempty"`
	StreamIdleSeconds      *int64 `json:"stream_idle_timeout_seconds,omitempty"`
	RequestTimeoutSeconds  *int64 `json:"request_timeout_seconds,omitempty"`
	WriteTimeoutSeconds    *int64 `json:"write_timeout_seconds,omitempty"`
	DNSCacheSeconds        *int64 `json:"dns_cache_seconds,omitempty"`
	ShutdownGraceSeconds   *int64 `json:"shutdown_grace_seconds,omitempty"`
	StatsIntervalSeconds   *int64 `json:"stats_interval_seconds,omitempty"`
	MaxDenialRecords       *int64 `json:"max_denial_records,omitempty"`
	ConnectTimeoutSeconds  *int64 `json:"connect_timeout_seconds,omitempty"`
	MaxUpstreamConnections *int64 `json:"max_upstream_connections,omitempty"`
}

// Route binds one path prefix on the broker to one upstream and one credential.
type Route struct {
	Name       string     `json:"name"`
	Upstream   Upstream   `json:"upstream"`
	Credential Credential `json:"credential"`
	Rules      []Rule     `json:"rules"`
}

// Upstream is one exact HTTPS origin.
type Upstream struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	BasePath string `json:"base_path,omitempty"`
	// PinSPKISHA256 optionally lists base64 SHA-256 digests of a certificate
	// SubjectPublicKeyInfo. A verified chain must contain one of them.
	PinSPKISHA256 []string `json:"pin_spki_sha256,omitempty"`
	// PrivateAddresses makes a private-by-design upstream reachable. When set,
	// every resolved address must be exactly one of these RFC 1918 or ULA
	// addresses; loopback, link-local (including 169.254.169.254), the broker
	// network and the host's own addresses stay refused.
	PrivateAddresses []string `json:"private_addresses,omitempty"`
}

// Credential says where the secret comes from and how it is injected.
type Credential struct {
	SecretFile   string            `json:"secret_file,omitempty"`
	SecretFD     *int              `json:"secret_fd,omitempty"`
	Header       string            `json:"header"`
	Scheme       string            `json:"scheme,omitempty"`
	Username     string            `json:"username,omitempty"`
	ExtraHeaders map[string]string `json:"extra_headers,omitempty"`
}

// Rule allows a set of methods on one route-relative path.
type Rule struct {
	Methods []string `json:"methods"`
	Path    string   `json:"path"`
	Match   string   `json:"match"`
}

// Settings are the resolved limits with defaults applied.
type Settings struct {
	MaxConnections         int
	MaxConcurrentRequests  int
	RequestsPerMinute      int
	Burst                  int
	MaxRequestBytes        int64
	MaxResponseBytes       int64
	MaxHeaderBytes         int
	MaxHeaderCount         int
	HeaderTimeout          time.Duration
	BodyTimeout            time.Duration
	UpstreamHeaderTimeout  time.Duration
	StreamIdleTimeout      time.Duration
	RequestTimeout         time.Duration
	WriteTimeout           time.Duration
	DNSCache               time.Duration
	ShutdownGrace          time.Duration
	StatsInterval          time.Duration
	MaxDenialRecords       int
	ConnectTimeout         time.Duration
	MaxUpstreamConnections int
}

type limitSpec struct {
	name     string
	field    func(*Limits) *int64
	def      int64
	min, max int64
}

var limitSpecs = []limitSpec{
	{"max_connections", func(l *Limits) *int64 { return l.MaxConnections }, 32, 1, 1024},
	{"max_concurrent_requests", func(l *Limits) *int64 { return l.MaxConcurrentRequests }, 16, 1, 1024},
	{"requests_per_minute", func(l *Limits) *int64 { return l.RequestsPerMinute }, 600, 1, 60000},
	{"burst", func(l *Limits) *int64 { return l.Burst }, 60, 1, 10000},
	{"max_request_bytes", func(l *Limits) *int64 { return l.MaxRequestBytes }, 16 << 20, 1 << 10, 256 << 20},
	{"max_response_bytes", func(l *Limits) *int64 { return l.MaxResponseBytes }, 256 << 20, 1 << 10, 4 << 30},
	{"max_header_bytes", func(l *Limits) *int64 { return l.MaxHeaderBytes }, 32 << 10, 4 << 10, 256 << 10},
	{"max_header_count", func(l *Limits) *int64 { return l.MaxHeaderCount }, 64, 8, 256},
	{"header_timeout_seconds", func(l *Limits) *int64 { return l.HeaderTimeoutSeconds }, 10, 1, 60},
	{"body_timeout_seconds", func(l *Limits) *int64 { return l.BodyTimeoutSeconds }, 60, 1, 3600},
	{"upstream_header_timeout_seconds", func(l *Limits) *int64 { return l.UpstreamHeaderSeconds }, 300, 1, 3600},
	{"stream_idle_timeout_seconds", func(l *Limits) *int64 { return l.StreamIdleSeconds }, 120, 1, 3600},
	{"request_timeout_seconds", func(l *Limits) *int64 { return l.RequestTimeoutSeconds }, 900, 1, 86400},
	{"write_timeout_seconds", func(l *Limits) *int64 { return l.WriteTimeoutSeconds }, 30, 1, 600},
	{"dns_cache_seconds", func(l *Limits) *int64 { return l.DNSCacheSeconds }, 30, 0, 300},
	{"shutdown_grace_seconds", func(l *Limits) *int64 { return l.ShutdownGraceSeconds }, 5, 0, 60},
	{"stats_interval_seconds", func(l *Limits) *int64 { return l.StatsIntervalSeconds }, 5, 1, 300},
	{"max_denial_records", func(l *Limits) *int64 { return l.MaxDenialRecords }, 64, 0, 256},
	{"connect_timeout_seconds", func(l *Limits) *int64 { return l.ConnectTimeoutSeconds }, 10, 1, 60},
	{"max_upstream_connections", func(l *Limits) *int64 { return l.MaxUpstreamConnections }, 16, 1, 256},
}

// maxBufferedBytes bounds max_concurrent_requests * max_request_bytes, since
// request bodies are buffered in full before anything is sent upstream.
const maxBufferedBytes = 1 << 30

var (
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	routePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
	labelPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	basePattern  = regexp.MustCompile(`^(/[A-Za-z0-9._~-]+)+$`)
)

// Allowed methods. CONNECT and TRACE are never allowed.
var allowedMethods = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true, http.MethodPut: true,
	http.MethodPatch: true, http.MethodDelete: true, http.MethodOptions: true,
}

// forbiddenInjected lists header names a credential rule may never set.
var forbiddenInjected = map[string]bool{
	"Host": true, "Content-Length": true, "Transfer-Encoding": true, "Connection": true, "Keep-Alive": true,
	"Proxy-Connection": true, "Te": true, "Trailer": true, "Upgrade": true, "Expect": true, "Cookie": true,
	"Cookie2": true, "Proxy-Authorization": true, "Proxy-Authenticate": true, "Accept-Encoding": true,
	"Content-Encoding": true, "Http2-Settings": true, "Forwarded": true, "Via": true, "Content-Type": true,
	"Date": true, "Range": true,
}

var forbiddenSuffixes = []string{".localhost", ".local", ".internal", ".home.arpa", ".arpa", ".onion", ".invalid", ".lan", ".intranet", ".corp", ".private"}

// ParseConfig strictly decodes a configuration document. It does not check the
// deadline against a clock; Validate does.
func ParseConfig(raw []byte) (*Config, error) {
	var c Config
	if err := decodeStrict(raw, MaxConfigBytes, &c); err != nil {
		return nil, fmt.Errorf("broker config: %w", err)
	}
	return &c, nil
}

// ConfigDigest is the SHA-256 of the exact configuration bytes.
func ConfigDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func cfgErr(field, reason string) error { return fmt.Errorf("broker config: %s: %s", field, reason) }

// Validate checks every field and returns the resolved settings. Errors name the
// field and never repeat a configured value.
func (c *Config) Validate(now time.Time) (Settings, error) {
	var s Settings
	if c.Version != ConfigVersion {
		return s, cfgErr("version", "must be "+ConfigVersion)
	}
	if !idPattern.MatchString(c.LaunchID) {
		return s, cfgErr("launch_id", "must match "+idPattern.String())
	}
	if !idPattern.MatchString(c.TargetID) {
		return s, cfgErr("target_id", "must match "+idPattern.String())
	}
	deadline, err := c.DeadlineTime()
	if err != nil {
		return s, err
	}
	if !deadline.After(now.Add(time.Second)) {
		return s, cfgErr("deadline", "is not in the future")
	}
	if deadline.After(now.Add(MaxLifetime)) {
		return s, cfgErr("deadline", "exceeds the maximum launch lifetime")
	}
	if err := c.Listen.validate(); err != nil {
		return s, err
	}
	if err := validStatsPath(c.StatsPath); err != nil {
		return s, err
	}
	if c.RunAs != nil {
		if c.RunAs.UID < 1 || c.RunAs.UID > 1<<31-2 || c.RunAs.GID < 1 || c.RunAs.GID > 1<<31-2 {
			return s, cfgErr("run_as", "uid and gid must be unprivileged ids")
		}
	}
	if s, err = c.settings(); err != nil {
		return s, err
	}
	if len(c.Routes) < 1 || len(c.Routes) > 16 {
		return s, cfgErr("routes", "must hold 1 to 16 routes")
	}
	names := map[string]bool{}
	fds := map[int]bool{}
	for i := range c.Routes {
		r := &c.Routes[i]
		field := fmt.Sprintf("routes[%d]", i)
		if err := r.validate(field); err != nil {
			return s, err
		}
		if c.Listen.Network == "tcp" {
			subnet := netip.MustParsePrefix(c.Listen.Subnet)
			for _, raw := range r.Upstream.PrivateAddresses {
				if subnet.Contains(netip.MustParseAddr(raw)) {
					return s, cfgErr(field+".upstream.private_addresses", "must not be inside the broker network")
				}
			}
		}
		if names[r.Name] {
			return s, cfgErr(field+".name", "is duplicated")
		}
		names[r.Name] = true
		// One secret file may back several routes (a secret whose metadata
		// lists several origins); each route still binds exactly one origin.
		// A descriptor can be read only once, so it is never shared.
		if r.Credential.SecretFile == "" {
			if fds[*r.Credential.SecretFD] {
				return s, cfgErr(field+".credential.secret_fd", "is shared with another route")
			}
			fds[*r.Credential.SecretFD] = true
		}
	}
	return s, nil
}

// DeadlineTime parses the deadline.
func (c *Config) DeadlineTime() (time.Time, error) {
	t, err := time.Parse(time.RFC3339, c.Deadline)
	if err != nil || len(c.Deadline) > 40 {
		return time.Time{}, cfgErr("deadline", "must be an RFC 3339 timestamp")
	}
	return t, nil
}

func (c *Config) settings() (Settings, error) {
	l := c.Limits
	if l == nil {
		l = &Limits{}
	}
	v := map[string]int64{}
	for _, spec := range limitSpecs {
		value := spec.def
		if p := spec.field(l); p != nil {
			value = *p
		}
		if value < spec.min || value > spec.max {
			return Settings{}, cfgErr("limits."+spec.name, fmt.Sprintf("must be between %d and %d", spec.min, spec.max))
		}
		v[spec.name] = value
	}
	if v["max_concurrent_requests"] > v["max_connections"] {
		return Settings{}, cfgErr("limits.max_concurrent_requests", "exceeds max_connections")
	}
	if v["max_concurrent_requests"]*v["max_request_bytes"] > maxBufferedBytes {
		return Settings{}, cfgErr("limits.max_request_bytes", "times max_concurrent_requests exceeds 1 GiB of buffered bodies")
	}
	sec := func(name string) time.Duration { return time.Duration(v[name]) * time.Second }
	return Settings{
		MaxConnections:         int(v["max_connections"]),
		MaxConcurrentRequests:  int(v["max_concurrent_requests"]),
		RequestsPerMinute:      int(v["requests_per_minute"]),
		Burst:                  int(v["burst"]),
		MaxRequestBytes:        v["max_request_bytes"],
		MaxResponseBytes:       v["max_response_bytes"],
		MaxHeaderBytes:         int(v["max_header_bytes"]),
		MaxHeaderCount:         int(v["max_header_count"]),
		HeaderTimeout:          sec("header_timeout_seconds"),
		BodyTimeout:            sec("body_timeout_seconds"),
		UpstreamHeaderTimeout:  sec("upstream_header_timeout_seconds"),
		StreamIdleTimeout:      sec("stream_idle_timeout_seconds"),
		RequestTimeout:         sec("request_timeout_seconds"),
		WriteTimeout:           sec("write_timeout_seconds"),
		DNSCache:               sec("dns_cache_seconds"),
		ShutdownGrace:          sec("shutdown_grace_seconds"),
		StatsInterval:          sec("stats_interval_seconds"),
		MaxDenialRecords:       int(v["max_denial_records"]),
		ConnectTimeout:         sec("connect_timeout_seconds"),
		MaxUpstreamConnections: int(v["max_upstream_connections"]),
	}, nil
}

func (l *Listen) validate() error {
	switch l.Network {
	case "tcp":
		if l.Path != "" || l.SocketGID != nil || l.Authority != "" {
			return cfgErr("listen", "tcp mode takes only address, port and subnet")
		}
		a, err := netip.ParseAddr(l.Address)
		if err != nil || !a.Is4() || a.String() != l.Address || !a.IsPrivate() {
			return cfgErr("listen.address", "must be one canonical private (RFC 1918) IPv4 address")
		}
		if l.Port < 1024 || l.Port > 65535 {
			return cfgErr("listen.port", "must be between 1024 and 65535")
		}
		p, err := netip.ParsePrefix(l.Subnet)
		if err != nil || p.Masked() != p || !p.Addr().Is4() || p.Bits() < 16 || p.Bits() > 30 || !p.Contains(a) {
			return cfgErr("listen.subnet", "must be the canonical /16../30 IPv4 network that contains listen.address")
		}
		if a == p.Addr() || a == lastAddr(p) {
			return cfgErr("listen.address", "must not be the network or broadcast address")
		}
		if !rfc1918(p.Addr()) || !rfc1918(lastAddr(p)) {
			return cfgErr("listen.subnet", "must be inside one RFC 1918 range")
		}
	case "unix":
		if l.Address != "" || l.Port != 0 || l.Subnet != "" {
			return cfgErr("listen", "unix mode takes only path, socket_gid and authority")
		}
		if !cleanAbs(l.Path) || len(l.Path) > 100 || filepath.Base(l.Path) == "/" {
			return cfgErr("listen.path", "must be a clean absolute path of at most 100 bytes")
		}
		if l.SocketGID == nil || *l.SocketGID < 0 || *l.SocketGID > 1<<31-2 {
			return cfgErr("listen.socket_gid", "is required and must be a valid gid")
		}
		if l.Authority == "" {
			l.Authority = "agentgate-broker"
		}
		if !hostName(l.Authority, 1) {
			return cfgErr("listen.authority", "must be a lowercase DNS-style name")
		}
	default:
		return cfgErr("listen.network", `must be "tcp" or "unix"`)
	}
	return nil
}

// ListenAuthority is the exact Host header a client must send.
func (l *Listen) ListenAuthority() string {
	if l.Network == "unix" {
		if l.Authority == "" {
			return "agentgate-broker"
		}
		return l.Authority
	}
	return netip.AddrPortFrom(netip.MustParseAddr(l.Address), uint16(l.Port)).String()
}

func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func cleanAbs(p string) bool {
	return p != "" && filepath.IsAbs(p) && filepath.Clean(p) == p && !strings.ContainsAny(p, "\x00\n\r")
}

func validStatsPath(p string) error {
	if !cleanAbs(p) || len(p) > 1024 || !strings.HasSuffix(p, ".json") || filepath.Dir(p) == p {
		return cfgErr("stats_path", "must be a clean absolute path ending in .json")
	}
	return nil
}

// hostName validates a lowercase DNS name with at least minLabels labels.
func hostName(h string, minLabels int) bool {
	if h == "" || len(h) > 253 || strings.HasSuffix(h, ".") {
		return false
	}
	labels := strings.Split(h, ".")
	if len(labels) < minLabels {
		return false
	}
	for _, label := range labels {
		if !labelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func (r *Route) validate(field string) error {
	if !routePattern.MatchString(r.Name) {
		return cfgErr(field+".name", "must match "+routePattern.String())
	}
	u := &r.Upstream
	if _, err := netip.ParseAddr(u.Host); err == nil {
		return cfgErr(field+".upstream.host", "must be a DNS name, not an address literal")
	}
	if !hostName(u.Host, 2) {
		return cfgErr(field+".upstream.host", "must be a lowercase DNS name with at least two labels")
	}
	labels := strings.Split(u.Host, ".")
	tld := labels[len(labels)-1]
	if strings.Trim(tld, "0123456789") == "" || strings.HasPrefix(tld, "0x") {
		return cfgErr(field+".upstream.host", "must not end in a numeric label")
	}
	if u.Host == "localhost" || hasForbiddenSuffix(u.Host) {
		return cfgErr(field+".upstream.host", "names a local or reserved domain")
	}
	if u.Port == 0 {
		u.Port = 443
	}
	if u.Port < 1 || u.Port > 65535 {
		return cfgErr(field+".upstream.port", "must be between 1 and 65535")
	}
	if u.BasePath != "" {
		if !basePattern.MatchString(u.BasePath) || len(u.BasePath) > 256 {
			return cfgErr(field+".upstream.base_path", "must be empty or /segment[/segment...] without a trailing slash")
		}
		for _, seg := range strings.Split(u.BasePath[1:], "/") {
			if seg == "." || seg == ".." {
				return cfgErr(field+".upstream.base_path", "must not contain dot segments")
			}
		}
	}
	if len(u.PinSPKISHA256) > 8 {
		return cfgErr(field+".upstream.pin_spki_sha256", "holds at most 8 pins")
	}
	pins := map[string]bool{}
	for _, pin := range u.PinSPKISHA256 {
		raw, err := base64.StdEncoding.Strict().DecodeString(pin)
		if err != nil || len(raw) != sha256.Size || pins[pin] {
			return cfgErr(field+".upstream.pin_spki_sha256", "entries must be unique base64 SHA-256 digests")
		}
		pins[pin] = true
	}
	if len(u.PrivateAddresses) > 4 {
		return cfgErr(field+".upstream.private_addresses", "holds at most 4 addresses")
	}
	exact := map[string]bool{}
	for _, raw := range u.PrivateAddresses {
		a, err := netip.ParseAddr(raw)
		if err != nil || a.String() != raw || exact[raw] || ClassifyAddress(a) != ClassPrivate || a.Is4In6() {
			return cfgErr(field+".upstream.private_addresses", "entries must be unique canonical RFC 1918 or ULA addresses")
		}
		exact[raw] = true
	}
	if err := r.Credential.validate(field + ".credential"); err != nil {
		return err
	}
	if len(r.Rules) < 1 || len(r.Rules) > 64 {
		return cfgErr(field+".rules", "must hold 1 to 64 rules")
	}
	for j, rule := range r.Rules {
		rf := fmt.Sprintf("%s.rules[%d]", field, j)
		if len(rule.Methods) < 1 || len(rule.Methods) > len(allowedMethods) {
			return cfgErr(rf+".methods", "must list allowed methods")
		}
		seen := map[string]bool{}
		for _, m := range rule.Methods {
			if !allowedMethods[m] || seen[m] {
				return cfgErr(rf+".methods", "entries must be unique and among GET HEAD POST PUT PATCH DELETE OPTIONS")
			}
			seen[m] = true
		}
		if _, ok := decodePath(rule.Path); !ok || strings.Contains(rule.Path, "%") || len(rule.Path) > 512 {
			return cfgErr(rf+".path", "must be a canonical absolute path without percent-encoding")
		}
		if rule.Match != "exact" && rule.Match != "prefix" {
			return cfgErr(rf+".match", `must be "exact" or "prefix"`)
		}
	}
	return nil
}

func hasForbiddenSuffix(h string) bool {
	for _, s := range forbiddenSuffixes {
		if strings.HasSuffix(h, s) || h == s[1:] {
			return true
		}
	}
	return false
}

func (c *Credential) validate(field string) error {
	if (c.SecretFile == "") == (c.SecretFD == nil) {
		return cfgErr(field, "needs exactly one of secret_file or secret_fd")
	}
	if c.SecretFile != "" && (!cleanAbs(c.SecretFile) || len(c.SecretFile) > 1024) {
		return cfgErr(field+".secret_file", "must be a clean absolute path")
	}
	if c.SecretFD != nil && (*c.SecretFD < 3 || *c.SecretFD > 1023) {
		return cfgErr(field+".secret_fd", "must be an inherited descriptor between 3 and 1023")
	}
	if !token(c.Header) || len(c.Header) > 64 {
		return cfgErr(field+".header", "must be an HTTP header name")
	}
	name := http.CanonicalHeaderKey(c.Header)
	if forbiddenInjected[name] || strings.HasPrefix(name, "X-Forwarded-") || strings.HasPrefix(name, "Proxy-") {
		return cfgErr(field+".header", "names a header the broker never injects")
	}
	switch c.Scheme {
	case "":
		if c.Username != "" {
			return cfgErr(field+".username", "is only valid with the Basic scheme")
		}
	case "Bearer":
		if name != "Authorization" || c.Username != "" {
			return cfgErr(field+".scheme", "Bearer requires the Authorization header and no username")
		}
	case "Basic":
		if name != "Authorization" {
			return cfgErr(field+".scheme", "Basic requires the Authorization header")
		}
		if c.Username == "" || len(c.Username) > 64 || !visibleASCII(c.Username) || strings.Contains(c.Username, ":") {
			return cfgErr(field+".username", "Basic requires a visible ASCII username without a colon")
		}
	default:
		return cfgErr(field+".scheme", `must be "", "Bearer" or "Basic"`)
	}
	if len(c.ExtraHeaders) > 8 {
		return cfgErr(field+".extra_headers", "holds at most 8 headers")
	}
	for k, v := range c.ExtraHeaders {
		ck := http.CanonicalHeaderKey(k)
		if !token(k) || len(k) > 64 || forbiddenInjected[ck] || ck == name || ck == "Authorization" || ck == "X-Api-Key" ||
			strings.HasPrefix(ck, "X-Forwarded-") || strings.HasPrefix(ck, "Proxy-") {
			return cfgErr(field+".extra_headers", "names a header the broker never injects")
		}
		if v == "" || len(v) > 256 || strings.TrimSpace(v) != v || !printableASCII(v) {
			return cfgErr(field+".extra_headers", "values must be 1 to 256 printable ASCII characters")
		}
	}
	return nil
}

// token reports whether s is an RFC 9110 token.
func token(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !tchar(s[i]) {
			return false
		}
	}
	return true
}

func tchar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

func visibleASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func rfc1918(a netip.Addr) bool {
	for _, p := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if netip.MustParsePrefix(p).Contains(a) {
			return true
		}
	}
	return false
}

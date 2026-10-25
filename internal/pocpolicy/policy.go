// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package pocpolicy implements only the experimental SSH network configuration.
// It cannot authorize normal product admission or other policy controls.
package pocpolicy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"alloyium.local/kernel-poc/internal/netrules"
)

type DNS struct {
	Resolvers []string `json:"resolvers"`
	Protocols []string `json:"protocols"`
	Port      int      `json:"port"`
}
type WebRule struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}
type Web struct {
	Destination string    `json:"destination"`
	Rules       []WebRule `json:"rules"`
}
type Taskboard struct {
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	TaskID   int    `json:"task_id"`
}

// Broker is the exact endpoint of one launch's credential broker. It takes
// the guard's single exact private TCP exception that the taskboard holds
// otherwise: a document names the taskboard or a broker, never both, until the
// BPF policy supports several exact endpoints (see docs/BROKER.md).
type Broker struct {
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}

// Endpoint is the document's one exact private TCP exception.
type Endpoint struct {
	Kind     string `json:"kind"` // "taskboard" or "broker"
	Address  string `json:"address"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	RuleID   string `json:"rule_id"`
}

type Document struct {
	Version string `json:"version"`
	Default string `json:"default"`
	IPv6    string `json:"ipv6"`
	DNS     DNS    `json:"dns"`
	Web     Web    `json:"web"`
	// Taskboard is omitted only when a launch document carries a broker
	// instead; every other document holds it, so existing digests are unchanged.
	Taskboard       Taskboard `json:"taskboard,omitzero"`
	Broker          *Broker   `json:"broker,omitempty"`
	DurationSeconds int       `json:"duration_seconds"`
	// Mode is empty for the one-command SSH POC, whose window stays exactly 25
	// seconds. A launch document names "oneshot" or "session"; duration_seconds
	// is then the launch lifetime, the hard cap in the kernel policy expiry.
	Mode string `json:"mode,omitempty"`
	// Version two documents also carry the host controls below.
	Filesystem *Filesystem `json:"filesystem,omitempty"`
	Process    *Process    `json:"process,omitempty"`
}

// Parse rejects unknown fields, duplicate keys, trailing values, and invalid policy.
func Parse(raw []byte) (Document, error) {
	var d Document
	if len(raw) > 16384 {
		return d, errors.New("network policy exceeds 16384 bytes")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueValue(dec); err != nil {
		return d, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return d, errors.New("network policy requires one JSON object")
	}
	dec = json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return d, err
	}
	return d, d.Validate()
}
func uniqueValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if delim != '{' && delim != '[' {
		return errors.New("unexpected JSON delimiter")
	}
	keys := map[string]bool{}
	for dec.More() {
		if delim == '{' {
			key, err := dec.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || keys[name] {
				return errors.New("duplicate JSON key")
			}
			keys[name] = true
		}
		if err := uniqueValue(dec); err != nil {
			return err
		}
	}
	_, err = dec.Token()
	return err
}
func publicIPv4(raw string) bool {
	a, err := netip.ParseAddr(raw)
	if err != nil || !a.Is4() || a.String() != raw || !a.IsGlobalUnicast() {
		return false
	}
	for _, s := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4"} {
		if netip.MustParsePrefix(s).Contains(a) {
			return false
		}
	}
	return true
}
func (d Document) Validate() error {
	if (d.Version != VersionV1 && d.Version != VersionV2) || d.Default != "deny" || d.IPv6 != "deny" || (d.Mode == "" && d.DurationSeconds != 25) {
		return errors.New("network policy requires version " + VersionV1 + " or " + VersionV2 + ", deny defaults, and duration_seconds 25")
	}
	if d.Mode != "" {
		if d.Version != VersionV2 {
			return errors.New("a launch mode requires version " + VersionV2 + " with host controls")
		}
		if err := ValidateLifetime(d.Mode, d.DurationSeconds); err != nil {
			return err
		}
	}
	if err := d.validateHostControls(); err != nil {
		return err
	}
	if len(d.DNS.Resolvers) < 1 || len(d.DNS.Resolvers) > 3 || d.DNS.Port != 53 || len(d.DNS.Protocols) != 2 ||
		!((d.DNS.Protocols[0] == "udp" && d.DNS.Protocols[1] == "tcp") ||
			(d.DNS.Protocols[0] == "tcp" && d.DNS.Protocols[1] == "udp")) {
		return errors.New("DNS requires 1..3 public IPv4 resolvers, protocols [udp,tcp], and port 53")
	}
	seen := map[string]bool{}
	for _, ip := range d.DNS.Resolvers {
		if !publicIPv4(ip) || seen[ip] {
			return errors.New("DNS resolver must be a unique public IPv4 address")
		}
		seen[ip] = true
	}
	if d.Web.Destination != "public-ipv4" || d.Web.Rules == nil || len(d.Web.Rules) > 3 {
		return errors.New("web requires public-ipv4 and an explicit rules array")
	}
	seen = map[string]bool{}
	for _, r := range d.Web.Rules {
		key := fmt.Sprintf("%s:%d", r.Protocol, r.Port)
		if seen[key] || !(r.Protocol == "tcp" && (r.Port == 80 || r.Port == 443) || r.Protocol == "udp" && r.Port == 443) {
			return errors.New("web rules support unique TCP80, TCP443, and optional UDP443 only")
		}
		seen[key] = true
	}
	return d.validateEndpoint()
}

// Broker endpoint bounds: the broker refuses a privileged listen port.
const (
	BrokerMinPort = 1024
	BrokerMaxPort = 65535
)

var metadataAddress = netip.MustParseAddr("169.254.169.254")

// ValidBrokerEndpoint checks one broker endpoint: a canonical private
// (RFC 1918) IPv4 address that is not loopback, link-local or a metadata
// address, TCP, and a port the broker can bind unprivileged.
func ValidBrokerEndpoint(address, protocol string, port int) error {
	a, err := netip.ParseAddr(address)
	if err != nil || !a.Is4() || a.String() != address || !a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() ||
		a == metadataAddress || protocol != "tcp" || port < BrokerMinPort || port > BrokerMaxPort {
		return fmt.Errorf("broker requires one canonical private IPv4 TCP endpoint (not loopback, link-local or metadata) with a port %d..%d", BrokerMinPort, BrokerMaxPort)
	}
	return nil
}

// validateEndpoint enforces the single exact-endpoint slot: the taskboard or a
// broker, never both and never neither.
func (d Document) validateEndpoint() error {
	taskboard := d.Taskboard != (Taskboard{})
	switch {
	case taskboard && d.Broker != nil:
		return errors.New("a policy has exactly one exact private endpoint: the taskboard or a broker, not both")
	case d.Broker != nil:
		if d.Mode == "" {
			return errors.New("a broker endpoint belongs to one launch; it requires a launch mode")
		}
		return ValidBrokerEndpoint(d.Broker.Address, d.Broker.Protocol, d.Broker.Port)
	}
	a, err := netip.ParseAddr(d.Taskboard.Address)
	if err != nil || !a.Is4() || a.String() != d.Taskboard.Address || !a.IsPrivate() || d.Taskboard.Protocol != "tcp" || d.Taskboard.Port < 1 || d.Taskboard.Port > 65535 || d.Taskboard.TaskID < 1 {
		return errors.New("taskboard requires one canonical private IPv4 TCP endpoint and positive task_id")
	}
	return nil
}

// Endpoint names the document's one exact private exception and the rule
// that Compile emits for it.
func (d Document) Endpoint() Endpoint {
	if d.Broker != nil {
		return Endpoint{Kind: "broker", Address: d.Broker.Address, Protocol: d.Broker.Protocol, Port: d.Broker.Port, RuleID: "broker-exact"}
	}
	return Endpoint{Kind: "taskboard", Address: d.Taskboard.Address, Protocol: d.Taskboard.Protocol, Port: d.Taskboard.Port, RuleID: "taskboard-exact"}
}

// WithBroker returns the launch document with a broker endpoint in the
// single exact-endpoint slot. The taskboard exception is removed: the guard
// allows one exact private endpoint, and the broker's is the one this launch
// needs. Only a launch document (with a mode) can carry a broker.
func (d Document) WithBroker(address string, port int) (Document, error) {
	if d.Mode == "" {
		return d, errors.New("a broker endpoint requires a launch document")
	}
	if err := ValidBrokerEndpoint(address, "tcp", port); err != nil {
		return d, err
	}
	out := d
	out.Taskboard = Taskboard{}
	out.Broker = &Broker{Address: address, Protocol: "tcp", Port: port}
	return out, out.Validate()
}

// Launch modes and their lifetime bounds in seconds. The lifetime is the hard
// cap: the kernel policy expires at it and the host kills the domain at it.
const (
	ModeOneshot        = "oneshot"
	ModeSession        = "session"
	OneshotMinSeconds  = 1
	OneshotMaxSeconds  = 3600
	SessionMinSeconds  = 60
	SessionMaxSeconds  = 86400
	legacyWindowSecond = 25
)

// ValidateLifetime checks one launch mode and lifetime against the contract.
func ValidateLifetime(mode string, seconds int) error {
	switch mode {
	case ModeOneshot:
		if seconds < OneshotMinSeconds || seconds > OneshotMaxSeconds {
			return fmt.Errorf("a oneshot launch lifetime must be %d..%d seconds", OneshotMinSeconds, OneshotMaxSeconds)
		}
	case ModeSession:
		if seconds < SessionMinSeconds || seconds > SessionMaxSeconds {
			return fmt.Errorf("a session launch lifetime must be %d..%d seconds", SessionMinSeconds, SessionMaxSeconds)
		}
	default:
		return errors.New("launch mode must be oneshot or session")
	}
	return nil
}

// IsLaunch reports whether the document is a launch document, not an SSH command policy.
func (d Document) IsLaunch() bool { return d.Mode != "" }

// ForLaunch returns the launch document for a stored profile document: the
// same rules with the launch mode and lifetime. A document that already names
// a mode must name exactly this one; nothing else changes.
func (d Document) ForLaunch(mode string, seconds int) (Document, error) {
	if err := ValidateLifetime(mode, seconds); err != nil {
		return d, err
	}
	if d.Mode != "" && (d.Mode != mode || d.DurationSeconds != seconds) {
		return d, errors.New("the policy names a different launch mode or lifetime than the launch")
	}
	if d.Mode == "" && d.DurationSeconds != legacyWindowSecond {
		return d, errors.New("a profile document must carry duration_seconds 25 or the launch lifetime")
	}
	out := d
	out.Mode, out.DurationSeconds = mode, seconds
	return out, out.Validate()
}

// Shorten returns a launch document whose lifetime is seconds, which may only
// be shorter than or equal to the signed lifetime. The host uses it when the
// signed expiry leaves less than the full lifetime: ForLaunch refuses a
// different lifetime for a document that already names a mode.
func (d Document) Shorten(mode string, seconds int) (Document, error) {
	if d.Mode == "" || d.Mode != mode {
		return d, errors.New("only a launch document of the same mode can be shortened")
	}
	if seconds > d.DurationSeconds {
		return d, errors.New("a launch lifetime can be shortened, never extended")
	}
	out := d
	out.DurationSeconds = seconds
	return out, out.Validate()
}

func (d Document) Digest() string {
	raw, _ := json.Marshal(d)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func addrBytes(raw string) [16]byte {
	var out [16]byte
	a := netip.MustParseAddr(raw).As4()
	copy(out[:4], a[:])
	return out
}

// Compile uses the existing kernel ABI and its independent private-address guard.
// This is separate from netrules.Compile and normal product policy validation.
func (d Document) Compile(now, deadline uint64) (netrules.Compiled, error) {
	var out netrules.Compiled
	if err := d.Validate(); err != nil {
		return out, err
	}
	if now == 0 || now >= deadline {
		return out, errors.New("network policy requires a live bounded deadline")
	}
	// The single exact private exception: the taskboard, or a launch's broker.
	endpoint := d.Endpoint()
	out.Policy = netrules.Policy{Generation: 1, ExpiresNS: deadline, PilotMode: 1, PilotFamily: netrules.IPv4, PilotPort: uint16(endpoint.Port), PilotAddress: addrBytes(endpoint.Address)}
	add := func(id, ip string, bits uint16, protocol uint8, port int, effect uint8) {
		out.RuleIDs = append(out.RuleIDs, id)
		r := netrules.Rule{Address: addrBytes(ip), PrefixBits: bits, Family: netrules.IPv4, Protocol: protocol, PortFrom: uint16(port), PortTo: uint16(port), Effect: effect, ExpiresNS: deadline, Index: uint32(len(out.RuleIDs))}
		out.Policy.Rules[out.Policy.Count] = r
		out.Policy.Count++
	}
	for i, ip := range d.DNS.Resolvers {
		add(fmt.Sprintf("dns-%d-udp", i+1), ip, 32, netrules.UDP, 53, netrules.Allow)
		add(fmt.Sprintf("dns-%d-tcp", i+1), ip, 32, netrules.TCP, 53, netrules.Allow)
	}
	for _, r := range d.Web.Rules {
		proto := uint8(netrules.TCP)
		if r.Protocol == "udp" {
			proto = netrules.UDP
		}
		add(fmt.Sprintf("public-%s-%d", r.Protocol, r.Port), "0.0.0.0", 0, proto, r.Port, netrules.Allow)
		// Documentation ranges are not public destinations. The independent BPF
		// boundary already denies private, bridge, loopback and link-local ranges.
		for i, ip := range []string{"192.0.2.0", "198.51.100.0", "203.0.113.0"} {
			add(fmt.Sprintf("reserved-%s-%d-%d", r.Protocol, r.Port, i), ip, 24, proto, r.Port, netrules.Deny)
		}
	}
	add(endpoint.RuleID, endpoint.Address, 32, netrules.TCP, endpoint.Port, netrules.Allow)
	return out, nil
}

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
type Document struct {
	Version         string    `json:"version"`
	Default         string    `json:"default"`
	IPv6            string    `json:"ipv6"`
	DNS             DNS       `json:"dns"`
	Web             Web       `json:"web"`
	Taskboard       Taskboard `json:"taskboard"`
	DurationSeconds int       `json:"duration_seconds"`
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
	if (d.Version != VersionV1 && d.Version != VersionV2) || d.Default != "deny" || d.IPv6 != "deny" || d.DurationSeconds != 25 {
		return errors.New("network policy requires version " + VersionV1 + " or " + VersionV2 + ", deny defaults, and duration_seconds 25")
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
	a, err := netip.ParseAddr(d.Taskboard.Address)
	if err != nil || !a.Is4() || a.String() != d.Taskboard.Address || !a.IsPrivate() || d.Taskboard.Protocol != "tcp" || d.Taskboard.Port < 1 || d.Taskboard.Port > 65535 || d.Taskboard.TaskID < 1 {
		return errors.New("taskboard requires one canonical private IPv4 TCP endpoint and positive task_id")
	}
	return nil
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
	out.Policy = netrules.Policy{Generation: 1, ExpiresNS: deadline, PilotMode: 1, PilotFamily: netrules.IPv4, PilotPort: uint16(d.Taskboard.Port), PilotAddress: addrBytes(d.Taskboard.Address)}
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
	add("taskboard-exact", d.Taskboard.Address, 32, netrules.TCP, d.Taskboard.Port, netrules.Allow)
	return out, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
)

// A secret's injection policy says where and how the host's broker may use
// it: the upstream origins, the header and scheme it is written in, the
// non-secret headers set with it, the request headers forwarded, and the
// method and path rules. The client that seals the value computes the
// policy's digest from what the operator intended and seals it with the value
// (secretseal binds it into the HPKE associated data and the receipt), the
// host stores the policy with the value, and the host builds every broker
// configuration from its stored policy, refusing a launch whose settings
// differ from it. So the service, which relays the policy, cannot send a
// stored credential anywhere or in any way the operator did not seal.

// SecretPolicyFormat names the canonical policy encoding.
const SecretPolicyFormat = "agentgate.secret-policy.v1"

// SecretPolicy is the normalized injection policy. Build it with
// NewSecretPolicy; its Canonical bytes and Digest are the same in every
// implementation (internal/hostproto here, web/src/secretseal.ts in the UI).
type SecretPolicy struct {
	Upstreams      []PolicyUpstream `json:"upstreams"`
	Header         string           `json:"header"`
	Scheme         string           `json:"scheme"`
	Username       string           `json:"username"`
	ExtraHeaders   []PolicyHeader   `json:"extra_headers"`
	ForwardHeaders []string         `json:"forward_headers"`
	Rules          []BrokerRule     `json:"rules"`
	Wildcard       bool             `json:"wildcard"`
}

// PolicyUpstream is one exact HTTPS origin. BasePath and PrivateAddresses are
// part of the encoding so a later API cannot add them unsealed; the secrets
// API sets neither today.
type PolicyUpstream struct {
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	BasePath         string   `json:"base_path"`
	PrivateAddresses []string `json:"private_addresses"`
}

// PolicyHeader is one non-secret header the broker sets.
type PolicyHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// MaxForwardHeaders bounds a secret's forward_headers.
const MaxForwardHeaders = 16

// NewSecretPolicy normalizes a secret's settings into its policy:
// upstreams keep their order (the first is the route the agent's variable
// names) with an explicit port (443 by default); header and every extra and
// forwarded header name are lower case; an empty scheme with an
// Authorization header is Bearer, the broker's own default; extra headers are
// sorted by name and forwarded headers are sorted; rule methods are in
// BrokerMethods order and the rules keep theirs. Values that two spellings
// share (x and x:443, Authorization and authorization) give one policy;
// anything ambiguous (a duplicate after normalizing) is refused. It checks
// shape only: CheckInjection and the broker's own validator check the rest.
func NewSecretPolicy(upstreams []string, header, scheme, username string, rules []BrokerRule, extra map[string]string, forward []string, wildcard bool) (SecretPolicy, error) {
	p := SecretPolicy{Upstreams: []PolicyUpstream{}, Header: strings.ToLower(header), Scheme: scheme, Username: username,
		ExtraHeaders: []PolicyHeader{}, ForwardHeaders: []string{}, Rules: []BrokerRule{}, Wildcard: wildcard}
	if len(upstreams) < 1 || len(upstreams) > 8 || !HeaderPattern.MatchString(header) {
		return p, errors.New("hostproto: a secret policy needs 1 to 8 upstreams and a header name")
	}
	seen := map[string]bool{}
	for _, u := range upstreams {
		if len(u) > 253 || !UpstreamPattern.MatchString(u) {
			return p, errors.New("hostproto: a policy upstream is an exact lowercase host name, optionally with a port")
		}
		host, port := u, 443
		if h, ps, err := net.SplitHostPort(u); err == nil {
			n, err := strconv.Atoi(ps)
			if err != nil || n < 1 || n > 65535 {
				return p, errors.New("hostproto: a policy upstream port is 1 to 65535")
			}
			host, port = h, n
		}
		key := host + ":" + strconv.Itoa(port)
		if seen[key] {
			return p, errors.New("hostproto: a policy upstream is listed twice")
		}
		seen[key] = true
		p.Upstreams = append(p.Upstreams, PolicyUpstream{Host: host, Port: port, BasePath: "", PrivateAddresses: []string{}})
	}
	if p.Scheme == "" && p.Header == "authorization" {
		p.Scheme = "Bearer"
	}
	names := map[string]bool{}
	for k, v := range extra {
		lower := strings.ToLower(k)
		if !HeaderPattern.MatchString(k) {
			return p, errors.New("hostproto: an extra header is a header name")
		}
		if names[lower] {
			return p, errors.New("hostproto: an extra header is listed twice")
		}
		names[lower] = true
		p.ExtraHeaders = append(p.ExtraHeaders, PolicyHeader{Name: lower, Value: v})
	}
	sort.Slice(p.ExtraHeaders, func(i, j int) bool { return p.ExtraHeaders[i].Name < p.ExtraHeaders[j].Name })
	if len(forward) > MaxForwardHeaders {
		return p, errors.New("hostproto: at most 16 forward headers")
	}
	fw := map[string]bool{}
	for _, f := range forward {
		lower := strings.ToLower(f)
		if !HeaderPattern.MatchString(f) || fw[lower] {
			return p, errors.New("hostproto: forward headers are unique header names")
		}
		fw[lower] = true
		p.ForwardHeaders = append(p.ForwardHeaders, lower)
	}
	sort.Strings(p.ForwardHeaders)
	if len(rules) > MaxBrokerRules {
		return p, errors.New("hostproto: at most 64 rules")
	}
	for _, r := range rules {
		methods := []string{}
		for _, m := range BrokerMethods {
			n := 0
			for _, x := range r.Methods {
				if x == m {
					n++
				}
			}
			if n > 1 {
				return p, errors.New("hostproto: a rule method is listed twice")
			}
			if n == 1 {
				methods = append(methods, m)
			}
		}
		if len(methods) != len(r.Methods) {
			return p, errors.New("hostproto: rule methods are among GET HEAD POST PUT PATCH DELETE OPTIONS")
		}
		p.Rules = append(p.Rules, BrokerRule{Methods: methods, Path: r.Path, Match: r.Match})
	}
	if wildcard && (len(p.Rules) != 1 || len(p.Rules[0].Methods) != len(BrokerMethods) || p.Rules[0].Path != "/" || p.Rules[0].Match != "prefix") {
		return p, errors.New("hostproto: a wildcard policy holds exactly the rule every method on prefix /")
	}
	return p, nil
}

// lp is the length-prefixed encoding secretseal uses: a big-endian uint32
// length before each field.
func lp(fields ...[]byte) []byte {
	var b bytes.Buffer
	for _, f := range fields {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		b.Write(n[:])
		b.Write(f)
	}
	return b.Bytes()
}

func lpStrings(values []string) []byte {
	fields := make([][]byte, len(values))
	for i, v := range values {
		fields[i] = []byte(v)
	}
	return lp(fields...)
}

// Canonical is the policy's one byte encoding: nested length-prefixed fields
//
//	lp(format,
//	   lp(lp(host, port, base_path, lp(private_address...))...),
//	   header, scheme, username,
//	   lp(lp(name, value)...),
//	   lp(forward_header...),
//	   lp(lp(lp(method...), path, match)...),
//	   "true" | "false")
//
// with the port in decimal. An empty list is an empty field.
func (p SecretPolicy) Canonical() []byte {
	ups := make([][]byte, len(p.Upstreams))
	for i, u := range p.Upstreams {
		addrs := append([]string(nil), u.PrivateAddresses...)
		sort.Strings(addrs)
		ups[i] = lp([]byte(u.Host), []byte(strconv.Itoa(u.Port)), []byte(u.BasePath), lpStrings(addrs))
	}
	extra := make([][]byte, len(p.ExtraHeaders))
	for i, h := range p.ExtraHeaders {
		extra[i] = lp([]byte(h.Name), []byte(h.Value))
	}
	rules := make([][]byte, len(p.Rules))
	for i, r := range p.Rules {
		rules[i] = lp(lpStrings(r.Methods), []byte(r.Path), []byte(r.Match))
	}
	return lp([]byte(SecretPolicyFormat), lp(ups...), []byte(p.Header), []byte(p.Scheme), []byte(p.Username),
		lp(extra...), lpStrings(p.ForwardHeaders), lp(rules...), []byte(strconv.FormatBool(p.Wildcard)))
}

// Digest is the hex SHA-256 of Canonical: the policy_digest a sealed
// envelope, its receipt, the service and the host all carry.
func (p SecretPolicy) Digest() string {
	sum := sha256.Sum256(p.Canonical())
	return hex.EncodeToString(sum[:])
}

// UpstreamNames is the upstreams as the secrets API writes them: "host" for
// port 443, else "host:port".
func (p SecretPolicy) UpstreamNames() []string {
	out := make([]string, len(p.Upstreams))
	for i, u := range p.Upstreams {
		out[i] = u.Host
		if u.Port != 443 {
			out[i] = net.JoinHostPort(u.Host, strconv.Itoa(u.Port))
		}
	}
	return out
}

// ExtraHeaderMap is the extra headers as a map.
func (p SecretPolicy) ExtraHeaderMap() map[string]string {
	out := map[string]string{}
	for _, h := range p.ExtraHeaders {
		out[h.Name] = h.Value
	}
	return out
}

// Policy is the injection policy a launch job carries for this secret.
func (s LaunchSecret) Policy() (SecretPolicy, error) {
	return NewSecretPolicy(s.Upstreams, s.Header, s.Scheme, s.Username, s.Rules, s.ExtraHeaders, s.ForwardHeaders, s.Wildcard)
}

// Policy is the injection policy a secret-put relays with the envelope.
func (p SecretPutPayload) Policy() (SecretPolicy, error) {
	return NewSecretPolicy(p.Upstreams, p.Header, p.Scheme, p.Username, p.Rules, p.ExtraHeaders, p.ForwardHeaders, p.Wildcard)
}

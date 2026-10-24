// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Inbound headers the broker never forwards. Credential headers are removed so
// the operator's credential is the only one an upstream sees; forwarding headers
// are removed so the broker network is not disclosed; framing and negotiation
// headers are set by the broker itself.
var inboundStripped = canonicalSet(
	// hop-by-hop (RFC 9110 section 7.6.1) and protocol switching
	"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Http2-Settings",
	// credentials
	"Authorization", "Proxy-Authorization", "X-Api-Key", "Api-Key", "X-Goog-Api-Key", "Private-Token", "X-Auth-Token",
	"Authentication", "Cookie", "Cookie2",
	// forwarding and client identity
	"Forwarded", "Via", "X-Real-Ip", "X-Client-Ip", "True-Client-Ip", "Cf-Connecting-Ip", "Fastly-Client-Ip",
	"X-Cluster-Client-Ip", "X-Original-Forwarded-For",
	// framing and negotiation owned by the broker
	"Host", "Content-Length", "Expect", "Accept-Encoding",
)

// Upstream response headers the broker never returns.
var responseStripped = canonicalSet(
	"Connection", "Keep-Alive", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailer",
	"Transfer-Encoding", "Upgrade", "Http2-Settings", "Set-Cookie", "Set-Cookie2", "Alt-Svc", "Content-Length",
	"Content-Encoding",
)

func canonicalSet(names ...string) map[string]bool {
	out := make(map[string]bool, len(names))
	for _, n := range names {
		out[http.CanonicalHeaderKey(n)] = true
	}
	return out
}

func strippedPrefix(name string) bool {
	return strings.HasPrefix(name, "X-Forwarded-") || strings.HasPrefix(name, "Proxy-")
}

// connectionListed returns the header names a message's Connection header
// declares hop-by-hop.
func connectionListed(h http.Header) map[string]bool {
	out := map[string]bool{}
	for _, v := range h.Values("Connection") {
		for _, f := range strings.Split(v, ",") {
			if f = strings.TrimSpace(f); f != "" {
				out[http.CanonicalHeaderKey(f)] = true
			}
		}
	}
	return out
}

// wantsUpgrade reports any attempt to switch protocols (WebSocket, h2c).
func wantsUpgrade(h http.Header) bool {
	if len(h.Values("Upgrade")) > 0 || len(h.Values("Http2-Settings")) > 0 {
		return true
	}
	return connectionListed(h)["Upgrade"]
}

// outboundHeaders copies the inbound headers the upstream may see.
func outboundHeaders(in http.Header, strip map[string]bool) http.Header {
	listed := connectionListed(in)
	out := make(http.Header, len(in))
	for k, vv := range in {
		ck := http.CanonicalHeaderKey(k)
		if inboundStripped[ck] || strip[ck] || listed[ck] || strippedPrefix(ck) {
			continue
		}
		out[ck] = append([]string(nil), vv...)
	}
	return out
}

// pchar bytes allowed literally in a request path (RFC 3986 pchar and "/").
func pathByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("-._~!$&'()*+,;=:@/", c) >= 0
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// decodePath validates a raw origin-form path and returns its decoded form.
// It refuses anything whose meaning an upstream could read differently from
// the broker's allowlist: percent-encoded "/", "\", "." or "%", control bytes,
// dot segments, and empty segments other than one trailing slash.
func decodePath(raw string) (string, bool) {
	if raw == "" || raw[0] != '/' || len(raw) > 2048 {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '%' {
			if i+2 >= len(raw) {
				return "", false
			}
			hi, ok1 := unhex(raw[i+1])
			lo, ok2 := unhex(raw[i+2])
			if !ok1 || !ok2 {
				return "", false
			}
			d := hi<<4 | lo
			if d < 0x20 || d == 0x7f || d == '/' || d == '\\' || d == '.' || d == '%' {
				return "", false
			}
			b.WriteByte(d)
			i += 2
			continue
		}
		if !pathByte(c) {
			return "", false
		}
		b.WriteByte(c)
	}
	decoded := b.String()
	segments := strings.Split(decoded[1:], "/")
	for i, seg := range segments {
		if seg == "." || seg == ".." {
			return "", false
		}
		if seg == "" && i != len(segments)-1 {
			return "", false
		}
	}
	return decoded, true
}

// validQuery accepts a raw query of visible ASCII without a fragment.
func validQuery(q string) bool {
	if len(q) > 4096 {
		return false
	}
	for i := 0; i < len(q); i++ {
		if q[i] < 0x21 || q[i] > 0x7e || q[i] == '#' {
			return false
		}
	}
	return true
}

// splitRoute takes "/route/rest" (raw and decoded) and returns the route name
// and the route-relative raw and decoded paths, each starting with "/".
func splitRoute(raw, decoded string) (name, restRaw, rest string, ok bool) {
	i := strings.IndexByte(raw[1:], '/')
	if i < 0 {
		name, restRaw = raw[1:], "/"
	} else {
		name, restRaw = raw[1:i+1], raw[i+1:]
	}
	if !routePattern.MatchString(name) {
		return "", "", "", false
	}
	rest = decoded[len(name)+1:]
	if rest == "" {
		rest = "/"
	}
	return name, restRaw, rest, true
}

// ruleAllows matches a decoded route-relative path against the route's rules.
// A prefix rule matches on a segment boundary only.
func ruleAllows(rules []Rule, method, path string) (methodKnown, allowed bool) {
	for _, r := range rules {
		match := false
		switch r.Match {
		case "exact":
			match = path == r.Path
		case "prefix":
			p := strings.TrimSuffix(r.Path, "/")
			match = path == r.Path || path == p || strings.HasPrefix(path, p+"/")
		}
		if !match {
			continue
		}
		methodKnown = true
		for _, m := range r.Methods {
			if m == method {
				return true, true
			}
		}
	}
	return methodKnown, false
}

// rewriteLocation maps an absolute redirect to the route's own upstream back
// onto the broker route, so a client follows it through the broker. Any other
// Location is returned verbatim and never followed by the broker.
func rewriteLocation(loc string, rt *route) string {
	u, err := url.Parse(loc)
	if err != nil || !u.IsAbs() || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return loc
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if !strings.EqualFold(host, rt.upstream.Host) || port != strconv.Itoa(rt.upstream.Port) {
		return loc
	}
	path := u.EscapedPath()
	if rt.upstream.BasePath != "" {
		if path != rt.upstream.BasePath && !strings.HasPrefix(path, rt.upstream.BasePath+"/") {
			return loc
		}
		path = strings.TrimPrefix(path, rt.upstream.BasePath)
	}
	if path == "" {
		path = "/"
	}
	out := "/" + rt.name + path
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Request headers are forwarded by allowlist. An inbound header reaches the
// upstream only when it is in DefaultForwarded, in one of the
// DefaultForwardedPrefixes families, or in the route's own forward_headers,
// and never when it is in NeverForwarded (or one of its prefixes or
// substrings). Everything else is dropped, so a header that changes how an
// upstream reads the request (a method or URL override, a forwarding chain,
// a cookie, a range) cannot widen what the route's method and path rules
// allowed. The broker itself sets Host, Content-Length (from the buffered
// body), Accept-Encoding (identity), the credential header and the route's
// extra_headers; agent copies of those are always dropped.

// DefaultForwarded is what model-API SDKs send on every request.
var DefaultForwarded = []string{"Accept", "Content-Type", "User-Agent", "Idempotency-Key"}

// DefaultForwardedPrefixes are header families the model APIs define:
// anthropic-version and anthropic-beta, openai-organization and
// openai-project, and the x-stainless-* client metadata of their SDKs.
var DefaultForwardedPrefixes = []string{"Anthropic-", "Openai-", "X-Stainless-"}

// NeverForwarded can never be forwarded, even when a route lists it.
var NeverForwarded = []string{
	// hop-by-hop (RFC 9110 section 7.6.1) and protocol switching
	"Connection", "Keep-Alive", "Proxy-Connection", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Http2-Settings",
	// credentials
	"Authorization", "Proxy-Authorization", "X-Api-Key", "Api-Key", "X-Goog-Api-Key", "Private-Token", "X-Auth-Token",
	"Authentication", "Cookie", "Cookie2",
	// forwarding and client identity
	"Forwarded", "Via", "X-Real-Ip", "X-Client-Ip", "True-Client-Ip", "Cf-Connecting-Ip", "Fastly-Client-Ip",
	"X-Cluster-Client-Ip", "X-Original-Forwarded-For",
	// method and URL overrides: an upstream that honours one acts on a
	// method or path the rules never matched
	"X-Http-Method-Override", "X-Http-Method", "X-Method-Override", "X-Original-Url", "X-Rewrite-Url",
	"X-Original-Uri", "X-Original-Method", "X-Forwarded-Method", "X-Forwarded-Uri", "X-Forwarded-Path",
	// partial responses would let a client read part of a response the
	// redactor never sees whole
	"Range", "If-Range",
	// framing and negotiation owned by the broker
	"Host", "Content-Length", "Expect", "Accept-Encoding", "Content-Encoding",
}

// NeverForwardedPrefixes and neverForwardedParts extend NeverForwarded to
// whole families (canonical header name forms).
var NeverForwardedPrefixes = []string{"X-Forwarded-", "Proxy-", "X-Override-", "X-Http-Method", "X-Original-", "X-Rewrite-", "Sec-"}

var neverForwardedParts = []string{"Authorization", "Token", "Secret", "Password", "Cookie", "Session", "Credential", "Api-Key", "Apikey", "Access-Key", "Signature"}

var (
	defaultForwarded = canonicalSet(DefaultForwarded...)
	neverForwarded   = canonicalSet(NeverForwarded...)
)

// neverForward reports a header the broker never forwards. name is canonical.
func neverForward(name string) bool {
	if neverForwarded[name] {
		return true
	}
	for _, p := range NeverForwardedPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	for _, p := range neverForwardedParts {
		if strings.Contains(name, p) && !defaultForwarded[name] {
			return true
		}
	}
	return false
}

// defaultForward reports a header the route default forwards. name is canonical.
func defaultForward(name string) bool {
	if defaultForwarded[name] {
		return true
	}
	for _, p := range DefaultForwardedPrefixes {
		if strings.HasPrefix(name, p) && len(name) > len(p) {
			return true
		}
	}
	return false
}

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

// outboundHeaders copies the inbound headers the upstream may see: those on
// the route default or in forward (the route's forward_headers, canonical),
// minus every header in NeverForwarded, the broker-set headers in strip (the
// credential header and the extra headers) and anything the Connection
// header lists as hop-by-hop.
func outboundHeaders(in http.Header, strip, forward map[string]bool) http.Header {
	listed := connectionListed(in)
	out := make(http.Header, len(in))
	for k, vv := range in {
		ck := http.CanonicalHeaderKey(k)
		if neverForward(ck) || strip[ck] || listed[ck] || !(defaultForward(ck) || forward[ck]) {
			continue
		}
		out[ck] = append([]string(nil), vv...)
	}
	return out
}

// checkForwardHeader validates one configured forward_headers entry.
func checkForwardHeader(name string) bool {
	return token(name) && len(name) <= 64 && !neverForward(http.CanonicalHeaderKey(name))
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

// decodePath validates a raw origin-form path and returns its canonical
// decoded form, the one the rules match and the broker forwards (re-encoded
// by canonicalPath). It refuses anything whose meaning an upstream could read
// differently from the broker's allowlist:
//   - path parameters: ";" anywhere, literal or encoded (Tomcat, Jetty and
//     several proxies strip ";..." and would turn "..;" into "..");
//   - any byte outside ASCII, literal or percent-encoded (an NFKC-normalizing
//     upstream turns fullwidth dots into "." and other look-alikes into
//     separators; overlong UTF-8 encodings of "." and "/" die here too);
//   - percent-encoded "/", "\", ".", "%", "?" and "#", and control bytes;
//   - dot segments, segments that end in "." or start or end with a space
//     (servers that trim them turn "..." or ".. " into ".."), and empty
//     segments other than one trailing slash.
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
			if d < 0x20 || d >= 0x7f || strings.IndexByte("/\\.%;?#", d) >= 0 {
				return "", false
			}
			b.WriteByte(d)
			i += 2
			continue
		}
		if !pathByte(c) || c == ';' {
			return "", false
		}
		b.WriteByte(c)
	}
	decoded := b.String()
	segments := strings.Split(decoded[1:], "/")
	for i, seg := range segments {
		if seg == "" {
			if i != len(segments)-1 {
				return "", false
			}
			continue
		}
		if strings.Trim(seg, ".") == "" || seg[len(seg)-1] == '.' || seg[0] == ' ' || seg[len(seg)-1] == ' ' {
			return "", false
		}
	}
	return decoded, true
}

// canonicalPath is the one encoding of a decoded path the broker forwards:
// RFC 3986 path characters literally (";" never occurs), every other byte as
// an upper-case percent escape. decodePath(canonicalPath(p)) == p, so the
// upstream reads exactly the path the rules matched.
func canonicalPath(decoded string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	b.Grow(len(decoded))
	for i := 0; i < len(decoded); i++ {
		c := decoded[i]
		if pathByte(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hexDigits[c>>4])
		b.WriteByte(hexDigits[c&15])
	}
	return b.String()
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

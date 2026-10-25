// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"net/http"
	"net/url"
	"path"
	"strings"
	"testing"
)

// Fuzz targets from the second adversarial review. Under plain go test they
// run only their seeds and testdata/fuzz; go test -fuzz explores further.

// FuzzDecodePath: an accepted raw path has one canonical form, survives a
// round trip through net/url exactly as forward() builds the upstream URL,
// and is unchanged by path.Clean (no upstream normalization moves it).
func FuzzDecodePath(f *testing.F) {
	for _, s := range []string{"/", "/a/b", "/a/%2e%2e/b", "/a%20b/c", "/a/b/", "/r/v1/messages", "/a%3Bb", "/a/.b", "/%7e",
		"/a+b", "/a%2Bb", "/a/b%3F", "/a%23", "/a:b@c", "/%41%42", "/a/ b", "/a/b ", "//a", "/a//b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		d, ok := decodePath(raw)
		if !ok {
			return
		}
		c := canonicalPath(d)
		d2, ok2 := decodePath(c)
		if !ok2 || d2 != d {
			t.Fatalf("canonical form not stable: raw=%q d=%q c=%q d2=%q ok2=%v", raw, d, c, d2, ok2)
		}
		if canonicalPath(d2) != c {
			t.Fatalf("canonical form not idempotent: %q", raw)
		}
		cl := path.Clean(d)
		if strings.HasSuffix(d, "/") && d != "/" {
			cl += "/"
		}
		if cl != d {
			t.Fatalf("path.Clean changes an accepted path: raw=%q d=%q clean=%q", raw, d, cl)
		}
		for _, base := range []string{"", "/base"} {
			u := &url.URL{Scheme: "https", Host: "h", Path: base + d, RawPath: base + c}
			req, err := http.NewRequest("GET", u.String(), nil)
			if err != nil {
				t.Fatalf("NewRequest(%q): %v", u.String(), err)
			}
			wire := req.URL.RequestURI()
			if strings.ContainsAny(wire, "?#") {
				t.Fatalf("the wire path carries ? or #: raw=%q wire=%q", raw, wire)
			}
			back, err := url.PathUnescape(wire)
			if err != nil || back != base+d {
				t.Fatalf("the upstream decodes another path: raw=%q d=%q wire=%q back=%q err=%v", raw, d, wire, back, err)
			}
		}
	})
}

// FuzzRuleAllows: a prefix rule matches only on a segment boundary, an exact
// rule only its own path, and an allowed path never leaves the rule's prefix
// after path.Clean.
func FuzzRuleAllows(f *testing.F) {
	f.Add("/v1/", "prefix", "/v1/messages")
	f.Add("/v1", "prefix", "/v1x")
	f.Add("/v1/messages", "exact", "/v1/messages/")
	f.Add("/", "prefix", "/a/%2e%2e/b")
	f.Fuzz(func(t *testing.T, rulePath, match, raw string) {
		if (match != "exact" && match != "prefix") || !fuzzRulePathOK(rulePath) {
			return
		}
		d, ok := decodePath(raw)
		if !ok {
			return
		}
		if _, allowed := ruleAllows([]Rule{{Methods: []string{"GET"}, Path: rulePath, Match: match}}, "GET", d); !allowed {
			return
		}
		if match == "exact" && d != rulePath {
			t.Fatalf("exact rule %q matched %q", rulePath, d)
		}
		if match == "prefix" {
			p := strings.TrimSuffix(rulePath, "/")
			if !(d == rulePath || d == p || strings.HasPrefix(d, p+"/")) {
				t.Fatalf("prefix rule %q matched %q", rulePath, d)
			}
			if cl := path.Clean(d); p != "" && !(cl == p || strings.HasPrefix(cl, p+"/")) {
				t.Fatalf("prefix rule %q: %q leaves it after Clean (%q)", rulePath, d, cl)
			}
		}
	})
}

// fuzzRulePathOK approximates the configuration's rule path check: absolute,
// pchar only, no empty interior segment, no dot segment.
func fuzzRulePathOK(p string) bool {
	if p == "" || p[0] != '/' || len(p) > 512 {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~!$&'()*+,=:@/", c) >= 0) {
			return false
		}
	}
	segs := strings.Split(p[1:], "/")
	for i, s := range segs {
		if s == "" {
			if i != len(segs)-1 {
				return false
			}
			continue
		}
		if strings.Trim(s, ".") == "" || s[len(s)-1] == '.' {
			return false
		}
	}
	return true
}

// FuzzOutboundHeaders: whatever header the agent sends and whatever
// forward_headers entry the validator accepts, no credential, hop-by-hop,
// override or forwarding header reaches the upstream in any spelling (case,
// or an underscore for a hyphen), and no name with an underscore is sent.
// testdata/fuzz/FuzzOutboundHeaders holds the minimized input that found
// X-StAinless-0AuthoriZAtion.
func FuzzOutboundHeaders(f *testing.F) {
	f.Add("Anthropic-Api_key", "v", "x-custom")
	f.Add("X-Stainless-Authorization", "v", "")
	f.Add("openai-organization", "v", "x-request-id")
	f.Add("x_auth_token", "v", "x_auth_token")
	f.Fuzz(func(t *testing.T, name, value, fwd string) {
		if !token(name) || len(name) > 128 {
			return
		}
		forward := map[string]bool{}
		if fwd != "" {
			if !checkForwardHeader(fwd) {
				return
			}
			forward[http.CanonicalHeaderKey(fwd)] = true
		}
		in := http.Header{}
		in[http.CanonicalHeaderKey(name)] = []string{value}
		out := outboundHeaders(in, map[string]bool{"X-Api-Key": true}, forward)
		for k := range out {
			if strings.Contains(k, "_") {
				t.Fatalf("forwarded %q, a name with an underscore (forward=%q)", k, fwd)
			}
			key := strings.ToLower(k)
			for _, n := range NeverForwarded {
				if key == strings.ToLower(n) {
					t.Fatalf("forwarded never-forwarded %q (forward=%q)", k, fwd)
				}
			}
			for _, p := range NeverForwardedPrefixes {
				if strings.HasPrefix(key, strings.ToLower(p)) {
					t.Fatalf("forwarded never-forwarded family %q (forward=%q)", k, fwd)
				}
			}
			for _, p := range neverForwardedParts {
				if strings.Contains(key, strings.ToLower(p)) && !defaultExact[key] {
					t.Fatalf("forwarded %q, which contains %q (forward=%q)", k, p, fwd)
				}
			}
			if key == "x-api-key" {
				t.Fatal("forwarded the stripped credential header")
			}
		}
	})
}

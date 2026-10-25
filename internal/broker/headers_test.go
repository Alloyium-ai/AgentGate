// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

func TestDecodePathTable(t *testing.T) {
	ok := map[string]string{
		"/":                          "/",
		"/anthropic/v1/messages":     "/anthropic/v1/messages",
		"/git/o/r.git/info/refs":     "/git/o/r.git/info/refs",
		"/a/b/":                      "/a/b/",
		"/a/b%20c":                   "/a/b c",
		"/v1/models:generateContent": "/v1/models:generateContent",
		"/a/%41":                     "/a/A",
		"/a/b@c=d,f+g$h&i'j(k)l*m!":  "/a/b@c=d,f+g$h&i'j(k)l*m!",
	}
	for raw, want := range ok {
		got, valid := decodePath(raw)
		if !valid || got != want {
			t.Errorf("%q: %q %v", raw, got, valid)
		}
	}
	bad := []string{"", "a", "*", "//", "/a//b", "/./a", "/a/./b", "/a/../b", "/a/..", "/..", "/a/%2e%2e/b", "/a/%2E",
		"/a%2fb", "/a%2Fb", "/a%5cb", "/a\\b", "/a%25b", "/a%00", "/a%0d%0a", "/a%7f", "/a%", "/a%2", "/a%zz", "/a b",
		"/a\"b", "/a<b", "/a{b", "/a|b", "/a^b", "/a`b", "/a#b", "/a?b", "/a[b", "/" + strings.Repeat("a", 2048),
		"/a/%C3%A9", "/a/b;c", "/a/%20b"}
	for _, raw := range bad {
		if _, valid := decodePath(raw); valid {
			t.Errorf("%q accepted", raw)
		}
	}
}

func TestSplitRouteAndRules(t *testing.T) {
	name, restRaw, rest, ok := splitRoute("/anthropic/v1/a%20b", "/anthropic/v1/a b")
	if !ok || name != "anthropic" || restRaw != "/v1/a%20b" || rest != "/v1/a b" {
		t.Fatal(name, restRaw, rest, ok)
	}
	if name, restRaw, rest, ok = splitRoute("/anthropic", "/anthropic"); !ok || name != "anthropic" || restRaw != "/" || rest != "/" {
		t.Fatal(name, restRaw, rest)
	}
	if _, _, _, ok = splitRoute("/An%74hropic/x", "/Anthropic/x"); ok {
		t.Fatal("escaped route name accepted")
	}
	rules := []Rule{
		{Methods: []string{"POST"}, Path: "/v1/messages", Match: "exact"},
		{Methods: []string{"GET"}, Path: "/v1/models", Match: "prefix"},
	}
	cases := []struct {
		method, path   string
		known, allowed bool
	}{
		{"POST", "/v1/messages", true, true},
		{"GET", "/v1/messages", true, false},
		{"POST", "/v1/messages/batches", false, false},
		{"POST", "/v1/messages/", false, false},
		{"GET", "/v1/models", true, true},
		{"GET", "/v1/models/claude", true, true},
		{"GET", "/v1/modelsx", false, false},
		{"GET", "/v1/files", false, false},
		{"DELETE", "/v1/models/x", true, false},
	}
	for _, c := range cases {
		known, allowed := ruleAllows(rules, c.method, c.path)
		if known != c.known || allowed != c.allowed {
			t.Errorf("%s %s: %v %v", c.method, c.path, known, allowed)
		}
	}
	if _, allowed := ruleAllows([]Rule{{Methods: []string{"GET"}, Path: "/", Match: "prefix"}}, "GET", "/anything/here"); !allowed {
		t.Fatal("root prefix")
	}
}

func TestOutboundHeadersStripCredentialsAndHopByHop(t *testing.T) {
	in := http.Header{}
	for _, k := range []string{"Authorization", "Proxy-Authorization", "X-Api-Key", "Cookie", "Connection", "Keep-Alive",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Connection", "Forwarded", "X-Forwarded-For",
		"X-Forwarded-Host", "X-Real-Ip", "Via", "Host", "Content-Length", "Expect", "Accept-Encoding", "Http2-Settings",
		"Proxy-Anything", "Anthropic-Version", "X-Listed", "Private-Token", "X-Goog-Api-Key"} {
		in.Set(k, "agent-supplied")
	}
	in.Set("Connection", "close, X-Listed")
	in.Set("Content-Type", "application/json")
	in.Set("Anthropic-Beta", "tools")
	out := outboundHeaders(in, map[string]bool{"Anthropic-Version": true}, nil)
	for k := range out {
		if k != "Content-Type" && k != "Anthropic-Beta" {
			t.Errorf("forwarded %s", k)
		}
	}
	if len(out) != 2 {
		t.Fatal(out)
	}
	if !wantsUpgrade(http.Header{"Connection": {"keep-alive, Upgrade"}}) || !wantsUpgrade(http.Header{"Upgrade": {"websocket"}}) ||
		!wantsUpgrade(http.Header{"Http2-Settings": {"AAA"}}) || wantsUpgrade(http.Header{"Connection": {"close"}}) {
		t.Fatal("upgrade detection")
	}
}

// Regression for the second review's FuzzOutboundHeaders finding: the never
// rules compared canonical names case-sensitively, so a name whose word
// follows a digit (X-StAinless-0AuthoriZAtion canonicalizes to
// X-Stainless-0authorization) or that spells a hyphen as an underscore
// (Anthropic-Api_key) passed in a default-forwarded family, and the
// forward_headers validator accepted x_auth_token and x-0secret.
func TestNeverForwardIgnoresCaseAndUnderscores(t *testing.T) {
	in := http.Header{}
	for _, k := range []string{"X-StAinless-0AuthoriZAtion", "Anthropic-Api_key", "X-Stainless-Foo_bar", "x_auth_token",
		"X-0secret", "Openai-9Session", "anthropic-0cookie", "X-Stainless-0SIGNATURE"} {
		in[k] = []string{"agent-supplied"}
	}
	in.Set("X-Stainless-Lang", "go")
	in.Set("Anthropic-Beta", "tools")
	out := outboundHeaders(in, nil, map[string]bool{"X-0secret": true, "X_auth_token": true})
	if len(out) != 2 || out.Get("X-Stainless-Lang") != "go" || out.Get("Anthropic-Beta") != "tools" {
		t.Fatalf("forwarded %v", out)
	}
	for _, name := range []string{"X-StAinless-0AuthoriZAtion", "Anthropic-Api_key", "x_auth_token", "x-0secret", "git_protocol",
		"X-Api_Key", "X_FORWARDED_HOST", "proxy_x", "SEC-x", "x-0TOKEN", "X-My-Apikey", "Content_Length"} {
		if checkForwardHeader(name) {
			t.Errorf("forward_headers accepted %q", name)
		}
	}
	for _, name := range []string{"git-protocol", "X-GitHub-Api-Version", "x-request-id", "Accept-Language"} {
		if !checkForwardHeader(name) {
			t.Errorf("forward_headers refused %q", name)
		}
	}
}

func TestRewriteLocation(t *testing.T) {
	rt := &route{name: "gh", upstream: Upstream{Host: "api.example.test", Port: 443, BasePath: "/api"}}
	cases := map[string]string{
		"https://api.example.test/api/v3/x?y=1":    "/gh/v3/x?y=1",
		"https://API.example.test:443/api":         "/gh/",
		"https://api.example.test/other":           "https://api.example.test/other",
		"https://api.example.test:8443/api/x":      "https://api.example.test:8443/api/x",
		"http://api.example.test/api/x":            "http://api.example.test/api/x",
		"https://evil.example/api/x":               "https://evil.example/api/x",
		"http://169.254.169.254/latest/meta-data/": "http://169.254.169.254/latest/meta-data/",
		"/relative/path":                           "/relative/path",
		"https://user@api.example.test/api/x":      "https://user@api.example.test/api/x",
	}
	for in, want := range cases {
		if got := rewriteLocation(in, rt); got != want {
			t.Errorf("%s: %s", in, got)
		}
	}
}

func redactAll(r *redactor, data []byte, chunk int) []byte {
	var out bytes.Buffer
	for len(data) > 0 {
		n := chunk
		if n > len(data) {
			n = len(data)
		}
		out.Write(r.process(data[:n], false))
		data = data[n:]
	}
	out.Write(r.process(nil, true))
	return out.Bytes()
}

func TestRedactorMasksAcrossChunkBoundaries(t *testing.T) {
	secret := []byte("sk-test-FAKE-0123456789abcdef")
	forms := credentialForms(append([]byte(nil), secret...), "x-access-token")
	patterns := newPatterns(forms)
	text := []byte("data: {\"echo\":\"" + string(secret) + "\"}\n\nprefix sk-test-FAKE-012 not a match\n" +
		string(forms[1]) + "|" + string(forms[len(forms)-1]) + "\n" + string(secret[:5]))
	for _, chunk := range []int{1, 2, 7, 16, 1 << 20} {
		r := newRedactor(patterns)
		out := redactAll(r, append([]byte(nil), text...), chunk)
		if len(out) != len(text) {
			t.Fatalf("chunk %d: length changed", chunk)
		}
		for _, f := range forms {
			if bytes.Contains(out, f) {
				t.Fatalf("chunk %d: form survived: %q", chunk, out)
			}
		}
		if !bytes.Contains(out, []byte("sk-test-FAKE-012 not a match")) || !bytes.HasSuffix(out, secret[:5]) {
			t.Fatalf("chunk %d: over-redacted: %q", chunk, out)
		}
		if r.count != 3 {
			t.Fatalf("chunk %d: count %d", chunk, r.count)
		}
	}
}

func TestRedactorDoesNotDelayEventBoundaries(t *testing.T) {
	patterns := newPatterns(credentialForms([]byte("sk-test-FAKE-0123456789abcdef"), ""))
	r := newRedactor(patterns)
	event := []byte("event: content_block_delta\ndata: {\"text\":\"hi\"}\n\n")
	if out := r.process(event, false); !bytes.Equal(out, event) {
		t.Fatalf("held back %d bytes", len(event)-len(out))
	}
	// A tail that could begin the secret is held until it is resolved.
	if out := r.process([]byte("x sk-te"), false); string(out) != "x " {
		t.Fatalf("%q", out)
	}
	if out := r.process([]byte("a\n"), false); string(out) != "sk-tea\n" {
		t.Fatalf("%q", out)
	}
}

func FuzzRedactor(f *testing.F) {
	f.Add([]byte("hello sk-test-FAKE-0123456789abcdef world"), uint8(3))
	f.Fuzz(func(t *testing.T, data []byte, chunk uint8) {
		secret := []byte("sk-test-FAKE-0123456789abcdef")
		patterns := newPatterns(credentialForms(secret, "u"))
		in := append(append(append([]byte(nil), data...), secret...), data...)
		out := redactAll(newRedactor(patterns), append([]byte(nil), in...), int(chunk)+1)
		if len(out) != len(in) {
			t.Fatal("length changed")
		}
		for _, p := range patterns {
			if bytes.Contains(out, p.b) {
				t.Fatal("form survived")
			}
		}
	})
}

// credentialForms mirrors the forms loadCredential derives in its arena.
func credentialForms(value []byte, username string) [][]byte {
	var forms [][]byte
	add := func(b []byte) {
		if len(b) < 8 {
			return
		}
		for _, f := range forms {
			if bytes.Equal(f, b) {
				return
			}
		}
		forms = append(forms, b)
	}
	add(value)
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		add([]byte(enc.EncodeToString(value)))
		if username != "" {
			basic := append([]byte(username+":"), value...)
			add([]byte(enc.EncodeToString(basic)))
			clear(basic)
		}
	}
	return forms
}

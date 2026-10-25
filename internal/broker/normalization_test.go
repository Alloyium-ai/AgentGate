// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"net/http"
	"strings"
	"testing"
)

// The broker matches a path against its rules and forwards it; an upstream
// that normalizes the path differently (strips ";..." path parameters,
// NFKC-folds look-alike dots, trims trailing dots or spaces, decodes once
// more) must never read a path the rules did not match. Every such spelling
// is refused before matching, and an accepted path is forwarded in exactly
// one canonical encoding of the bytes the rules matched.
func TestDecodePathRefusesUpstreamNormalizationTricks(t *testing.T) {
	refused := map[string]string{
		"/v1/models/..;/..;/admin":      "Tomcat-style ..; dot segment",
		"/v1/models/.;/admin":           ".; dot segment",
		"/v1/models;jsessionid=1":       "path parameter",
		"/v1/models/x;a=b/y":            "path parameter mid-path",
		"/v1/models/%3B/x":              "encoded ;",
		"/v1/models%3bjsessionid=1":     "lowercase encoded ;",
		"/v1/models/%EF%BC%8E%EF%BC%8E": "fullwidth dots (NFKC to ..)",
		"/v1/models/%E2%80%A4%E2%80%A4": "one-dot leaders",
		"/v1/models/%C0%AE%C0%AE/x":     "overlong UTF-8 dots",
		"/v1/models/%C0%AF":             "overlong UTF-8 slash",
		"/v1/models/%E2%88%95x":         "division slash",
		"/v1/models/\xef\xbc\x8e":       "literal non-ASCII",
		"/v1/models/%80":                "high byte",
		"/v1/models/%FF":                "high byte",
		"/v1/models/%2e%2e/admin":       "encoded dots",
		"/v1/models/.%2e/admin":         "mixed dot encoding",
		"/v1/models/%252e%252e/admin":   "double encoding",
		"/v1/models/%u002e":             "IIS %u encoding",
		"/v1//models":                   "double slash",
		"//v1/models":                   "leading double slash",
		"/v1/models/":                   "", // accepted: one trailing slash
		"/v1/models./admin":             "trailing dot",
		"/v1/models/...":                "dot-only segment",
		"/v1/models/..../x":             "dot-only segment",
		"/v1/models/..%20/admin":        "trailing space after dots",
		"/v1/models/%20../admin":        "leading space",
		"/v1/models%3F/../admin":        "encoded ? (query-vs-path)",
		"/v1/models%23frag":             "encoded #",
		"/v1/models?x=/../admin":        "query is not part of the path",
		"/v1/models%5c..%5cadmin":       "encoded backslash",
	}
	for raw, why := range refused {
		path := raw
		if i := strings.IndexByte(raw, '?'); i >= 0 {
			path = raw[:i] // the server splits the query off before decodePath
		}
		_, ok := decodePath(path)
		if why == "" || raw == "/v1/models?x=/../admin" {
			if !ok {
				t.Errorf("%q refused", raw)
			}
			continue
		}
		if ok {
			t.Errorf("%q accepted (%s)", raw, why)
		}
	}
}

func TestCanonicalPathIsTheOneEncodingOfTheMatchedBytes(t *testing.T) {
	for raw, want := range map[string]string{
		"/v1/messages":     "/v1/messages",
		"/v1/a%20b":        "/v1/a%20b",
		"/v1/%41%42c":      "/v1/ABc",
		"/v1/a%2Cb":        "/v1/a,b",
		"/v1/a%22b":        "/v1/a%22b",
		"/v1/models:x@y=z": "/v1/models:x@y=z",
		"/v1/a%7Bb%7D":     "/v1/a%7Bb%7D",
	} {
		decoded, ok := decodePath(raw)
		if !ok {
			t.Fatalf("%q refused", raw)
		}
		got := canonicalPath(decoded)
		if got != want {
			t.Errorf("%q: forwarded %q, want %q", raw, got, want)
		}
		again, ok := decodePath(got)
		if !ok || again != decoded || canonicalPath(again) != got {
			t.Errorf("%q: canonical form %q does not round-trip (%q %v)", raw, got, again, ok)
		}
	}
}

// Regression for the review repro TestReviewPathParamDotSegmentsForwarded:
// "..;" and fullwidth-dot segments under an allowed prefix were forwarded
// verbatim.
func TestPathParametersAndLookalikeDotsNeverReachTheUpstream(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{
		"/anthropic/v1/models/..;/..;/admin/keys",
		"/anthropic/v1/models/%EF%BC%8E%EF%BC%8E/admin",
		"/anthropic/v1/models;jsessionid=1",
		"/anthropic/v1/models/.;/x",
		"/anthropic/v1/models/x./y",
		"/anthropic/v1/models/..%20/admin",
	} {
		resp := e.do("GET", p, nil)
		e.text(resp)
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s -> %d", p, resp.StatusCode)
		}
	}
	if got := e.requests(); len(got) != 0 {
		t.Fatalf("the upstream saw %q", got[0].RequestURI)
	}
	// An allowed path is forwarded in its canonical encoding.
	resp := e.do("GET", "/anthropic/v1/models/%63laude%20x", nil)
	e.text(resp)
	got := e.requests()
	if resp.StatusCode != 200 || len(got) != 1 || got[0].RequestURI != "/v1/models/claude%20x" || got[0].Path != "/v1/models/claude x" {
		t.Fatalf("%d %+v", resp.StatusCode, got)
	}
}

// Regression for the review repro TestReviewOverrideHeadersForwarded: a
// POST-only rule forwarded X-HTTP-Method-Override and X-Original-URL.
func TestOverrideAndUnlistedHeadersNeverReachTheUpstream(t *testing.T) {
	e := newEnv(t)
	resp := e.do("POST", "/anthropic/v1/messages", strings.NewReader("{}"),
		"X-HTTP-Method-Override", "DELETE", "X-HTTP-Method", "DELETE", "X-Method-Override", "DELETE",
		"X-Original-URL", "/v1/admin/keys", "X-Rewrite-URL", "/v1/admin/keys", "X-Override-Method", "DELETE",
		"X-Original-Method", "DELETE", "X-Forwarded-Uri", "/v1/admin", "Range", "bytes=0-3", "If-Range", "x",
		"X-Unlisted", "1", "Sec-Fetch-Mode", "cors", "Content-Encoding", "gzip",
		"Content-Type", "application/json")
	e.text(resp)
	got := e.requests()
	if len(got) != 1 {
		t.Fatalf("upstream saw %d requests (status %d)", len(got), resp.StatusCode)
	}
	for k := range got[0].Header {
		switch k {
		case "Content-Type", "Content-Length", "X-Api-Key", "Anthropic-Version", "Accept-Encoding", "User-Agent":
		default:
			t.Errorf("forwarded %s", k)
		}
	}
}

// The route default forwards what the model-API SDKs send, and a route's
// forward_headers adds exact names.
func TestModelSDKHeadersPassTheRouteDefault(t *testing.T) {
	route := func(m map[string]any, _ *env) {
		m["routes"].([]any)[0].(map[string]any)["forward_headers"] = []any{"git-protocol", "X-GitHub-Api-Version"}
	}
	e := newEnv(t, route)
	sdk := []string{
		"Accept", "application/json", "Content-Type", "application/json", "User-Agent", "Anthropic/Python 0.40.0",
		"Anthropic-Beta", "tools-2024-04-04", "X-Stainless-Lang", "python", "X-Stainless-Package-Version", "0.40.0",
		"X-Stainless-Os", "Linux", "X-Stainless-Arch", "x64", "X-Stainless-Runtime", "CPython", "X-Stainless-Runtime-Version", "3.12.0",
		"X-Stainless-Retry-Count", "0", "X-Stainless-Timeout", "600", "Openai-Organization", "org-x", "Openai-Project", "proj-x",
		"Idempotency-Key", "stainless-retry-1", "Git-Protocol", "version=2", "X-Github-Api-Version", "2022-11-28",
		"X-Api-Key", "agent-supplied-key", "Authorization", "Bearer agent-supplied",
	}
	resp := e.do("POST", "/anthropic/v1/messages", strings.NewReader("{}"), sdk...)
	e.text(resp)
	got := e.requests()
	if resp.StatusCode != 200 || len(got) != 1 {
		t.Fatalf("%d %d", resp.StatusCode, len(got))
	}
	h := got[0].Header
	for i := 0; i+1 < len(sdk); i += 2 {
		name, value := http.CanonicalHeaderKey(sdk[i]), sdk[i+1]
		switch name {
		case "X-Api-Key":
			if h.Get(name) != testSecret {
				t.Error("the agent's own credential reached the upstream")
			}
		case "Authorization":
			if h.Get(name) != "" {
				t.Error("an agent Authorization header was forwarded")
			}
		default:
			if h.Get(name) != value {
				t.Errorf("%s: %q, want %q", name, h.Get(name), value)
			}
		}
	}
	if h.Get("Anthropic-Version") != "2023-06-01" {
		t.Error("the extra header the broker sets is missing")
	}
}

func TestForwardHeadersRefuseWhatTheBrokerNeverForwards(t *testing.T) {
	for _, name := range []string{"Authorization", "x-api-key", "Cookie", "Connection", "Transfer-Encoding", "Host",
		"X-HTTP-Method-Override", "X-Original-URL", "X-Rewrite-URL", "X-Override-Anything", "X-Forwarded-For", "Forwarded",
		"Proxy-Authorization", "Proxy-Anything", "Range", "Via", "X-Real-Ip", "X-Session-Token", "X-Client-Secret",
		"anthropic-version", "bad name", ""} {
		m := validConfigJSON()
		m["routes"].([]any)[0].(map[string]any)["forward_headers"] = []any{name}
		cfg, err := ParseConfig(encode(t, m))
		if err == nil {
			_, err = cfg.Validate(testNow)
		}
		if err == nil || !strings.Contains(err.Error(), "forward_headers") {
			t.Errorf("%q: %v", name, err)
		}
	}
	m := validConfigJSON()
	m["routes"].([]any)[0].(map[string]any)["forward_headers"] = []any{"git-protocol", "Git-Protocol"}
	if cfg, err := ParseConfig(encode(t, m)); err == nil {
		if _, err = cfg.Validate(testNow); err == nil {
			t.Error("a duplicated forward header was accepted")
		}
	}
	m["routes"].([]any)[0].(map[string]any)["forward_headers"] = []any{"git-protocol", "x-github-api-version"}
	cfg, err := ParseConfig(encode(t, m))
	if err == nil {
		_, err = cfg.Validate(testNow)
	}
	if err != nil {
		t.Fatal(err)
	}
}

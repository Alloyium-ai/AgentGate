// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var testNow = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

func validConfigJSON() map[string]any {
	return map[string]any{
		"version":   ConfigVersion,
		"launch_id": "lch-0001",
		"target_id": "local",
		"deadline":  testNow.Add(time.Hour).Format(time.RFC3339),
		"listen": map[string]any{
			"network": "tcp", "address": "10.99.0.2", "port": 8443, "subnet": "10.99.0.0/29",
		},
		"stats_path": "/var/lib/agentgate/broker/stats.json",
		"run_as":     map[string]any{"uid": 10002, "gid": 10002},
		"routes": []any{map[string]any{
			"name":     "anthropic",
			"upstream": map[string]any{"host": "api.example.test"},
			"credential": map[string]any{
				"secret_file": "/run/agentgate/secrets/anthropic", "header": "x-api-key",
				"extra_headers": map[string]any{"anthropic-version": "2023-06-01"},
			},
			"rules": []any{map[string]any{"methods": []any{"POST"}, "path": "/v1/messages", "match": "exact"}},
		}},
	}
}

func encode(t testing.TB, v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestValidConfigResolvesDefaults(t *testing.T) {
	cfg, err := ParseConfig(encode(t, validConfigJSON()))
	if err != nil {
		t.Fatal(err)
	}
	set, err := cfg.Validate(testNow)
	if err != nil {
		t.Fatal(err)
	}
	if set.MaxConnections != 32 || set.MaxConcurrentRequests != 16 || set.MaxRequestBytes != 16<<20 ||
		set.StreamIdleTimeout != 120*time.Second || set.DNSCache != 30*time.Second || cfg.Routes[0].Upstream.Port != 443 {
		t.Fatalf("defaults not applied: %+v", set)
	}
	if got := cfg.Listen.ListenAuthority(); got != "10.99.0.2:8443" {
		t.Fatalf("authority %q", got)
	}
	if got := BaseURL(cfg, "anthropic"); got != "http://10.99.0.2:8443/anthropic" {
		t.Fatalf("base url %q", got)
	}
}

func TestConfigRejectsMalformedDocuments(t *testing.T) {
	good := string(encode(t, validConfigJSON()))
	cases := map[string]string{
		"empty":            ``,
		"array":            `[]`,
		"trailing":         good + `{}`,
		"duplicate key":    strings.Replace(good, `"version":`, `"version":"x","version":`, 1),
		"case alias":       strings.Replace(good, `"version":`, `"Version":"x","version":`, 1),
		"uppercase key":    strings.Replace(good, `"launch_id":`, `"Launch_id":`, 1),
		"unknown field":    strings.Replace(good, `"version":`, `"extra":1,"version":`, 1),
		"null":             strings.Replace(good, `"run_as":{"gid":10002,"uid":10002}`, `"run_as":null`, 1),
		"float limit":      strings.Replace(good, `"routes":`, `"limits":{"burst":1.5},"routes":`, 1),
		"string number":    strings.Replace(good, `"port":8443`, `"port":"8443"`, 1),
		"oversize":         good[:len(good)-1] + `,"x":"` + strings.Repeat("a", MaxConfigBytes) + `"}`,
		"deep nesting":     strings.Repeat(`{"a":`, 20) + `1` + strings.Repeat(`}`, 20),
		"duplicate nested": strings.Replace(good, `"header":"x-api-key"`, `"header":"x-api-key","header":"authorization"`, 1),
	}
	for name, raw := range cases {
		if _, err := ParseConfig([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestConfigRejectsInvalidFields(t *testing.T) {
	type mutate func(m map[string]any)
	route := func(m map[string]any) map[string]any { return m["routes"].([]any)[0].(map[string]any) }
	cred := func(m map[string]any) map[string]any { return route(m)["credential"].(map[string]any) }
	up := func(m map[string]any) map[string]any { return route(m)["upstream"].(map[string]any) }
	listen := func(m map[string]any) map[string]any { return m["listen"].(map[string]any) }
	rule := func(m map[string]any) map[string]any { return route(m)["rules"].([]any)[0].(map[string]any) }
	cases := map[string]mutate{
		"version":                func(m map[string]any) { m["version"] = "agentgate.broker.v0" },
		"launch id":              func(m map[string]any) { m["launch_id"] = "../x" },
		"target id":              func(m map[string]any) { m["target_id"] = "" },
		"deadline past":          func(m map[string]any) { m["deadline"] = testNow.Add(-time.Minute).Format(time.RFC3339) },
		"deadline far":           func(m map[string]any) { m["deadline"] = testNow.Add(48 * time.Hour).Format(time.RFC3339) },
		"deadline format":        func(m map[string]any) { m["deadline"] = "tomorrow" },
		"listen wildcard":        func(m map[string]any) { listen(m)["address"] = "0.0.0.0" },
		"listen loopback":        func(m map[string]any) { listen(m)["address"] = "127.0.0.1" },
		"listen public":          func(m map[string]any) { listen(m)["address"] = "8.8.8.8" },
		"listen ipv6":            func(m map[string]any) { listen(m)["address"] = "fd00::2" },
		"listen non-canonical":   func(m map[string]any) { listen(m)["address"] = "010.99.0.2" },
		"listen cgnat":           func(m map[string]any) { listen(m)["address"] = "100.64.0.2"; listen(m)["subnet"] = "100.64.0.0/29" },
		"listen port low":        func(m map[string]any) { listen(m)["port"] = 80 },
		"listen subnet outside":  func(m map[string]any) { listen(m)["subnet"] = "10.98.0.0/29" },
		"listen subnet wide":     func(m map[string]any) { listen(m)["subnet"] = "10.0.0.0/8" },
		"listen subnet unmasked": func(m map[string]any) { listen(m)["subnet"] = "10.99.0.2/29" },
		"listen broadcast":       func(m map[string]any) { listen(m)["address"] = "10.99.0.7" },
		"listen network addr":    func(m map[string]any) { listen(m)["address"] = "10.99.0.0" },
		"listen network":         func(m map[string]any) { listen(m)["network"] = "udp" },
		"listen mixed":           func(m map[string]any) { listen(m)["path"] = "/run/x.sock" },
		"unix without gid": func(m map[string]any) {
			m["listen"] = map[string]any{"network": "unix", "path": "/run/agentgate/broker/broker.sock"}
		},
		"unix relative": func(m map[string]any) {
			m["listen"] = map[string]any{"network": "unix", "path": "broker.sock", "socket_gid": 65534}
		},
		"stats relative":      func(m map[string]any) { m["stats_path"] = "stats.json" },
		"stats suffix":        func(m map[string]any) { m["stats_path"] = "/var/lib/x/stats" },
		"stats unclean":       func(m map[string]any) { m["stats_path"] = "/var/lib/../x/stats.json" },
		"run as root":         func(m map[string]any) { m["run_as"] = map[string]any{"uid": 0, "gid": 0} },
		"no routes":           func(m map[string]any) { m["routes"] = []any{} },
		"route name":          func(m map[string]any) { route(m)["name"] = "Anthropic" },
		"host ip literal":     func(m map[string]any) { up(m)["host"] = "1.2.3.4" },
		"host ipv6 literal":   func(m map[string]any) { up(m)["host"] = "::1" },
		"host single label":   func(m map[string]any) { up(m)["host"] = "metadata" },
		"host localhost":      func(m map[string]any) { up(m)["host"] = "api.localhost" },
		"host internal":       func(m map[string]any) { up(m)["host"] = "metadata.google.internal" },
		"host numeric tld":    func(m map[string]any) { up(m)["host"] = "127.0.0.1.2" },
		"host uppercase":      func(m map[string]any) { up(m)["host"] = "API.example.test" },
		"host trailing dot":   func(m map[string]any) { up(m)["host"] = "api.example.test." },
		"host with port":      func(m map[string]any) { up(m)["host"] = "api.example.test:443" },
		"host userinfo":       func(m map[string]any) { up(m)["host"] = "user@api.example.test" },
		"port":                func(m map[string]any) { up(m)["port"] = 70000 },
		"base path slash":     func(m map[string]any) { up(m)["base_path"] = "/v1/" },
		"base path dots":      func(m map[string]any) { up(m)["base_path"] = "/v1/.." },
		"pin":                 func(m map[string]any) { up(m)["pin_spki_sha256"] = []any{"not-base64"} },
		"no secret source":    func(m map[string]any) { delete(cred(m), "secret_file") },
		"two secret sources":  func(m map[string]any) { cred(m)["secret_fd"] = 3 },
		"secret relative":     func(m map[string]any) { cred(m)["secret_file"] = "secrets/a" },
		"secret fd stdio":     func(m map[string]any) { delete(cred(m), "secret_file"); cred(m)["secret_fd"] = 2 },
		"header host":         func(m map[string]any) { cred(m)["header"] = "host" },
		"header cookie":       func(m map[string]any) { cred(m)["header"] = "cookie" },
		"header invalid":      func(m map[string]any) { cred(m)["header"] = "x api key" },
		"header crlf":         func(m map[string]any) { cred(m)["header"] = "x-api-key\r\nx-evil" },
		"bearer wrong header": func(m map[string]any) { cred(m)["scheme"] = "Bearer" },
		"basic no user": func(m map[string]any) {
			cred(m)["header"] = "authorization"
			cred(m)["scheme"] = "Basic"
		},
		"username without basic": func(m map[string]any) { cred(m)["username"] = "x" },
		"scheme unknown":         func(m map[string]any) { cred(m)["header"] = "authorization"; cred(m)["scheme"] = "Digest" },
		"extra header crlf": func(m map[string]any) {
			cred(m)["extra_headers"] = map[string]any{"anthropic-version": "1\r\nx-evil: 1"}
		},
		"extra header auth": func(m map[string]any) {
			cred(m)["extra_headers"] = map[string]any{"authorization": "Bearer x"}
		},
		"extra header forwarded": func(m map[string]any) {
			cred(m)["extra_headers"] = map[string]any{"x-forwarded-for": "1.1.1.1"}
		},
		"no rules":         func(m map[string]any) { route(m)["rules"] = []any{} },
		"rule connect":     func(m map[string]any) { rule(m)["methods"] = []any{"CONNECT"} },
		"rule trace":       func(m map[string]any) { rule(m)["methods"] = []any{"TRACE"} },
		"rule dup method":  func(m map[string]any) { rule(m)["methods"] = []any{"GET", "GET"} },
		"rule no methods":  func(m map[string]any) { rule(m)["methods"] = []any{} },
		"rule path dots":   func(m map[string]any) { rule(m)["path"] = "/v1/../admin" },
		"rule path rel":    func(m map[string]any) { rule(m)["path"] = "v1/messages" },
		"rule path escape": func(m map[string]any) { rule(m)["path"] = "/v1%2fmessages" },
		"rule match":       func(m map[string]any) { rule(m)["match"] = "regex" },
		"duplicate route": func(m map[string]any) {
			m["routes"] = append(m["routes"].([]any), m["routes"].([]any)[0])
		},
		"limit range":    func(m map[string]any) { m["limits"] = map[string]any{"max_connections": 0} },
		"limit negative": func(m map[string]any) { m["limits"] = map[string]any{"dns_cache_seconds": -1} },
		"limit concurrency": func(m map[string]any) {
			m["limits"] = map[string]any{"max_connections": 4, "max_concurrent_requests": 8}
		},
		"limit buffered": func(m map[string]any) {
			m["limits"] = map[string]any{"max_concurrent_requests": 16, "max_request_bytes": 256 << 20}
		},
		"limit unknown": func(m map[string]any) { m["limits"] = map[string]any{"max_everything": 1} },
	}
	for name, change := range cases {
		m := validConfigJSON()
		change(m)
		cfg, err := ParseConfig(encode(t, m))
		if err == nil {
			_, err = cfg.Validate(testNow)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.HasPrefix(err.Error(), "broker config") {
			t.Errorf("%s: error lacks its prefix: %v", name, err)
		}
	}
}

func TestConfigErrorsNeverEchoValues(t *testing.T) {
	m := validConfigJSON()
	marker := "ZZ-config-value-marker-ZZ"
	m["routes"].([]any)[0].(map[string]any)["credential"].(map[string]any)["extra_headers"] = map[string]any{"x-team": marker + "\r\n"}
	cfg, err := ParseConfig(encode(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Validate(testNow); err == nil || strings.Contains(err.Error(), marker) {
		t.Fatalf("error %v", err)
	}
}

func TestUnixListenConfig(t *testing.T) {
	m := validConfigJSON()
	m["listen"] = map[string]any{"network": "unix", "path": "/run/agentgate/broker/broker.sock", "socket_gid": 65534}
	cfg, err := ParseConfig(encode(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Validate(testNow); err != nil {
		t.Fatal(err)
	}
	if cfg.Listen.ListenAuthority() != "agentgate-broker" || BaseURL(cfg, "anthropic") != "http://agentgate-broker/anthropic" {
		t.Fatal(cfg.Listen.ListenAuthority())
	}
}

func FuzzParseConfig(f *testing.F) {
	f.Add(encode(f, validConfigJSON()))
	f.Add([]byte(`{"version":"agentgate.broker.v1","routes":[{"name":"a"}]}`))
	f.Add([]byte(`{"a":{"b":[1,2,{"c":null}]}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		cfg, err := ParseConfig(raw)
		if err != nil {
			return
		}
		if _, err := cfg.Validate(testNow); err != nil {
			return
		}
		// Anything accepted must have the invariants the server relies on.
		if cfg.Listen.Network == "tcp" && !strings.HasPrefix(cfg.Listen.Address, "10.") &&
			!strings.HasPrefix(cfg.Listen.Address, "172.") && !strings.HasPrefix(cfg.Listen.Address, "192.168.") {
			t.Fatalf("accepted a non-private listen address")
		}
		for _, r := range cfg.Routes {
			if len(r.Rules) == 0 || r.Upstream.Port == 0 {
				t.Fatalf("accepted a route without rules or port")
			}
		}
	})
}

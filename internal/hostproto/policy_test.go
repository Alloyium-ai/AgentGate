// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type policyCase struct {
	Name           string            `json:"name"`
	Upstreams      []string          `json:"upstreams"`
	Header         string            `json:"header"`
	Scheme         string            `json:"scheme"`
	Username       string            `json:"username"`
	Rules          []BrokerRule      `json:"rules"`
	ExtraHeaders   map[string]string `json:"extra_headers"`
	ForwardHeaders []string          `json:"forward_headers"`
	Wildcard       bool              `json:"wildcard"`
	Policy         *SecretPolicy     `json:"policy"`
	CanonicalHex   string            `json:"canonical_hex"`
	Digest         string            `json:"digest"`
}

func policyCases() []policyCase {
	all := []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	return []policyCase{
		{Name: "one upstream, one rule", Upstreams: []string{"api.example.test"}, Header: "x-api-key",
			Rules: []BrokerRule{{Methods: []string{"POST"}, Path: "/v1/messages", Match: "exact"}}},
		{Name: "normalized spellings", Upstreams: []string{"api.example.test:443", "eu.api.example.test:8443"}, Header: "Authorization",
			Rules:        []BrokerRule{{Methods: []string{"POST", "GET"}, Path: "/v1/messages", Match: "exact"}, {Methods: []string{"GET"}, Path: "/v1/models", Match: "prefix"}},
			ExtraHeaders: map[string]string{"Anthropic-Version": "2023-06-01", "anthropic-beta": "tools-2024-04-04"}, ForwardHeaders: []string{"X-GitHub-Api-Version", "git-protocol"}},
		{Name: "basic", Upstreams: []string{"git.example.test"}, Header: "authorization", Scheme: "Basic", Username: "x-access-token",
			Rules: []BrokerRule{{Methods: []string{"GET", "POST"}, Path: "/example-org/app.git", Match: "prefix"}}},
		{Name: "wildcard", Upstreams: []string{"api.example.test"}, Header: "x-api-key", Wildcard: true,
			Rules: []BrokerRule{{Methods: all, Path: "/", Match: "prefix"}}},
		{Name: "no rules", Upstreams: []string{"api.example.test"}, Header: "x-api-key", Rules: []BrokerRule{}},
	}
}

// policyRefusals are settings every implementation refuses to make a
// policy of: each is ambiguous or malformed.
func policyRefusals() []policyCase {
	rules := []BrokerRule{{Methods: []string{"POST"}, Path: "/v1/messages", Match: "exact"}}
	return []policyCase{
		{Name: "no upstream", Upstreams: []string{}, Header: "x-api-key", Rules: rules},
		{Name: "nine upstreams", Upstreams: []string{"a.example.test", "b.example.test", "c.example.test", "d.example.test", "e.example.test", "f.example.test", "g.example.test", "h.example.test", "i.example.test"}, Header: "x-api-key", Rules: rules},
		{Name: "upstream with capitals", Upstreams: []string{"Api.Example.test"}, Header: "x-api-key", Rules: rules},
		{Name: "upstream with a scheme", Upstreams: []string{"https://api.example.test"}, Header: "x-api-key", Rules: rules},
		{Name: "port zero", Upstreams: []string{"api.example.test:0"}, Header: "x-api-key", Rules: rules},
		{Name: "port out of range", Upstreams: []string{"api.example.test:65536"}, Header: "x-api-key", Rules: rules},
		{Name: "duplicate origin", Upstreams: []string{"api.example.test", "api.example.test:443"}, Header: "x-api-key", Rules: rules},
		{Name: "header with a space", Upstreams: []string{"api.example.test"}, Header: "x api key", Rules: rules},
		{Name: "duplicate extra header", Upstreams: []string{"api.example.test"}, Header: "x-api-key", Rules: rules, ExtraHeaders: map[string]string{"A-B": "1", "a-b": "2"}},
		{Name: "extra header that is not a name", Upstreams: []string{"api.example.test"}, Header: "x-api-key", Rules: rules, ExtraHeaders: map[string]string{"a:b": "1"}},
		{Name: "duplicate forward header", Upstreams: []string{"api.example.test"}, Header: "x-api-key", Rules: rules, ForwardHeaders: []string{"X-A", "x-a"}},
		{Name: "forward header that is not a name", Upstreams: []string{"api.example.test"}, Header: "x-api-key", Rules: rules, ForwardHeaders: []string{"x a"}},
		{Name: "seventeen forward headers", Upstreams: []string{"api.example.test"}, Header: "x-api-key", Rules: rules,
			ForwardHeaders: []string{"h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10", "h11", "h12", "h13", "h14", "h15", "h16", "h17"}},
		{Name: "duplicate method", Upstreams: []string{"api.example.test"}, Header: "x-api-key", Rules: []BrokerRule{{Methods: []string{"GET", "GET"}, Path: "/", Match: "prefix"}}},
		{Name: "unknown method", Upstreams: []string{"api.example.test"}, Header: "x-api-key", Rules: []BrokerRule{{Methods: []string{"*"}, Path: "/", Match: "prefix"}}},
		{Name: "lower-case method", Upstreams: []string{"api.example.test"}, Header: "x-api-key", Rules: []BrokerRule{{Methods: []string{"get"}, Path: "/", Match: "prefix"}}},
		{Name: "wildcard flag with narrower rules", Upstreams: []string{"api.example.test"}, Header: "x-api-key", Rules: rules, Wildcard: true},
	}
}

func (c policyCase) build() (SecretPolicy, error) {
	return NewSecretPolicy(c.Upstreams, c.Header, c.Scheme, c.Username, c.Rules, c.ExtraHeaders, c.ForwardHeaders, c.Wildcard)
}

// The canonical policy is the same bytes in every implementation: Go writes
// these vectors (AGENTGATE_WRITE_WEB_FIXTURES=1) and web/qa/secretseal.node.mjs
// reproduces each canonical encoding and digest from the raw settings, and
// refuses every refused case.
func TestSecretPolicyVectors(t *testing.T) {
	cases := policyCases()
	for i := range cases {
		p, err := cases[i].build()
		if err != nil {
			t.Fatalf("%s: %v", cases[i].Name, err)
		}
		cases[i].Policy, cases[i].CanonicalHex, cases[i].Digest = &p, hex.EncodeToString(p.Canonical()), p.Digest()
	}
	refused := policyRefusals()
	for _, c := range refused {
		if _, err := c.build(); err == nil {
			t.Fatalf("%s: accepted", c.Name)
		}
	}
	raw, _ := json.MarshalIndent(map[string]any{"format": SecretPolicyFormat, "cases": cases, "refused": refused}, "", "  ")
	raw = append(raw, '\n')
	files := []string{filepath.Join("testdata", "secret-policy-vectors.json"), filepath.Join("..", "..", "web", "qa", "fixtures", "secret-policy-vectors.json")}
	for _, f := range files {
		if os.Getenv("AGENTGATE_WRITE_WEB_FIXTURES") == "1" {
			if err := os.WriteFile(f, raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		got, err := os.ReadFile(f)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("%s differs from the policies this build encodes (regenerate with AGENTGATE_WRITE_WEB_FIXTURES=1): %v", f, err)
		}
	}
}

func TestSecretPolicyNormalizesSpellingsAndRefusesAmbiguity(t *testing.T) {
	rules := []BrokerRule{{Methods: []string{"POST"}, Path: "/v1/messages", Match: "exact"}}
	base, err := NewSecretPolicy([]string{"api.example.test"}, "authorization", "Bearer", "", rules, map[string]string{"anthropic-version": "1"}, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	same, err := NewSecretPolicy([]string{"api.example.test:443"}, "Authorization", "", "", rules, map[string]string{"Anthropic-Version": "1"}, []string{}, false)
	if err != nil || same.Digest() != base.Digest() {
		t.Fatal("two spellings of one policy differ", err)
	}
	changes := map[string]func() (SecretPolicy, error){
		"upstream": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"collect.attacker.example"}, "authorization", "", "", rules, map[string]string{"anthropic-version": "1"}, nil, false)
		},
		"port": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test:8443"}, "authorization", "", "", rules, map[string]string{"anthropic-version": "1"}, nil, false)
		},
		"second upstream": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test", "collect.attacker.example"}, "authorization", "", "", rules, map[string]string{"anthropic-version": "1"}, nil, false)
		},
		"header": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test"}, "x-api-key", "", "", rules, map[string]string{"anthropic-version": "1"}, nil, false)
		},
		"scheme": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test"}, "authorization", "Basic", "u", rules, map[string]string{"anthropic-version": "1"}, nil, false)
		},
		"extra value": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test"}, "authorization", "", "", rules, map[string]string{"anthropic-version": "2"}, nil, false)
		},
		"forward": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test"}, "authorization", "", "", rules, map[string]string{"anthropic-version": "1"}, []string{"x-debug"}, false)
		},
		"rule path": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test"}, "authorization", "", "", []BrokerRule{{Methods: []string{"POST"}, Path: "/v1/", Match: "prefix"}}, map[string]string{"anthropic-version": "1"}, nil, false)
		},
		"rule method": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test"}, "authorization", "", "", []BrokerRule{{Methods: []string{"POST", "DELETE"}, Path: "/v1/messages", Match: "exact"}}, map[string]string{"anthropic-version": "1"}, nil, false)
		},
	}
	for name, change := range changes {
		p, err := change()
		if err != nil || p.Digest() == base.Digest() {
			t.Errorf("%s: %v (digest unchanged: %v)", name, err, err == nil && p.Digest() == base.Digest())
		}
	}
	for name, bad := range map[string]func() (SecretPolicy, error){
		"duplicate origin": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test", "api.example.test:443"}, "x-api-key", "", "", rules, nil, nil, false)
		},
		"duplicate extra": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test"}, "x-api-key", "", "", rules, map[string]string{"A": "1", "a": "2"}, nil, false)
		},
		"duplicate method": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test"}, "x-api-key", "", "", []BrokerRule{{Methods: []string{"GET", "GET"}, Path: "/", Match: "prefix"}}, nil, nil, false)
		},
		"unknown method": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test"}, "x-api-key", "", "", []BrokerRule{{Methods: []string{"*"}, Path: "/", Match: "prefix"}}, nil, nil, false)
		},
		"wildcard flag without the wildcard rule": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test"}, "x-api-key", "", "", rules, nil, nil, true)
		},
		"no upstream": func() (SecretPolicy, error) { return NewSecretPolicy(nil, "x-api-key", "", "", rules, nil, nil, false) },
		"upstream shape": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"Api.Example.test"}, "x-api-key", "", "", rules, nil, nil, false)
		},
		"duplicate forward": func() (SecretPolicy, error) {
			return NewSecretPolicy([]string{"api.example.test"}, "x-api-key", "", "", rules, nil, []string{"X-A", "x-a"}, false)
		},
	} {
		if _, err := bad(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Each field is its own length-prefixed field: no two policies share bytes.
	a, _ := NewSecretPolicy([]string{"ab.example.test"}, "x-api-key", "", "", []BrokerRule{{Methods: []string{"GET"}, Path: "/a", Match: "exact"}}, nil, nil, false)
	b, _ := NewSecretPolicy([]string{"ab.example.test"}, "x-api-key", "", "", []BrokerRule{{Methods: []string{"GET"}, Path: "/", Match: "exact"}, {Methods: []string{"GET"}, Path: "/a", Match: "exact"}}, nil, nil, false)
	if bytes.Equal(a.Canonical(), b.Canonical()) || !strings.HasPrefix(string(a.Canonical()[4:]), SecretPolicyFormat) {
		t.Fatal("the canonical encoding is ambiguous")
	}
}

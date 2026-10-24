// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"strings"
	"testing"
	"time"
)

func launchInput() LaunchInput {
	return LaunchInput{LaunchID: "lch-1", TargetID: "local", Deadline: testNow.Add(time.Hour),
		Listen:    Listen{Network: "tcp", Address: "172.30.7.2", Port: 8443, Subnet: "172.30.7.0/29"},
		StatsPath: "/var/lib/agentgate/broker/stats.json", RunAs: Identity{UID: 10002, GID: 10002},
		Secrets: []LaunchSecret{
			{Ref: "anthropic", Env: "ANTHROPIC_BASE_URL", Upstreams: []string{"api.example.test"}, Header: "x-api-key",
				SecretFile: "/run/agentgate/secrets/anthropic"},
			{Ref: "github", Env: "GITHUB_API_URL", Upstreams: []string{"api.github.example", "uploads.github.example:8443"},
				Header: "Authorization", SecretFile: "/run/agentgate/secrets/github",
				Rules: []Rule{{Methods: []string{"GET"}, Path: "/repos", Match: "prefix"}}},
		}}
}

func TestBuildLaunchConfigBindsOneSecretPerOrigin(t *testing.T) {
	raw, cfg, env, err := BuildLaunchConfig(launchInput(), testNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Routes) != 3 || cfg.Routes[0].Name != "anthropic" || cfg.Routes[1].Name != "github" || cfg.Routes[2].Name != "github-2" {
		t.Fatalf("%+v", cfg.Routes)
	}
	if cfg.Routes[2].Upstream.Port != 8443 || cfg.Routes[2].Credential.Scheme != "Bearer" ||
		cfg.Routes[0].Rules[0].Path != "/" || cfg.Routes[1].Rules[0].Path != "/repos" {
		t.Fatalf("%+v", cfg.Routes)
	}
	if env["ANTHROPIC_BASE_URL"] != "http://172.30.7.2:8443/anthropic" || env["GITHUB_API_URL"] != "http://172.30.7.2:8443/github" {
		t.Fatal(env)
	}
	if again, err := ParseConfig(raw); err != nil || ConfigDigest(raw) == "" || again.LaunchID != "lch-1" {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "value") {
		t.Fatal("config mentions a value")
	}
	bad := launchInput()
	bad.Secrets[0].Upstreams = []string{"169.254.169.254"}
	if _, _, _, err := BuildLaunchConfig(bad, testNow); err == nil {
		t.Fatal("address literal upstream accepted")
	}
	bad = launchInput()
	bad.Listen.Address = "0.0.0.0"
	if _, _, _, err := BuildLaunchConfig(bad, testNow); err == nil {
		t.Fatal("wildcard listen accepted")
	}
}

func TestBrokerCountsForTheReceipt(t *testing.T) {
	doc := &StatsDocument{Routes: map[string]*RouteStats{
		"anthropic": {Upstream: "api.example.test:443", Forwarded: 7},
		"github":    {Upstream: "api.github.example:443", Forwarded: 2},
		"github-2":  {Upstream: "uploads.github.example:8443", Forwarded: 1},
	}}
	got := BrokerCounts(doc)
	if got["api.example.test"] != 7 || got["api.github.example"] != 2 || got["uploads.github.example:8443"] != 1 || len(got) != 3 {
		t.Fatal(got)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"alloyium.local/kernel-poc/internal/controlclient"
	"alloyium.local/kernel-poc/internal/grant"
	"alloyium.local/kernel-poc/internal/workload"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestCustomerGrantBindsWorkloadAndPolicy(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	agent, _, _ := ed25519.GenerateKey(rand.Reader)
	job := workload.Job{Executable: "/usr/bin/dash", Arguments: []string{"-c", "printf example"}, Workspace: "/var/lib/customer-workspace"}
	cfg := controlclient.Config{Authority: controlclient.EncodeKey(public), Agent: "synthetic-agent", AgentKey: controlclient.EncodeKey(agent), RequestID: "synthetic-request"}
	nonce, _ := grant.Nonce()
	now := time.Now().Unix()
	c := grant.Claims{Issuer: grant.Issuer, Audience: grant.Audience, Deployment: "agentgate-community-v1", Node: "synthetic-node", Boot: "synthetic-boot", Run: "synthetic-run", Domain: "42", Agent: cfg.Agent, AgentKey: cfg.AgentKey, JobDigest: job.Digest(), Generation: "1", Workspace: job.Workspace + "/", Endpoint: "192.0.2.20:8443", DeadlineNS: "9007199254740993", Issued: now, Expires: now + 30, Nonce: nonce, PolicyVersion: strings.Repeat("a", 32), PolicyDigest: strings.Repeat("b", 64)}
	token, err := grant.Sign(c, key)
	if err != nil {
		t.Fatal(err)
	}
	admission := controllerAdmission{ID: nonce, RequestID: cfg.RequestID, RunID: c.Run, AgentID: c.Agent, VersionID: c.PolicyVersion, Digest: c.PolicyDigest, Token: token, State: "issued"}
	claims, err := verifyWorkloadAdmission(admission, cfg, job, c.Node, c.Boot, c.Run, 42, 9007199254740993)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := workloadPolicy(claims)
	if err != nil || policy.AllowedIP != 0x140200c0 || policy.AllowedPort != 0xfb20 {
		t.Fatalf("the customer compiler changed IPv4/TCP byte order: %+v %v", policy, err)
	}
	changed := job
	changed.Arguments = []string{"-c", "printf altered"}
	if _, err = verifyWorkloadAdmission(admission, cfg, changed, c.Node, c.Boot, c.Run, 42, 9007199254740993); err == nil {
		t.Fatal("another workload reused the signed admission")
	}
	admission.VersionID = strings.Repeat("c", 32)
	if _, err = verifyWorkloadAdmission(admission, cfg, job, c.Node, c.Boot, c.Run, 42, 9007199254740993); err == nil {
		t.Fatal("another version reused the signed admission")
	}
}
func TestCustomerRunRejectsUnqualifiedDenyAllBeforeLaunch(t *testing.T) {
	if err := runWorkload([]string{"/unavailable/object", "/unavailable/evidence", "/unavailable/config", "/unavailable/job"}); err != errDenyAllUnqualified {
		t.Fatal("the compatibility run reached input or kernel setup before deny-all qualification")
	}
}

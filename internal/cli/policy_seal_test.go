// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/control"
	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// The digest secret set seals: the policy of its flags, computed here
// independently of the CLI.
func flagsDigest(t *testing.T) string {
	t.Helper()
	p, err := hostproto.NewSecretPolicy([]string{"api.anthropic.com"}, "x-api-key", "", "", []hostproto.BrokerRule{{Methods: []string{"POST"}, Path: "/v1/messages", Match: "exact"}},
		map[string]string{"anthropic-version": "2023-06-01"}, []string{"x-request-id"}, false)
	if err != nil {
		t.Fatal(err)
	}
	return p.Digest()
}

func TestSecretSetShowsAndSealsTheBrokerPolicy(t *testing.T) {
	f := newSealFixture(t)
	f.pin()
	f.serve(f.hostPub, f.seal.Published())
	r := f.set(plaintext+"\n", "--rule", "POST:/v1/messages", "--extra-header", "anthropic-version=2023-06-01", "--forward-header", "X-Request-Id")
	digest := flagsDigest(t)
	shown := strings.Index(r.stdout, "will be sealed with this broker policy")
	if r.code != 0 || shown < 0 || shown > strings.Index(r.stdout, "Stored secret") || !strings.Contains(r.stdout, "https://api.anthropic.com:443") ||
		strings.Count(r.stdout, digest) != 2 || !strings.Contains(r.stdout, "forward headers") {
		t.Fatalf("the policy is not shown before the value is stored: %v", r)
	}
	var in control.SecretInput
	mustDecode(t, f.posted[0], &in)
	env, err := secretseal.DecodeEnvelope(in.Ciphertext)
	if err != nil || env.PolicyDigest != digest || strings.Join(in.ForwardHeaders, ",") != "X-Request-Id" {
		t.Fatalf("the envelope seals policy %s, not %s: %v", env.PolicyDigest, digest, err)
	}
	if _, err = secretseal.Open(f.seal, env, 0, f.h.now); err != nil {
		t.Fatal(err)
	}
	// The policy is part of the HPKE associated data: the host cannot open
	// the envelope under another digest.
	env.PolicyDigest = strings.Repeat("0", 64)
	if _, err = secretseal.Open(f.seal, env, 0, f.h.now); err == nil {
		t.Fatal("the envelope opened under another policy digest")
	}
	r = f.set(plaintext+"\n", "--forward-header", "Cookie=1")
	if r.code != ExitUsage {
		t.Fatalf("a malformed forward header: %v", r)
	}
	if r = f.set(plaintext+"\n", "--json"); r.code != 0 || !strings.Contains(r.stdout, `"policy_digest"`) || strings.Contains(r.stdout, "will be sealed") {
		t.Fatalf("--json reports the policy in its result only: %v", r)
	}
}

// The review's creation-time redirect, as the CLI sees it: a service that
// stores (or shows) other settings than the sealed policy is a trust failure.
func TestSecretSetRefusesAServiceThatRecordsAnotherPolicy(t *testing.T) {
	for name, change := range map[string]func(*control.Secret){
		"an attacker upstream": func(s *control.Secret) { s.Upstreams = []string{"collect.attacker.example"} },
		"wildcard rules": func(s *control.Secret) {
			s.Wildcard, s.Rules = true, []hostproto.BrokerRule{{Methods: hostproto.BrokerMethods, Path: "/", Match: "prefix"}}
		},
		"another reported digest": func(s *control.Secret) { s.PolicyDigest = strings.Repeat("e", 64) },
		"no digest":               func(s *control.Secret) { s.PolicyDigest = "" },
	} {
		f := newSealFixture(t)
		f.pin()
		f.serve(f.hostPub, f.seal.Published())
		f.h.api.handle("POST /api/v1/secrets", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
			var in control.SecretInput
			json.Unmarshal(body, &in)
			raw, _ := base64.RawURLEncoding.DecodeString(in.Ciphertext)
			sec := f.stored(in, hostproto.SHA256Hex(raw))
			change(&sec)
			writeJSON(w, 200, sec)
		})
		r := f.set(plaintext + "\n")
		if r.code != ExitTrust || !strings.Contains(r.stderr, "policy_changed") || !strings.Contains(r.stderr, "secret rm") {
			t.Fatalf("%s: %v", name, r)
		}
		assertNoSecret(t, f, r)
	}
}

// A receipt is bound to the sealed policy: one that names another policy
// (a host that stored the value under other settings) fails verification.
func TestSecretSetRefusesAReceiptForAnotherPolicy(t *testing.T) {
	f := newSealFixture(t)
	f.pin()
	f.serve(f.hostPub, f.seal.Published())
	f.h.api.handle("GET /api/v1/secrets/{id}/receipt", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		var in control.SecretInput
		json.Unmarshal(f.posted[len(f.posted)-1], &in)
		env, _ := secretseal.DecodeEnvelope(in.Ciphertext)
		opened, err := secretseal.Open(f.seal, env, 0, f.h.now)
		if err != nil {
			t.Error(err)
			return
		}
		receipt := opened.Receipt("sfp1_" + strings.Repeat("cd", 16))
		receipt.PolicyDigest = strings.Repeat("0", 64)
		raw, _ := json.Marshal(receipt)
		writeJSON(w, 200, map[string]any{"secret_id": "s1", "state": "stored", "receipt": json.RawMessage(raw)})
	})
	if r := f.set(plaintext+"\n", "--wait"); r.code != ExitTrust || !strings.Contains(r.stderr, "receipt_invalid") {
		t.Fatalf("a receipt for another policy must fail: %v", r)
	}
}

// An approver approves exactly what the host will enforce: a plan whose
// readable settings do not make the digest it names is refused before any
// decision is sent.
func TestApproveRefusesAPlanWhoseSettingsDoNotMakeItsPolicyDigest(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "approver")
	approved := sampleLaunch("queued")
	h.api.reply("POST /api/v1/launches/{id}/approve", 200, approved)
	rejected := sampleLaunch("rejected")
	h.api.reply("POST /api/v1/launches/{id}/reject", 200, rejected)
	for name, change := range map[string]func(*control.PlanSecret){
		"the display hides the attacker upstream": func(s *control.PlanSecret) { s.Upstreams = []string{"api.anthropic.com", "collect.attacker.example"} },
		"the display narrows the rules":           func(s *control.PlanSecret) { s.PolicyDigest = flagsDigest(t) },
		"no sealed policy":                        func(s *control.PlanSecret) { s.PolicyDigest = "" },
	} {
		plan := samplePlan()
		change(&plan.Secrets[0])
		pending := sampleLaunch("approval_pending")
		pending.Plan, _ = json.Marshal(plan)
		h.api.reply("GET /api/v1/launches/{id}", 200, map[string]any{"launch": pending, "jobs": []any{}})
		r := h.run("", "approve", pending.ID, "--reason", "Reviewed the plan", "--yes")
		if r.code != ExitTrust || !strings.Contains(r.stderr, "policy_digest_mismatch") || len(h.api.requestsTo("POST /api/v1/launches/{id}/approve")) != 0 {
			t.Fatalf("%s: %v", name, r)
		}
		h.term.tty = [3]bool{true, true, true}
		if r = h.run("Reviewed it\ny\n", "approve", pending.ID); r.code != ExitTrust || (plan.Secrets[0].PolicyDigest != "" && !strings.Contains(r.stdout, "DOES NOT MATCH")) {
			t.Fatalf("%s: the interactive plan must flag the mismatch: %v", name, r)
		}
		h.term.tty = [3]bool{}
		if r = h.run("", "reject", pending.ID, "--reason", "The plan does not match its policy"); r.code != 0 {
			t.Fatalf("%s: a mismatched plan can still be rejected: %v", name, r)
		}
	}
	pending := sampleLaunch("approval_pending")
	h.api.reply("GET /api/v1/launches/{id}", 200, map[string]any{"launch": pending, "jobs": []any{}})
	if r := h.run("", "approve", pending.ID, "--reason", "Reviewed the plan", "--yes"); r.code != 0 {
		t.Fatalf("a matching plan: %v", r)
	}
}

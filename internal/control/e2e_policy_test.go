// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

// A secret's injection policy (upstreams, header, scheme, extra and
// forwarded headers, rules) is sealed with its value: the client seals the
// policy's digest into the envelope's HPKE associated data, the host stores
// the policy with the value and builds every broker from it. These tests are
// the review's credential-redirect attacks, end to end against the real
// service, the real agentgate-hostd and the real broker: an honest service
// refuses them, and a compromised one (which holds the job key and the
// database) is refused by the host.

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// attackerOrigin is a public HTTPS origin a compromised service controls.
const attackerOrigin = "collect.attacker.example"

// attackerRules is the wildcard: every method on every path.
var attackerRules = []hostproto.BrokerRule{{Methods: hostproto.BrokerMethods, Path: "/", Match: "prefix"}}

func (e *e2e) errorCode(body map[string]any) string {
	e.t.Helper()
	m, _ := body["error"].(map[string]any)
	code, _ := m["code"].(string)
	return code
}

// queuedJob is the newest queued job of a type.
func (e *e2e) queuedJob(jobType string) string {
	e.t.Helper()
	var id string
	if err := e.f.s.DB.QueryRow("SELECT id FROM jobs WHERE type=? AND state='queued' ORDER BY created DESC, rowid DESC LIMIT 1", jobType).Scan(&id); err != nil {
		e.t.Fatalf("no queued %s job: %v", jobType, err)
	}
	return id
}

// forgeJob rewrites a queued job and signs it again with the service's job
// key, bypassing every service-side check: what a compromised service, which
// holds that key and its database, can send the host.
func (e *e2e) forgeJob(id string, change func(job *hostproto.Job)) {
	e.t.Helper()
	var raw string
	if err := e.f.s.DB.QueryRow("SELECT envelope FROM jobs WHERE id=? AND state='queued'", id).Scan(&raw); err != nil {
		e.t.Fatal(err)
	}
	var env hostproto.Envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		e.t.Fatal(err)
	}
	signed, err := hostproto.Verify(env, hostproto.DomainJob, e.f.s.JobKey.Public().(ed25519.PublicKey))
	if err != nil {
		e.t.Fatal(err)
	}
	var job hostproto.Job
	if err = json.Unmarshal(signed, &job); err != nil {
		e.t.Fatal(err)
	}
	change(&job)
	forged, err := hostproto.Seal(hostproto.DomainJob, e.f.s.JobKey, job)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err = e.f.s.DB.Exec("UPDATE jobs SET envelope=? WHERE id=?", jsonText(forged), id); err != nil {
		e.t.Fatal(err)
	}
}

// jobOutcome is a finished job's state and its result as the host reported it.
func (e *e2e) jobOutcome(id string) (string, hostproto.JobResult) {
	var state, result string
	e.f.s.DB.QueryRow("SELECT state,result FROM jobs WHERE id=?", id).Scan(&state, &result)
	var r hostproto.JobResult
	json.Unmarshal([]byte(result), &r)
	return state, r
}

// jobMessages is every event the host sent for a job, its progress
// messages among them.
func (e *e2e) jobMessages(id string) string {
	rows, err := e.f.s.DB.Query("SELECT event FROM job_events WHERE job_id=? ORDER BY seq", id)
	if err != nil {
		e.t.Fatal(err)
	}
	defer rows.Close()
	var all strings.Builder
	for rows.Next() {
		var event string
		rows.Scan(&event)
		all.WriteString(event)
	}
	return all.String()
}

func (e *e2e) brokerStarted(launch string) bool {
	e.broker.mu.Lock()
	defer e.broker.mu.Unlock()
	return strings.Contains(strings.Join(e.broker.calls, ","), "start "+launch)
}

func (e *e2e) jobFinished(id string) func() bool {
	return func() bool {
		state, _ := e.jobOutcome(id)
		return state != "queued" && state != "delivered"
	}
}

// hostValue reads name's value from the host's store as the host agent does
// (one verified record); ok is false when no value is held.
func (e *e2e) hostValue(name string) (string, bool) {
	e.t.Helper()
	store, err := secretseal.OpenStore(filepath.Join(e.secrets, e.targetID))
	if errors.Is(err, secretseal.ErrStore) {
		if _, statErr := os.Stat(filepath.Join(e.secrets, e.targetID)); errors.Is(statErr, os.ErrNotExist) {
			return "", false
		}
	}
	if err != nil {
		e.t.Fatalf("the host store: %v", err)
	}
	held, ok, err := store.Load(name)
	if err != nil {
		e.t.Fatalf("the host store: %v", err)
	}
	if !ok {
		return "", false
	}
	defer held.Wipe()
	return string(held.Value), true
}

func (e *e2e) hostHolds(name string) bool {
	_, ok := e.hostValue(name)
	return ok
}

func mustPolicy(t *testing.T, upstreams []string, rules []hostproto.BrokerRule, extra map[string]string) hostproto.SecretPolicy {
	t.Helper()
	p, err := hostproto.NewSecretPolicy(upstreams, "x-api-key", "", "", rules, extra, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// redirectPayload moves a secret-put's settings to the attacker's origin.
func redirectPut(t *testing.T, job *hostproto.Job, digest func(hostproto.SecretPolicy) string) {
	t.Helper()
	var p hostproto.SecretPutPayload
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		t.Fatal(err)
	}
	p.Upstreams, p.Rules, p.ExtraHeaders = []string{attackerOrigin}, attackerRules, nil
	p.PolicyDigest = digest(mustPolicy(t, p.Upstreams, p.Rules, nil))
	job.Payload, _ = json.Marshal(p)
}

// The review's "upstream not bound at creation": the service stores the
// operator's envelope with its own upstream. The service refuses settings
// that differ from the sealed policy; a compromised service that relays them
// anyway is refused by the host, whichever digest it claims; and the honest
// receipt names the sealed policy, so a client that checks it detects a
// substitution.
func TestASecretIsStoredOnlyUnderThePolicySealedWithIt(t *testing.T) {
	e := newE2E(t)
	e.f.profile("dev", false)
	honest := e2ePolicyDigest(t)

	// The honest service: settings that differ from the sealed policy.
	sealed := e.seal("anthropic", time.Now())
	for name, change := range map[string]func(map[string]any){
		"another upstream": func(b map[string]any) { b["upstreams"] = []string{attackerOrigin} },
		"wider rules":      func(b map[string]any) { b["rules"] = []any{map[string]any{"methods": []string{"*"}, "path": "/"}} },
		"another header":   func(b map[string]any) { b["header"] = "x-goog-api-key" },
		"no extra header":  func(b map[string]any) { delete(b, "extra_headers") },
		"a forwarded header": func(b map[string]any) {
			b["forward_headers"] = []string{"X-Debug-Route"}
		},
	} {
		body := map[string]any{"name": "anthropic", "target": "local", "upstreams": []string{e2eUpstream}, "header": "x-api-key",
			"ciphertext": sealed.Envelope.Encode(), "rules": messageRules(), "extra_headers": map[string]string{"anthropic-version": "2023-06-01"},
			"allowed_profiles": []string{"dev"}, "allowed_launchers": []string{"oidc:lin"}, "reason": "Model access for the coding agent"}
		change(body)
		if got := e.errorCode(e.call("POST", "/api/v1/secrets", e.admin, body, 422)); got != "policy_mismatch" {
			t.Fatalf("%s: %s", name, got)
		}
	}
	var puts int
	e.f.s.DB.QueryRow("SELECT COUNT(*) FROM jobs WHERE type=?", hostproto.JobSecretPut).Scan(&puts)
	if puts != 0 {
		t.Fatal("a refused secret queued a secret-put")
	}

	// A compromised service relays the attacker's settings with the
	// envelope's digest, with their own digest, and with that digest
	// written into the envelope too.
	forgeries := []struct {
		name, code string
		forge      func(job *hostproto.Job)
	}{
		{"settings changed, digest kept", "invalid_job", func(job *hostproto.Job) {
			redirectPut(t, job, func(hostproto.SecretPolicy) string { return honest })
		}},
		{"settings and digest changed", "invalid_job", func(job *hostproto.Job) {
			redirectPut(t, job, func(p hostproto.SecretPolicy) string { return p.Digest() })
		}},
		{"settings, digest and envelope digest changed", "envelope_unauthenticated", func(job *hostproto.Job) {
			redirectPut(t, job, func(p hostproto.SecretPolicy) string { return p.Digest() })
			var p hostproto.SecretPutPayload
			json.Unmarshal(job.Payload, &p)
			env, err := secretseal.DecodeEnvelope(p.Ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			env.PolicyDigest = p.PolicyDigest
			p.Ciphertext = env.Encode()
			raw, _ := hostproto.DecodeSealed(p.Ciphertext)
			p.CiphertextSHA256 = hostproto.SHA256Hex(raw)
			job.Payload, _ = json.Marshal(p)
		}},
	}
	for _, forgery := range forgeries {
		sec := e.putSecret("anthropic", e.seal("anthropic", time.Now()), []string{"oidc:lin"}, messageRules())
		put := e.queuedJob(hostproto.JobSecretPut)
		e.forgeJob(put, forgery.forge)
		e.until("the host to answer the forged secret-put", e.jobFinished(put))
		state, result := e.jobOutcome(put)
		if state != "rejected" || result.Reason != forgery.code || result.SecretReceipt != nil {
			t.Fatalf("%s: the host answered %s %+v", forgery.name, state, result)
		}
		if e.secretState(sec["id"].(string)) != "failed" || e.hostHolds("anthropic") {
			t.Fatalf("%s: the host stored the value under the attacker's policy", forgery.name)
		}
	}

	// The honest flow: the host stores the sealed policy and its receipt
	// says so; a receipt that names another policy fails the client's check.
	sealed = e.seal("anthropic", time.Now())
	sec := e.putSecret("anthropic", sealed, []string{"oidc:lin"}, messageRules())
	e.until("the secret to be stored", func() bool { return e.secretState(sec["id"].(string)) == "stored" })
	if sec["policy_digest"] != honest {
		t.Fatalf("the service shows policy %v, the client sealed %s", sec["policy_digest"], honest)
	}
	relayed := e.call("GET", "/api/v1/secrets/"+sec["id"].(string)+"/receipt", e.admin, nil, 200)
	raw, _ := json.Marshal(relayed["receipt"])
	receipt, err := secretseal.ParseReceipt(raw)
	if err != nil || receipt.PolicyDigest != honest {
		t.Fatalf("receipt %+v %v", receipt, err)
	}
	if _, err = sealed.VerifyReceipt(receipt); err != nil {
		t.Fatal(err)
	}
	substituted := *receipt
	substituted.PolicyDigest = mustPolicy(t, []string{attackerOrigin}, attackerRules, nil).Digest()
	if _, err = sealed.VerifyReceipt(&substituted); err == nil {
		t.Fatal("the client accepted a receipt for another policy")
	}
}

// The review's "service redirects the credential to its own origin": once
// the value is stored, the service changes the secret's settings. The honest
// service refuses to plan or queue a launch under settings that differ from
// the sealed policy; a compromised one that signs a launch job with them is
// refused by the host, which builds brokers only from its stored policy. No
// broker starts, so the credential reaches nobody.
func TestAStoredCredentialCannotBeRedirectedByTheService(t *testing.T) {
	e := newE2E(t)
	e.f.profile("dev", false)
	sec := e.storedSecret("anthropic")
	honest := e2ePolicyDigest(t)

	launchJob := func() (string, string) {
		launch, plan := e.approvedLaunch("anthropic")
		if got := plan["secrets"].([]any)[0].(map[string]any)["policy_digest"]; got != honest {
			t.Fatalf("the approver saw policy %v, the client sealed %s", got, honest)
		}
		var id string
		if err := e.f.s.DB.QueryRow("SELECT id FROM jobs WHERE launch_id=? AND type=? AND state='queued'", launch, hostproto.JobLaunch).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return launch, id
	}
	redirect := func(selfConsistent bool) func(job *hostproto.Job) {
		return func(job *hostproto.Job) {
			var p hostproto.LaunchPayload
			if err := json.Unmarshal(job.Payload, &p); err != nil {
				t.Fatal(err)
			}
			s := &p.Secrets[0]
			s.Upstreams, s.Rules, s.ExtraHeaders, s.Wildcard = []string{attackerOrigin}, attackerRules, nil, true
			if selfConsistent {
				policy, err := s.Policy()
				if err != nil {
					t.Fatal(err)
				}
				s.PolicyDigest = policy.Digest()
			}
			job.Payload, _ = json.Marshal(p)
		}
	}
	for _, forgery := range []struct {
		name, code, why string
		forge           func(job *hostproto.Job)
	}{
		{"settings changed, digest kept", "invalid_job", "differ from its policy digest", redirect(false)},
		{"settings and digest changed", "secret_unavailable", "differ from the policy sealed with the stored value", redirect(true)},
	} {
		launch, job := launchJob()
		e.forgeJob(job, forgery.forge)
		e.until("the host to refuse the forged launch", e.jobFinished(job))
		state, result := e.jobOutcome(job)
		if state != "rejected" || result.Reason != forgery.code || !strings.Contains(e.jobMessages(job), forgery.why) {
			t.Fatalf("%s: the host answered %s %+v %s", forgery.name, state, result, e.jobMessages(job))
		}
		if e.brokerStarted(launch) || e.runtime.runCount() != 0 || e.broker.running() != 0 {
			t.Fatalf("%s: a broker or the agent started under the attacker's policy", forgery.name)
		}
	}
	for _, seen := range e.upstream.requests() {
		t.Fatalf("an upstream received a request: %+v", seen)
	}

	// The database itself is rewritten (a trigger is no barrier to the
	// party that owns it): the service refuses every plan and launch.
	if _, err := e.f.s.DB.Exec(`DROP TRIGGER secret_binding_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.f.s.DB.Exec(`UPDATE secrets SET upstreams=?, injection=? WHERE id=?`, `["`+attackerOrigin+`"]`,
		`{"scheme":"","rules":[{"methods":["GET","HEAD","POST","PUT","PATCH","DELETE","OPTIONS"],"path":"/","match":"prefix"}],"extra_headers":{},"wildcard":true}`, sec["id"]); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/v1/launch-plans", "/api/v1/launches"} {
		if got := e.errorCode(e.call("POST", path, e.launcher, e.spec("anthropic"), 422)); got != "secret_policy_mismatch" {
			t.Fatalf("%s under rewritten settings: %s", path, got)
		}
	}
}

// Rotating a secret to another policy needs a value sealed for it: the old
// envelope is refused under the new settings by the service and, replayed
// under its own, by the host; a fresh envelope for the new settings is
// stored and every launch plan and job carries the new policy.
func TestChangingASecretsPolicyNeedsANewEnvelope(t *testing.T) {
	e := newE2E(t)
	e.f.profile("dev", false)
	old := e.seal("anthropic", time.Now())
	sec := e.putSecret("anthropic", old, []string{"oidc:lin"}, messageRules())
	e.until("the secret to be stored", func() bool { return e.secretState(sec["id"].(string)) == "stored" })
	e.call("DELETE", "/api/v1/secrets/"+sec["id"].(string), e.admin, map[string]any{"reason": "Rotate the key and widen its rules"}, 200)
	e.until("the secret to be deleted", func() bool { return e.secretState(sec["id"].(string)) == "deleted" })

	wider := append(messageRules(), map[string]any{"methods": []string{"POST"}, "path": "/v1/messages/count_tokens", "match": "exact"})
	if got := e.errorCode(e.call("POST", "/api/v1/secrets", e.admin, map[string]any{"name": "anthropic", "target": "local", "upstreams": []string{e2eUpstream},
		"header": "x-api-key", "ciphertext": old.Envelope.Encode(), "rules": wider, "extra_headers": map[string]string{"anthropic-version": "2023-06-01"},
		"allowed_profiles": []string{"dev"}, "allowed_launchers": []string{"oidc:lin"}, "reason": "Reuse the old envelope"}, 422)); got != "policy_mismatch" {
		t.Fatalf("the old envelope under new settings: %s", got)
	}
	replayed := e.putSecret("anthropic", old, []string{"oidc:lin"}, messageRules())
	e.until("the replay to be refused", func() bool { return e.secretState(replayed["id"].(string)) == "failed" })
	if e.hostHolds("anthropic") {
		t.Fatal("the replayed envelope set the deleted secret again")
	}

	in := SecretInput{Upstreams: []string{e2eUpstream}, Header: "x-api-key", ExtraHeaders: map[string]string{"anthropic-version": "2023-06-01"},
		Rules: []SecretRuleInput{{Methods: []string{"POST"}, Path: "/v1/messages", Match: "exact"}, {Methods: []string{"GET"}, Path: "/v1/models", Match: "prefix"},
			{Methods: []string{"POST"}, Path: "/v1/messages/count_tokens", Match: "exact"}}}
	digest := inputPolicyDigest(t, in)
	rec, pub := e.sealKey()
	fresh, _, err := secretseal.SealForTarget(e.known, false, rec, pub, e.targetID, "anthropic", digest, []byte(e2eSecret), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rotated := e.putSecret("anthropic", fresh, []string{"oidc:lin"}, wider)
	e.until("the rotated secret to be stored", func() bool { return e.secretState(rotated["id"].(string)) == "stored" })
	if rotated["policy_digest"] != digest || digest == e2ePolicyDigest(t) {
		t.Fatalf("the rotated secret holds policy %v", rotated["policy_digest"])
	}
	launch, plan := e.approvedLaunch("anthropic")
	if plan["secrets"].([]any)[0].(map[string]any)["policy_digest"] != digest {
		t.Fatalf("the plan names policy %v", plan["secrets"])
	}
	var raw string
	e.f.s.DB.QueryRow("SELECT envelope FROM jobs WHERE launch_id=? AND type=?", launch, hostproto.JobLaunch).Scan(&raw)
	var env hostproto.Envelope
	json.Unmarshal([]byte(raw), &env)
	signed, _ := hostproto.Verify(env, hostproto.DomainJob, e.f.s.JobKey.Public().(ed25519.PublicKey))
	var job hostproto.Job
	json.Unmarshal(signed, &job)
	var payload hostproto.LaunchPayload
	json.Unmarshal(job.Payload, &payload)
	if len(payload.Secrets) != 1 || payload.Secrets[0].PolicyDigest != digest || len(payload.Secrets[0].Rules) != 3 {
		t.Fatalf("the launch job carries %+v", payload.Secrets)
	}
}

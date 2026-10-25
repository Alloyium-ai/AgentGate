// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/pocpolicy"
	"alloyium.local/kernel-poc/internal/secretseal"
)

func auditCount(f *provFixture, action string) int {
	var n int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action=?", action).Scan(&n)
	return n
}

func TestSealKeyIsStoredOnlyWhenTheHostSignedItAndServedVerbatim(t *testing.T) {
	f := newProv(t)
	h, target := f.enrolledTarget()
	// A record signed by another key (what a service of its own would need).
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	forged, err := secretseal.HostKeyFromECDH(h.id, h.enc, other, f.now(), 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	genuine := h.sealKey
	h.sealKey = forged
	h.poll()
	h.poll()
	if _, err := f.s.TargetSealKey("local"); errCode(err) != "seal_key_unavailable" {
		t.Fatal("a seal key not signed by the host key was stored")
	}
	if n := auditCount(f, "target.seal_key.rejected"); n != 1 {
		t.Fatalf("a rejected record was audited %d times", n)
	}
	// A record for another target, signed by the right key.
	elsewhere, _ := secretseal.HostKeyFromECDH(strings.Repeat("9", 32), h.enc, h.key, f.now(), 30*24*time.Hour)
	h.sealKey = elsewhere
	h.poll()
	if _, err := f.s.TargetSealKey("local"); errCode(err) != "seal_key_unavailable" {
		t.Fatal("a seal key for another target was stored")
	}
	h.sealKey = genuine
	h.poll()
	got := must(f.s.TargetSealKey("local"))
	want, _ := json.Marshal(genuine.Published())
	if !bytes.Equal(got["record"].(json.RawMessage), want) || got["host_public_key"] != hostproto.EncodeKey(h.key.Public().(ed25519.PublicKey)) ||
		got["host_key_fingerprint"] != secretseal.HostKeyFingerprint(h.key.Public().(ed25519.PublicKey)) || got["seal_key_id"] != genuine.Record().KeyID {
		t.Fatalf("seal key %v", got)
	}
	if auditCount(f, "target.seal_key.published") != 1 {
		t.Fatal("publication not audited once")
	}
	h.poll()
	if auditCount(f, "target.seal_key.published") != 1 {
		t.Fatal("an unchanged record was stored again")
	}
	detail := must(f.s.TargetDetail("local"))
	if detail.SealKeyID != genuine.Record().KeyID || !bytes.Equal(detail.SealKey, want) || detail.HostPublicKey == "" {
		t.Fatalf("target detail %+v", detail)
	}
	// The API serves it to viewers; a CLI or UI verifies it itself.
	tok := f.token(f.viewer(), "viewer")
	resp, body := f.apiRequest("GET", "/api/v1/targets/"+target.ID+"/seal-key", tok, nil)
	if resp.StatusCode != 200 || body["seal_key_id"] != genuine.Record().KeyID {
		t.Fatalf("seal-key endpoint %d %v", resp.StatusCode, body)
	}
	raw, _ := json.Marshal(body["record"])
	rec, err := secretseal.ParseSignedKeyRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secretseal.VerifyKeyRecord(rec, h.key.Public().(ed25519.PublicKey), secretseal.HostKeyFingerprint(h.key.Public().(ed25519.PublicKey)), target.ID, f.now()); err != nil {
		t.Fatalf("the served record does not verify: %v", err)
	}
	// Enrolling again with a new host key drops the record the old key signed.
	token := must(f.s.IssueEnrollment(f.admin(), "local", ReasonInput{Reason: "Reinstall the host"})).(map[string]any)["enrollment"].(map[string]any)["token"].(string)
	again := newHost(f)
	if _, err := again.enroll(token); err != nil {
		t.Fatal(err)
	}
	var stored string
	f.s.DB.QueryRow("SELECT seal_key FROM targets WHERE id=?", target.ID).Scan(&stored)
	if stored != "" {
		t.Fatal("a re-enrolled target kept the old key's seal record")
	}
}

func TestSecretCreationRefusesEnvelopesTheHostWouldRefuse(t *testing.T) {
	f := newProv(t)
	h, target := f.enrolledTarget()
	p := f.profile("dev", false)
	in := secretInput("model-api", &secretseal.Sealed{Envelope: secretseal.Envelope{}}, p.Name)
	in.Ciphertext = hostproto.EncodeSealed(bytes.Repeat([]byte{1}, 120))
	if _, err := f.s.CreateSecret(f.admin(), in); errCode(err) != "invalid_ciphertext" {
		t.Fatalf("an old-format ciphertext was accepted: %v", err)
	}
	// The host has not published a seal key yet.
	genuine := h.sealKey
	h.sealKey = nil
	h.poll()
	h.sealKey = genuine
	pub, _ := secretseal.GenerateHostKey(target.ID, h.key, f.now(), time.Hour)
	rec := pub.Published()
	verified, err := secretseal.VerifyKeyRecord(&rec, h.key.Public().(ed25519.PublicKey), secretseal.HostKeyFingerprint(h.key.Public().(ed25519.PublicKey)), target.ID, f.now())
	if err != nil {
		t.Fatal(err)
	}
	early, _ := secretseal.SealAt(verified, target.ID, "model-api", defaultPolicyDigest(), []byte("synthetic-credential-0123456789"), f.now())
	in = secretInput("model-api", early, p.Name)
	if _, err := f.s.CreateSecret(f.admin(), in); errCode(err) != "seal_key_unavailable" {
		t.Fatalf("a secret was accepted before the host published a seal key: %v", err)
	}
	h.poll()
	// Sealed to a key the target does not publish.
	if _, err := f.s.CreateSecret(f.admin(), in); errCode(err) != "seal_key_changed" {
		t.Fatalf("an envelope for another seal key was accepted: %v", err)
	}
	sealed := f.sealFor(h, "model-api", "synthetic-credential-0123456789")
	renamed := secretInput("other-api", sealed, p.Name)
	if _, err := f.s.CreateSecret(f.admin(), renamed); errCode(err) != "invalid_ciphertext" {
		t.Fatalf("an envelope sealed for another name was accepted: %v", err)
	}
	bad := map[string]func(*SecretInput){
		"bearer on x-api-key": func(s *SecretInput) { s.Scheme = "Bearer" },
		"basic without user":  func(s *SecretInput) { s.Header, s.Scheme = "Authorization", "Basic" },
		"connect": func(s *SecretInput) {
			s.Rules = []SecretRuleInput{{Methods: []string{"CONNECT"}, Path: "/", Match: "prefix"}}
		},
		"encoded path": func(s *SecretInput) {
			s.Rules = []SecretRuleInput{{Methods: []string{"GET"}, Path: "/a%2fb", Match: "exact"}}
		},
		"missing match":        func(s *SecretInput) { s.Rules = []SecretRuleInput{{Methods: []string{"GET"}, Path: "/v1"}} },
		"wildcard with a path": func(s *SecretInput) { s.Rules = []SecretRuleInput{{Methods: []string{"*"}, Path: "/v1"}} },
		"wildcard and others": func(s *SecretInput) {
			s.Rules = []SecretRuleInput{{Methods: []string{"*"}, Path: "/"}, {Methods: []string{"GET"}, Path: "/x", Match: "exact"}}
		},
		"extra credential":      func(s *SecretInput) { s.ExtraHeaders = map[string]string{"Authorization": "Bearer x"} },
		"local upstream":        func(s *SecretInput) { s.Upstreams = []string{"metadata.internal"} },
		"numeric upstream":      func(s *SecretInput) { s.Upstreams = []string{"169.254.169.254"} },
		"basic colon user name": func(s *SecretInput) { s.Header, s.Scheme, s.Username = "Authorization", "Basic", "a:b" },
	}
	for name, change := range bad {
		in := secretInput("model-api", sealed, p.Name)
		change(&in)
		if _, err := f.s.CreateSecret(f.admin(), in); err == nil {
			t.Errorf("%s: accepted", name)
		} else if code := errCode(err); code != "invalid_secret" && code != "invalid_ciphertext" {
			t.Errorf("%s: %s", name, code)
		}
	}
	// Bearer is stored explicitly for an Authorization header.
	in = secretInput("model-api", nil, p.Name)
	in.Header = "Authorization"
	sec := must(f.s.CreateSecret(f.admin(), f.sealInput(h, in, "synthetic-credential-0123456789"))).(Secret)
	if sec.Scheme != "Bearer" {
		t.Fatalf("scheme %q", sec.Scheme)
	}
	// The HTTP API takes the same shape.
	tok := f.token(f.admin(), "admin")
	httpIn := f.sealInput(h, SecretInput{Name: "http-api", Target: "local", Upstreams: []string{"api.model.example"}, Header: "x-api-key",
		Rules: []SecretRuleInput{{Methods: []string{"*"}, Path: "/"}}, ExtraHeaders: map[string]string{"anthropic-version": "2023-06-01"}}, "synthetic-credential-0123456789")
	body, _ := json.Marshal(map[string]any{"name": "http-api", "target": "local", "upstreams": []string{"api.model.example"}, "header": "x-api-key",
		"ciphertext": httpIn.Ciphertext, "rules": []any{map[string]any{"methods": []string{"*"}, "path": "/"}},
		"extra_headers": map[string]string{"anthropic-version": "2023-06-01"}, "allowed_profiles": []string{"dev"}, "allowed_launchers": []string{"oidc:lin"}, "reason": "Store over HTTP"})
	resp, out := f.apiRequest("POST", "/api/v1/secrets", tok, body)
	if resp.StatusCode != 200 || out["wildcard_rules"] != true || out["scheme"] != "" {
		t.Fatalf("HTTP secret %d %v", resp.StatusCode, out)
	}
	for _, field := range []string{`"rules":[{"methods":["*"],"path":"/","match":"exact"}]`, `"extra_headers":{"anthropic-version":7}`, `"scheme":"Token"`} {
		raw := bytes.Replace(body, []byte(`"rules":[{"methods":["*"],"path":"/"}]`), []byte(field), 1)
		raw = bytes.Replace(raw, []byte(`"name":"http-api"`), []byte(`"name":"http-api-2"`), 1)
		if resp, _ := f.apiRequest("POST", "/api/v1/secrets", tok, raw); resp.StatusCode != 422 {
			t.Errorf("%s: %d", field, resp.StatusCode)
		}
	}
}

// storeSecret creates a secret and completes its secret-put with a receipt.
func (f *provFixture) storeSecret(h *fakeHost, in SecretInput, sealed *secretseal.Sealed) Secret {
	f.t.Helper()
	sec := must(f.s.CreateSecret(f.admin(), in)).(Secret)
	put := h.poll()[0]
	var payload hostproto.SecretPutPayload
	json.Unmarshal(put.Payload, &payload)
	env, err := secretseal.DecodeEnvelope(payload.Ciphertext)
	if err != nil {
		f.t.Fatal(err)
	}
	receipt, err := h.hostStore().Accept(h.sealKey, env, f.now())
	if err != nil {
		f.t.Fatal(err)
	}
	r := ev(1, f, hostproto.EventResult)
	hr := hostproto.SecretReceipt(*receipt)
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stored", SecretReceipt: &hr}
	must(h.events(put.ID, r))
	return must(scanSecret(f.s.DB.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", sec.ID)))
}

func TestSecretPutReceiptMustAnswerTheRelayedEnvelope(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	p := f.profile("dev", false)
	h.poll()
	sealed := f.sealFor(h, "model-api", "synthetic-credential-0123456789")
	sec := must(f.s.CreateSecret(f.admin(), secretInput("model-api", sealed, p.Name))).(Secret)
	put := h.poll()[0]
	// A receipt for another envelope (an older version) does not store it.
	other := hostproto.SecretReceipt{Format: hostproto.SecretReceiptFormat, TargetID: h.id, Name: "model-api", Version: sealed.Envelope.Version - 1,
		KeyID: sealed.Envelope.KeyID, Nonce: sealed.Envelope.Nonce, PolicyDigest: sealed.Envelope.PolicyDigest, Fingerprint: "sfp1_" + strings.Repeat("a", 32), Tag: hostproto.EncodeSealed(make([]byte, 32))}
	r := ev(1, f, hostproto.EventResult)
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stored", SecretReceipt: &other}
	must(h.events(put.ID, r))
	got := must(scanSecret(f.s.DB.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", sec.ID)))
	if got.State != "failed" || len(got.Receipt) != 0 || auditCount(f, "secret.store.failed") != 1 {
		t.Fatalf("a mismatched receipt stored the secret: %+v", got)
	}
	// A receipt for the relayed envelope that names another policy (a host
	// that stored the value under settings the client did not seal) does not
	// store it either.
	sealed = f.sealFor(h, "model-api", "synthetic-credential-0123456789")
	repolicied := must(f.s.CreateSecret(f.admin(), secretInput("model-api", sealed, p.Name))).(Secret)
	put = h.poll()[0]
	var relayed hostproto.SecretPutPayload
	json.Unmarshal(put.Payload, &relayed)
	env, err := secretseal.DecodeEnvelope(relayed.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := h.hostStore().Accept(h.sealKey, env, f.now())
	if err != nil {
		t.Fatal(err)
	}
	wrong := hostproto.SecretReceipt(*accepted)
	wrong.PolicyDigest = strings.Repeat("0", 64)
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stored", SecretReceipt: &wrong}
	must(h.events(put.ID, r))
	if got := must(scanSecret(f.s.DB.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", repolicied.ID))); got.State != "failed" || len(got.Receipt) != 0 {
		t.Fatalf("a receipt for another policy stored the secret: %+v", got)
	}
	// A success without a receipt fails closed too.
	sealed = f.sealFor(h, "model-api", "synthetic-credential-0123456789")
	again := must(f.s.CreateSecret(f.admin(), secretInput("model-api", sealed, p.Name))).(Secret)
	put = h.poll()[0]
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stored"}
	must(h.events(put.ID, r))
	if got := must(scanSecret(f.s.DB.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", again.ID))); got.State != "failed" {
		t.Fatalf("a receipt-less success stored the secret: %s", got.State)
	}
	// A receipt for exactly the relayed envelope stores it.
	stored := f.storeSecret(h, secretInput("model-api", f.sealFor(h, "model-api", "synthetic-credential-0123456789"), p.Name), nil)
	if stored.State != "stored" || stored.ValueFingerprint == "" {
		t.Fatalf("stored %+v", stored)
	}
}

func TestBrokerLaunchPlansRulesEndpointAndPolicy(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	p := f.profile("dev", false)
	h.poll()
	noRules := secretInput("bare-api", nil, p.Name)
	noRules.Rules = nil
	f.storeSecret(h, f.sealInput(h, noRules, "synthetic-credential-0123456789"), nil)
	m := specMap("dev")
	m["secrets"] = []any{map[string]any{"ref": "bare-api", "expose": map[string]any{"env": "BARE_BASE_URL"}}}
	if _, err := f.s.CreateLaunch(f.launcher(), specBytes(t, m)); errCode(err) != "secret_rules_missing" {
		t.Fatalf("a secret without rules was planned: %v", err)
	}
	if _, err := f.s.PlanLaunch(f.launcher(), specBytes(t, m)); errCode(err) != "secret_rules_missing" {
		t.Fatalf("a dry run planned a secret without rules: %v", err)
	}
	wild := secretInput("wild-api", nil, p.Name)
	wild.Rules = []SecretRuleInput{{Methods: []string{"*"}, Path: "/"}}
	f.storeSecret(h, f.sealInput(h, wild, "synthetic-credential-0123456789"), nil)
	exact := f.storeSecret(h, secretInput("model-api", f.sealFor(h, "model-api", "synthetic-credential-0123456789"), p.Name), nil)
	m["secrets"] = []any{map[string]any{"ref": "model-api", "expose": map[string]any{"env": "MODEL_BASE_URL"}}, map[string]any{"ref": "wild-api", "expose": map[string]any{"env": "WILD_BASE_URL"}}}
	l, plan := f.launch(f.launcher(), m)
	if plan.Broker == nil || plan.Broker != nil && *plan.Broker != brokerEndpoint(l.ID) {
		t.Fatalf("broker endpoint %+v", plan.Broker)
	}
	warned := false
	for _, n := range plan.Notices {
		warned = warned || strings.Contains(n, "WARNING: secret wild-api uses wildcard rules")
	}
	if !warned || !strings.Contains(strings.Join(plan.ApprovalReasons, ";"), "secret wild-api has wildcard broker rules") || !plan.Secrets[1].Wildcard {
		t.Fatalf("the wildcard is not flagged: %v %v", plan.Notices, plan.ApprovalReasons)
	}
	detail := f.state(l.ID)
	doc, err := pocpolicy.Parse(detail.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if doc.Broker == nil || doc.Broker.Address != plan.Broker.Address || doc.Broker.Port != 8443 || doc.Taskboard != (pocpolicy.Taskboard{}) || doc.Digest() != l.PolicyDigest {
		t.Fatalf("launch policy endpoint %+v %+v", doc.Broker, doc.Taskboard)
	}
	must(f.s.DecideLaunch(f.approver(), l.ID, true, DecisionInput{Reason: "Reviewed the broker rules"}))
	jobs := h.poll()
	var launch hostproto.Job
	for _, j := range jobs {
		if j.Type == hostproto.JobLaunch {
			launch = j
		}
	}
	var payload hostproto.LaunchPayload
	json.Unmarshal(launch.Payload, &payload)
	if len(payload.Secrets) != 2 || len(payload.Secrets[0].Rules) != 2 || payload.Secrets[0].SecretID != exact.ID || len(payload.Secrets[1].Rules) != 1 ||
		len(payload.Secrets[1].Rules[0].Methods) != 7 {
		t.Fatalf("launch job secrets %+v", payload.Secrets)
	}
	// A receipt with broker evidence outside the plan is refused; a matching one ends the launch.
	receipt := h.receipt(launch, true)
	evidence := &hostproto.BrokerEvidence{Version: hostproto.BrokerEvidenceVersion, ConfigSHA256: strings.Repeat("c", 64), Listen: "tcp:" + plan.Broker.Address + ":8443",
		State: "stopped", StopReason: "signal", Complete: true, StartedAt: "2026-10-24T20:00:00Z", UpdatedAt: "2026-10-24T20:01:00Z",
		Requests: hostproto.BrokerRequests{Total: 2, Forwarded: 2}, Denied: map[string]uint64{},
		Routes: map[string]hostproto.BrokerRouteEvidence{"model-api": {Upstream: "api.model.example:443", Requests: 2, Forwarded: 2, Status: map[string]uint64{"2xx": 2}, Errors: map[string]uint64{}}}}
	foreign := *receipt
	foreign.BrokerCounts = map[string]uint64{"api.model.example": 2}
	moved := *evidence
	moved.Listen = "tcp:172.30.0.2:8443"
	foreign.BrokerEvidence = &moved
	r := ev(1, f, hostproto.EventResult)
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "exited", Receipt: &foreign}
	if _, err := h.events(launch.ID, r); errCode(err) != "invalid_receipt" {
		t.Fatalf("broker evidence for another endpoint was accepted: %v", err)
	}
	good := *receipt
	good.BrokerCounts = map[string]uint64{"api.model.example": 2}
	good.BrokerEvidence = evidence
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "exited", Receipt: &good}
	must(h.events(launch.ID, r))
	if got := f.state(l.ID); got.State != StateStopped || !bytes.Contains(got.Receipt, []byte(`"broker_evidence"`)) || got.KernelVerified {
		t.Fatalf("launch %s %s", got.State, got.Receipt)
	}
	// Broker evidence on a launch without secrets is refused.
	plain, _ := f.launch(f.launcher(), specMap("dev"))
	var plainJob hostproto.Job
	for _, j := range h.poll() {
		if j.Type == hostproto.JobLaunch && j.LaunchID == plain.ID {
			plainJob = j
		}
	}
	extra := *h.receipt(plainJob, true)
	extra.BrokerCounts = map[string]uint64{"api.model.example": 2}
	extra.BrokerEvidence = evidence
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "exited", Receipt: &extra}
	if _, err := h.events(plainJob.ID, r); errCode(err) != "invalid_receipt" {
		t.Fatalf("broker evidence for a launch without secrets: %v", err)
	}
}

func TestBrokerEndpointsAreDeterministicPerLaunchAndInsideThePool(t *testing.T) {
	pool := netip.MustParsePrefix(brokerPoolText)
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		b := brokerEndpoint(newID())
		subnet := netip.MustParsePrefix(b.Subnet)
		addr, target := netip.MustParseAddr(b.Address), netip.MustParseAddr(b.TargetAddress)
		base := subnet.Addr().As4()
		if subnet.Bits() != 29 || !pool.Contains(subnet.Addr()) || !subnet.Contains(addr) || !subnet.Contains(target) || b.Port != 8443 ||
			addr.As4()[3] != base[3]+2 || target.As4()[3] != base[3]+3 || subnet.Addr() == pool.Addr() {
			t.Fatalf("endpoint %+v", b)
		}
		if err := pocpolicy.ValidBrokerEndpoint(b.Address, "tcp", b.Port); err != nil {
			t.Fatal(err)
		}
		seen[b.Subnet] = true
	}
	if len(seen) < 1500 {
		t.Fatalf("only %d distinct subnets for 2000 launches", len(seen))
	}
	if brokerEndpoint("abc") != brokerEndpoint("abc") {
		t.Fatal("the endpoint is not deterministic")
	}
}

func TestSchemaSixMigratesAVersionFiveDatabase(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	// Rebuild the version five shape: no broker columns or triggers.
	for _, stmt := range []string{"DROP TRIGGER secret_binding_immutable", "DROP TRIGGER secret_receipt_once", "DROP TRIGGER target_seal_key_json",
		"ALTER TABLE secrets DROP COLUMN injection", "ALTER TABLE secrets DROP COLUMN envelope", "ALTER TABLE secrets DROP COLUMN receipt",
		"ALTER TABLE targets DROP COLUMN seal_key",
		"CREATE TRIGGER secret_binding_immutable BEFORE UPDATE OF id,name,target_id,upstreams,header,fingerprint,allowed_profiles,allowed_launchers,created,created_by ON secrets BEGIN SELECT RAISE(ABORT,'immutable secret metadata'); END",
		"PRAGMA user_version=5"} {
		if _, err := f.s.DB.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	f.http.Close()
	f.s.DB.Close()
	s, err := OpenStore(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	var version, targets int
	s.DB.QueryRow("PRAGMA user_version").Scan(&version)
	s.DB.QueryRow("SELECT count(*) FROM targets WHERE seal_key=''").Scan(&targets)
	if version != SchemaVersion || targets != 1 {
		t.Fatalf("version %d targets %d", version, targets)
	}
	for _, trigger := range []string{"secret_receipt_once", "target_seal_key_json", "secret_binding_immutable"} {
		var sql string
		if err := s.DB.QueryRow("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", trigger).Scan(&sql); err != nil {
			t.Fatalf("trigger %s: %v", trigger, err)
		}
		if trigger == "secret_binding_immutable" && !strings.Contains(sql, "injection,envelope") {
			t.Fatal("the secret binding trigger does not cover the injection rules")
		}
	}
	if _, err := s.DB.Exec("UPDATE targets SET seal_key='not json'"); err == nil {
		t.Fatal("a non-JSON seal key record was stored")
	}
	s.DB.Close()
	if s, err = OpenStore(f.dir); err != nil {
		t.Fatal(err)
	}
	var migrations int
	s.DB.QueryRow("SELECT count(*) FROM audit WHERE request_id='migration-6'").Scan(&migrations)
	if migrations != 2 {
		t.Fatalf("migration six recorded %d times", migrations)
	}
}

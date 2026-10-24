// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostproto

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleEvidence() *BrokerEvidence {
	return &BrokerEvidence{Version: BrokerEvidenceVersion, ConfigSHA256: strings.Repeat("c", 64), Listen: "tcp:172.30.7.2:8443", State: "stopped",
		StopReason: "signal", Complete: true, StartedAt: "2026-10-24T20:00:00.104Z", UpdatedAt: "2026-10-24T20:10:00.002Z",
		Hardening:   &BrokerHardening{UID: 10002, GID: 10002, NotDumpable: true, CoreLimitZero: true, NoNewPrivs: true, NoCapabilities: true},
		Connections: BrokerConnections{Accepted: 5}, Requests: BrokerRequests{Total: 5, Denied: 1, Forwarded: 4},
		Denied: map[string]uint64{"path_not_allowed": 1},
		Routes: map[string]BrokerRouteEvidence{
			"model-api":   {Upstream: "api.model.example:443", Requests: 4, Forwarded: 3, Status: map[string]uint64{"2xx": 3}, Errors: map[string]uint64{}, BytesIn: 10, BytesOut: 20},
			"model-api-2": {Upstream: "uploads.model.example:8443", Requests: 1, Forwarded: 1, Status: map[string]uint64{"2xx": 1}, Errors: map[string]uint64{}},
		}, DenialsRecorded: 1}
}

func TestReceiptBrokerEvidenceMustMatchItsCounts(t *testing.T) {
	job := sampleJobs(t)[JobLaunch]
	r := Receipt{Version: ReceiptVersion, LaunchID: launchID, TargetID: targetID, SpecDigest: job.SpecDigest, PolicyDigest: job.PolicyDigest,
		BPFObjects: map[string]string{}, Mounts: []MountIdentity{}, Reason: "exited",
		BrokerCounts: map[string]uint64{"api.model.example": 3, "uploads.model.example:8443": 1}, BrokerEvidence: sampleEvidence()}
	if err := r.Check(job); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Receipt){
		"counts without evidence": func(r *Receipt) { r.BrokerEvidence = nil },
		"inflated count":          func(r *Receipt) { r.BrokerCounts["api.model.example"] = 4 },
		"extra upstream":          func(r *Receipt) { r.BrokerCounts["evil.example"] = 0 },
		"missing upstream":        func(r *Receipt) { delete(r.BrokerCounts, "uploads.model.example:8443") },
		"version":                 func(r *Receipt) { r.BrokerEvidence.Version = "v0" },
		"config digest":           func(r *Receipt) { r.BrokerEvidence.ConfigSHA256 = "x" },
		"listen":                  func(r *Receipt) { r.BrokerEvidence.Listen = "tcp:0.0.0.0" },
		"state":                   func(r *Receipt) { r.BrokerEvidence.State = "exploded" },
		"stop reason":             func(r *Receipt) { r.BrokerEvidence.StopReason = "because" },
		"time":                    func(r *Receipt) { r.BrokerEvidence.StartedAt = "yesterday" },
		"denial code":             func(r *Receipt) { r.BrokerEvidence.Denied = map[string]uint64{"Bad Code": 1} },
		"denial sum":              func(r *Receipt) { r.BrokerEvidence.Denied = map[string]uint64{"path_not_allowed": 2} },
		"nil routes":              func(r *Receipt) { r.BrokerEvidence.Routes = nil },
		"forwarded sum": func(r *Receipt) {
			route := r.BrokerEvidence.Routes["model-api"]
			route.Forwarded = 2
			r.BrokerEvidence.Routes["model-api"] = route
		},
		"route upstream": func(r *Receipt) {
			route := r.BrokerEvidence.Routes["model-api"]
			route.Upstream = "api.model.example"
			r.BrokerEvidence.Routes["model-api"] = route
		},
		"status class": func(r *Receipt) {
			route := r.BrokerEvidence.Routes["model-api"]
			route.Status = map[string]uint64{"200": 3}
			r.BrokerEvidence.Routes["model-api"] = route
		},
		"route name": func(r *Receipt) {
			r.BrokerEvidence.Routes["Model API"] = r.BrokerEvidence.Routes["model-api"]
			delete(r.BrokerEvidence.Routes, "model-api")
		},
		"missing with data": func(r *Receipt) { r.BrokerEvidence.Missing = "broker_stats" },
	}
	for name, change := range cases {
		bad := r
		bad.BrokerCounts = map[string]uint64{}
		for k, v := range r.BrokerCounts {
			bad.BrokerCounts[k] = v
		}
		evidence := *sampleEvidence()
		bad.BrokerEvidence = &evidence
		change(&bad)
		if bad.Check(job) == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	missing := r
	missing.BrokerCounts = map[string]uint64{}
	missing.BrokerEvidence = &BrokerEvidence{Version: BrokerEvidenceVersion, Missing: "broker_stats"}
	if err := missing.Check(job); err != nil {
		t.Fatalf("missing broker stats: %v", err)
	}
	raw, _ := json.Marshal(r)
	for _, forbidden := range []string{`"body"`, `"headers"`, `"query"`, `"path"`, `"denials":[`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("broker evidence carries %s", forbidden)
		}
	}
}

func TestSecretPutBindsTheEnvelopeToTargetAndName(t *testing.T) {
	now := fixedNow.Add(time.Minute)
	put := sampleJobs(t)[JobSecretPut]
	if _, err := put.Check(targetID, now); err != nil {
		t.Fatal(err)
	}
	var p SecretPutPayload
	json.Unmarshal(put.Payload, &p)
	other := p
	other.Name = "other-api"
	bad := put
	bad.Payload = raw(t, other)
	if _, err := bad.Check(targetID, now); err == nil {
		t.Fatal("an envelope sealed for another name was relayed")
	}
	var e SealedEnvelope
	sealed, _ := DecodeSealed(p.Ciphertext)
	json.Unmarshal(sealed, &e)
	e.TargetID = strings.Repeat("9", 32)
	moved, _ := json.Marshal(e)
	p2 := p
	p2.Ciphertext, p2.CiphertextSHA256 = EncodeSealed(moved), SHA256Hex(moved)
	bad.Payload = raw(t, p2)
	if _, err := bad.Check(targetID, now); err == nil {
		t.Fatal("an envelope sealed for another target was relayed")
	}
}

func TestLaunchSecretsNeedExplicitValidInjectionRules(t *testing.T) {
	now := fixedNow.Add(time.Minute)
	launch := sampleJobs(t)[JobLaunch]
	if _, err := launch.Check(targetID, now); err != nil {
		t.Fatal(err)
	}
	var p LaunchPayload
	json.Unmarshal(launch.Payload, &p)
	cases := map[string]func(*LaunchSecret){
		"no rules":        func(s *LaunchSecret) { s.Rules = nil },
		"empty rules":     func(s *LaunchSecret) { s.Rules = []BrokerRule{} },
		"wildcard method": func(s *LaunchSecret) { s.Rules = []BrokerRule{{Methods: []string{"*"}, Path: "/", Match: "prefix"}} },
		"connect": func(s *LaunchSecret) {
			s.Rules = []BrokerRule{{Methods: []string{"CONNECT"}, Path: "/", Match: "prefix"}}
		},
		"repeated method": func(s *LaunchSecret) {
			s.Rules = []BrokerRule{{Methods: []string{"GET", "GET"}, Path: "/", Match: "prefix"}}
		},
		"no match": func(s *LaunchSecret) { s.Rules = []BrokerRule{{Methods: []string{"GET"}, Path: "/"}} },
		"encoded path": func(s *LaunchSecret) {
			s.Rules = []BrokerRule{{Methods: []string{"GET"}, Path: "/a%2fb", Match: "exact"}}
		},
		"dot segment": func(s *LaunchSecret) {
			s.Rules = []BrokerRule{{Methods: []string{"GET"}, Path: "/a/../b", Match: "exact"}}
		},
		"empty segment": func(s *LaunchSecret) {
			s.Rules = []BrokerRule{{Methods: []string{"GET"}, Path: "/a//b", Match: "exact"}}
		},
		"relative":             func(s *LaunchSecret) { s.Rules = []BrokerRule{{Methods: []string{"GET"}, Path: "v1", Match: "exact"}} },
		"bearer on x-api-key":  func(s *LaunchSecret) { s.Scheme = "Bearer" },
		"basic without user":   func(s *LaunchSecret) { s.Header, s.Scheme = "authorization", "Basic" },
		"basic colon user":     func(s *LaunchSecret) { s.Header, s.Scheme, s.Username = "authorization", "Basic", "a:b" },
		"username without":     func(s *LaunchSecret) { s.Username = "x" },
		"unknown scheme":       func(s *LaunchSecret) { s.Header, s.Scheme = "authorization", "Token" },
		"extra credential":     func(s *LaunchSecret) { s.ExtraHeaders = map[string]string{"Authorization": "Bearer x"} },
		"extra same header":    func(s *LaunchSecret) { s.ExtraHeaders = map[string]string{"X-API-KEY": "x"} },
		"extra forwarding":     func(s *LaunchSecret) { s.ExtraHeaders = map[string]string{"X-Forwarded-For": "1.2.3.4"} },
		"extra value newline":  func(s *LaunchSecret) { s.ExtraHeaders = map[string]string{"anthropic-version": "a\nb"} },
		"extra value empty":    func(s *LaunchSecret) { s.ExtraHeaders = map[string]string{"anthropic-version": ""} },
		"extra value unicode":  func(s *LaunchSecret) { s.ExtraHeaders = map[string]string{"anthropic-version": "é"} },
		"extra value trailing": func(s *LaunchSecret) { s.ExtraHeaders = map[string]string{"anthropic-version": "1 "} },
	}
	for name, change := range cases {
		bad := p
		secret := p.Secrets[0]
		secret.ExtraHeaders = map[string]string{}
		change(&secret)
		bad.Secrets = []LaunchSecret{secret}
		job := launch
		job.Payload = raw(t, bad)
		if _, err := job.Check(targetID, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := p
	basic := p.Secrets[0]
	basic.Header, basic.Scheme, basic.Username = "Authorization", "Basic", "x-access-token"
	basic.Rules = []BrokerRule{{Methods: []string{"GET", "POST"}, Path: "/example-org/app.git", Match: "prefix"}, {Methods: []string{"GET"}, Path: "/", Match: "exact"}}
	good.Secrets = []LaunchSecret{basic}
	job := launch
	job.Payload = raw(t, good)
	if _, err := job.Check(targetID, now); err != nil {
		t.Fatalf("a Basic secret with rules: %v", err)
	}
	twice := p
	second := p.Secrets[0]
	second.Ref = "model-api-two"
	twice.Secrets = []LaunchSecret{p.Secrets[0], second}
	job.Payload = raw(t, twice)
	if _, err := job.Check(targetID, now); err == nil {
		t.Fatal("two secrets shared one environment variable")
	}
}

func TestSecretReceiptShapeAndResultRules(t *testing.T) {
	r := SecretReceipt{Format: SecretReceiptFormat, TargetID: targetID, Name: "model-api", Version: 7, KeyID: strings.Repeat("ab", 32),
		Nonce: strings.Repeat("0f", 16), Fingerprint: "sfp1_" + strings.Repeat("1", 32), Tag: b64.EncodeToString(make([]byte, 32))}
	if err := r.Check(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*SecretReceipt){
		"format": func(r *SecretReceipt) { r.Format = "x" }, "fingerprint": func(r *SecretReceipt) { r.Fingerprint = "sha256:1" },
		"tag": func(r *SecretReceipt) { r.Tag = "short" }, "version": func(r *SecretReceipt) { r.Version = 0 },
		"name": func(r *SecretReceipt) { r.Name = "A" }, "key": func(r *SecretReceipt) { r.KeyID = "k" },
	} {
		bad := r
		change(&bad)
		if bad.Check() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	h := Header{HostID: targetID, Nonce: fixedNonce, TimestampMS: fixedNow.UnixMilli(), Sequence: 3}
	ok := JobResult{Status: ResultSucceeded, Reason: "stored", SecretReceipt: &r}
	if err := (EventsRequest{Header: h, JobID: launchID, Events: []Event{{Seq: 1, TimeMS: 1, Kind: EventResult, Result: &ok}}}).Check(fixedNow); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []JobResult{
		{Status: ResultFailed, Reason: "x", SecretReceipt: &r},
		{Status: ResultSucceeded, Reason: "x", SecretReceipt: &r, EvidenceMissing: "y"},
		{Status: ResultSucceeded, Reason: "x", SecretReceipt: &SecretReceipt{}},
	} {
		if (EventsRequest{Header: h, JobID: launchID, Events: []Event{{Seq: 1, TimeMS: 1, Kind: EventResult, Result: &bad}}}).Check(fixedNow) == nil {
			t.Errorf("result %+v accepted", bad)
		}
	}
	var e SealedEnvelope
	json.Unmarshal(sealedFixture(t), &e)
	answer := SecretReceipt{TargetID: e.TargetID, Name: e.Name, Version: e.Version, KeyID: e.KeyID, Nonce: e.Nonce}
	if !answer.Answers(e) {
		t.Fatal("a receipt for the envelope does not answer it")
	}
	answer.Version++
	if answer.Answers(e) {
		t.Fatal("a receipt for another version answers the envelope")
	}
}

func TestHeartbeatSealKeyIsBoundedAndCapabilityKnown(t *testing.T) {
	poll := PollRequest{Header: Header{HostID: targetID, Nonce: fixedNonce, TimestampMS: fixedNow.UnixMilli(), Sequence: 7},
		Heartbeat: Heartbeat{Capabilities: []string{CapabilityDocker, CapabilityBrokeredSecrets}, RunningLaunches: []string{}, AgentVersion: "0.1.0",
			SealKey: json.RawMessage(`{"record":{},"signature":"x"}`)}, MaxJobs: 4}
	if err := poll.Check(fixedNow); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`[]`, `"x"`, `{"a":` + strings.Repeat(" ", MaxSealKeyRecordBytes) + `1}`} {
		poll.Heartbeat.SealKey = json.RawMessage(bad)
		if poll.Check(fixedNow) == nil {
			t.Errorf("seal key %.20q accepted", bad)
		}
	}
}

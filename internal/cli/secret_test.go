// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/control"
	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

const plaintext = "sk-test-SECRET-VALUE-0123456789"

type sealFixture struct {
	h       *harness
	target  control.Target
	hostPub ed25519.PublicKey
	hostKey ed25519.PrivateKey
	boxKey  *ecdh.PrivateKey
	seal    *secretseal.HostKey
	posted  [][]byte
}

func newSealFixture(t *testing.T) *sealFixture {
	h := newHarness(t)
	h.login("local:ada", "admin")
	f := &sealFixture{h: h}
	f.hostPub, f.hostKey, _ = ed25519.GenerateKey(rand.Reader)
	f.boxKey, _ = ecdh.X25519().GenerateKey(rand.Reader)
	f.target = sampleTarget("active")
	f.target.HostKeyID = hostproto.KeyID(f.hostPub)
	f.target.EncryptionKey = hostproto.EncodeKey(f.boxKey.PublicKey().Bytes())
	var err error
	if f.seal, err = secretseal.GenerateHostKey(f.target.ID, f.hostKey, h.now, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	h.api.handle("POST /api/v1/secrets", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		f.posted = append(f.posted, body)
		var in control.SecretInput
		json.Unmarshal(body, &in)
		raw, _ := base64.RawURLEncoding.DecodeString(in.Ciphertext)
		writeJSON(w, 200, control.Secret{ID: "s1", Name: in.Name, TargetID: f.target.ID, Upstreams: in.Upstreams, Header: in.Header, Fingerprint: hostproto.SHA256Hex(raw), AllowedProfiles: in.AllowedProfiles, AllowedLaunchers: in.AllowedLaunchers, State: "pending"})
	})
	return f
}

// serve answers GET /targets/{id} with the target and GET /targets/{id}/seal-key
// with the key material (or 404 when hostPub is nil and record is nil).
func (f *sealFixture) serve(hostPub ed25519.PublicKey, record any) {
	f.h.api.reply("GET /api/v1/targets/{id}", 200, f.target)
	if hostPub == nil && record == nil {
		f.h.api.handle("GET /api/v1/targets/{id}/seal-key", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
			apiError(w, 404, "seal_key_unavailable", "The target's host has not published a host-signed seal key yet.")
		})
		return
	}
	m := map[string]any{"record": record, "target_id": f.target.ID, "host_key_id": f.target.HostKeyID}
	if hostPub != nil {
		m["host_public_key"] = hostproto.EncodeKey(hostPub)
		m["host_key_fingerprint"] = secretseal.HostKeyFingerprint(hostPub)
	}
	f.h.api.reply("GET /api/v1/targets/{id}/seal-key", 200, m)
}

func (f *sealFixture) pin() {
	st := store{dir: f.h.dir, euid: os.Geteuid()}
	if _, err := st.pin(KnownTarget{Server: f.h.api.URL(), TargetID: f.target.ID, TargetName: f.target.Name, HostKeyID: f.target.HostKeyID, Source: "test"}, true); err != nil {
		f.h.t.Fatal(err)
	}
}

// set runs secret set with one broker rule unless extra names the rules.
func (f *sealFixture) set(stdin string, extra ...string) result {
	args := []string{"secret", "set", "anthropic", "--upstream", "api.anthropic.com", "--allow-profile", "python-dev", "--allow-launcher", "local:lin", "--verbose"}
	rules := false
	for _, a := range extra {
		rules = rules || a == "--rule" || a == "--allow-any-path"
	}
	if !rules {
		args = append(args, "--rule", "POST:/v1/messages")
	}
	return f.h.run(stdin, append(args, extra...)...)
}

func assertNoSecret(t *testing.T, f *sealFixture, r result) {
	t.Helper()
	if strings.Contains(r.stdout+r.stderr, plaintext) {
		t.Fatalf("the secret value reached the output:\n%v", r)
	}
	for _, req := range f.h.api.requests() {
		if strings.Contains(string(req.Body), plaintext) || strings.Contains(req.Path+req.Query.Encode(), plaintext) {
			t.Fatalf("the secret value was sent in clear to %s %s", req.Method, req.Path)
		}
		for _, values := range req.Header {
			for _, v := range values {
				if strings.Contains(v, plaintext) {
					t.Fatal("the secret value was sent in a header")
				}
			}
		}
	}
	if strings.Contains(strings.Join(os.Args, " "), plaintext) {
		t.Fatal("the secret value is in the process arguments")
	}
}

func TestSecretSetSealsToTheHostSignedKey(t *testing.T) {
	f := newSealFixture(t)
	f.pin()
	f.serve(f.hostPub, f.seal.Published())
	r := f.set(plaintext + "\n")
	if r.code != 0 || !strings.Contains(r.stdout, f.target.HostKeyID+" (pinned)") || !strings.Contains(r.stdout, sealMethodSigned) {
		t.Fatalf("%v", r)
	}
	assertNoSecret(t, f, r)
	var in control.SecretInput
	mustDecode(t, f.posted[0], &in)
	env, err := secretseal.DecodeEnvelope(in.Ciphertext)
	if err != nil {
		t.Fatalf("the ciphertext is not a secretseal envelope: %v", err)
	}
	opened, err := secretseal.Open(f.seal, env, 0, f.h.now)
	if err != nil || string(opened.Value) != plaintext {
		t.Fatalf("the host cannot open the envelope: %v", err)
	}
	if in.Target != f.target.ID || in.Header != "x-api-key" || in.AllowedLaunchers[0] != "local:lin" || len(in.Reason) < 3 {
		t.Fatalf("%+v", in)
	}
}

func TestSecretSetRefusesAMaliciousService(t *testing.T) {
	attackerPub, attackerKey, _ := ed25519.GenerateKey(rand.Reader)
	cases := map[string]func(f *sealFixture) (ed25519.PublicKey, any){
		// The service swaps in its own host key and a seal key it signed.
		"substituted host key": func(f *sealFixture) (ed25519.PublicKey, any) {
			k, _ := secretseal.GenerateHostKey(f.target.ID, attackerKey, f.h.now, time.Hour)
			return attackerPub, k.Published()
		},
		// The service keeps the real host key but offers its own seal key.
		"substituted seal key": func(f *sealFixture) (ed25519.PublicKey, any) {
			k, _ := secretseal.GenerateHostKey(f.target.ID, attackerKey, f.h.now, time.Hour)
			rec := k.Published()
			rec.Record.HostKey = secretseal.HostKeyFingerprint(f.hostPub)
			return f.hostPub, rec
		},
		// A genuine record for another target.
		"record for another target": func(f *sealFixture) (ed25519.PublicKey, any) {
			k, _ := secretseal.GenerateHostKey("another-target", f.hostKey, f.h.now, time.Hour)
			return f.hostPub, k.Published()
		},
		// A genuine record that has expired.
		"expired record": func(f *sealFixture) (ed25519.PublicKey, any) {
			k, _ := secretseal.GenerateHostKey(f.target.ID, f.hostKey, f.h.now.Add(-48*time.Hour), time.Hour)
			return f.hostPub, k.Published()
		},
		"key without a record": func(f *sealFixture) (ed25519.PublicKey, any) { return f.hostPub, nil },
	}
	for name, attack := range cases {
		t.Run(name, func(t *testing.T) {
			f := newSealFixture(t)
			f.pin()
			pub, rec := attack(f)
			f.serve(pub, rec)
			r := f.set(plaintext + "\n")
			if r.code != ExitTrust || !strings.Contains(r.stderr, "Nothing was sent") && !strings.Contains(r.stderr, "nothing was sent") {
				t.Fatalf("%v", r)
			}
			if len(f.posted) != 0 {
				t.Fatal("a secret was submitted despite the failed key check")
			}
			assertNoSecret(t, f, r)
		})
	}
}

func TestSecretSetPinChecks(t *testing.T) {
	f := newSealFixture(t)
	f.serve(f.hostPub, f.seal.Published())
	if r := f.set(plaintext + "\n"); r.code != ExitTrust || !strings.Contains(r.stderr, "target pin local") {
		t.Fatalf("an unpinned target: %v", r)
	}
	f.pin()
	moved := f.target
	moved.HostKeyID = "ed25519:" + strings.Repeat("7", 32)
	f.h.api.reply("GET /api/v1/targets/{id}", 200, moved)
	if r := f.set(plaintext + "\n"); r.code != ExitTrust || !strings.Contains(r.stderr, "host_key_pin_mismatch") {
		t.Fatalf("a re-keyed target: %v", r)
	}
	if len(f.posted) != 0 {
		t.Fatal("submitted")
	}
}

func TestSecretSetRefusesWithoutAPublishedSealKey(t *testing.T) {
	f := newSealFixture(t)
	f.pin()
	f.serve(nil, nil)
	r := f.set(plaintext + "\n")
	if r.code != ExitTrust || !strings.Contains(r.stderr, "seal_key_unpublished") || !strings.Contains(r.stderr, "Nothing was read or sent") || len(f.posted) != 0 {
		t.Fatalf("%v", r)
	}
	assertNoSecret(t, f, r)
	if r = f.set(plaintext+"\n", "--allow-unsigned-key"); r.code != ExitUsage {
		t.Fatalf("there is no way to seal to an unsigned key: %v", r)
	}
}

func TestSecretSetBearerSchemeAndFingerprintPin(t *testing.T) {
	f := newSealFixture(t)
	f.pin()
	f.serve(f.hostPub, f.seal.Published())
	r := f.set(plaintext+"\n", "--header", "Authorization", "--scheme", "Bearer")
	if r.code != 0 {
		t.Fatalf("%v", r)
	}
	var in control.SecretInput
	mustDecode(t, f.posted[0], &in)
	env, _ := secretseal.DecodeEnvelope(in.Ciphertext)
	opened, err := secretseal.Open(f.seal, env, 0, f.h.now)
	if err != nil || string(opened.Value) != plaintext || in.Header != "Authorization" || in.Scheme != "Bearer" {
		t.Fatalf("the scheme is a field, never part of the value: %q %+v (%v)", opened.Value, in, err)
	}
	st := store{dir: f.h.dir, euid: os.Geteuid()}
	k, _ := st.loadTrust()
	if pin := k.find(f.h.api.URL(), f.target.ID); pin == nil || pin.HostKeyFingerprint != secretseal.HostKeyFingerprint(f.hostPub) {
		t.Fatalf("the verified SHA256 fingerprint is recorded next to the pin: %+v", pin)
	}
}

func TestSecretSetInputRules(t *testing.T) {
	f := newSealFixture(t)
	f.pin()
	f.serve(f.hostPub, f.seal.Published())
	if r := f.h.run("", "secret", "set", "anthropic", "--value", plaintext, "--upstream", "api.anthropic.com", "--allow-profile", "p"); r.code != ExitUsage {
		t.Fatalf("there is no value flag: %v", r)
	}
	f.h.env["AGENTGATE_SECRET"] = plaintext
	if r := f.set(""); r.code != ExitUsage || !strings.Contains(r.stderr, "standard input was empty") {
		t.Fatalf("the value never comes from the environment: %v", r)
	}
	if r := f.set(plaintext+"\n", "--scheme", "Bearer"); r.code != ExitUsage || !strings.Contains(r.stderr, "--header Authorization") {
		t.Fatalf("%v", r)
	}
	f.h.term.tty = [3]bool{true, true, true}
	f.h.term.secrets = [][]byte{[]byte(plaintext), []byte(plaintext + "x")}
	if r := f.set(""); r.code != ExitUsage || !strings.Contains(r.stderr, "differ") || len(f.posted) != 0 {
		t.Fatalf("mismatching entries: %v", r)
	}
	f.h.term.secrets = [][]byte{[]byte(plaintext), []byte(plaintext)}
	r := f.set("")
	if r.code != 0 || len(f.posted) != 1 {
		t.Fatalf("%v", r)
	}
	assertNoSecret(t, f, r)
	if !strings.Contains(strings.Join(f.h.term.prompts, "|"), "input hidden") {
		t.Fatal("the terminal prompt does not say the input is hidden")
	}
}

func TestSecretSetDetectsAChangedCiphertext(t *testing.T) {
	f := newSealFixture(t)
	f.pin()
	f.serve(f.hostPub, f.seal.Published())
	f.h.api.handle("POST /api/v1/secrets", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		writeJSON(w, 200, control.Secret{ID: "s1", Name: "anthropic", TargetID: f.target.ID, Fingerprint: strings.Repeat("0", 64), State: "pending"})
	})
	if r := f.set(plaintext + "\n"); r.code != ExitTrust || !strings.Contains(r.stderr, "ciphertext_changed") {
		t.Fatalf("%v", r)
	}
}

func TestSecretSetUsesTheServiceInjectionFieldsAndVerifiesTheReceipt(t *testing.T) {
	f := newSealFixture(t)
	f.pin()
	f.serve(f.hostPub, f.seal.Published())
	var receipt json.RawMessage
	f.h.api.handle("GET /api/v1/secrets/{id}/receipt", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		if receipt == nil {
			var in control.SecretInput
			json.Unmarshal(f.posted[len(f.posted)-1], &in)
			env, _ := secretseal.DecodeEnvelope(in.Ciphertext)
			opened, err := secretseal.Open(f.seal, env, 0, f.h.now)
			if err != nil {
				t.Fatal(err)
			}
			receipt, _ = json.Marshal(opened.Receipt("sfp1_" + strings.Repeat("ab", 16)))
			apiError(w, 404, "receipt_unavailable", "The host has not returned a receipt for this secret (state pending).")
			return
		}
		writeJSON(w, 200, map[string]any{"secret_id": "s1", "state": "stored", "value_fingerprint": "sfp1_" + strings.Repeat("ab", 16), "receipt": receipt})
	})
	f.h.api.reply("GET /api/v1/secrets", 200, map[string]any{"items": []control.Secret{{ID: "s1", Name: "anthropic", State: "pending"}}})
	r := f.set(plaintext+"\n", "--header", "Authorization", "--scheme", "Bearer", "--rule", "POST:/v1/messages:exact", "--rule", "get,head:/v1/models:prefix", "--extra-header", "anthropic-version=2023-06-01", "--wait")
	if r.code != 0 || !strings.Contains(r.stdout, "receipt verifies") || !strings.Contains(r.stdout, "sfp1_abab") {
		t.Fatalf("%v", r)
	}
	assertNoSecret(t, f, r)
	var body map[string]json.RawMessage
	mustDecode(t, f.posted[len(f.posted)-1], &body)
	if string(body["scheme"]) != `"Bearer"` || string(body["rules"]) != `[{"methods":["POST"],"path":"/v1/messages","match":"exact"},{"methods":["GET","HEAD"],"path":"/v1/models","match":"prefix"}]` || string(body["extra_headers"]) != `{"anthropic-version":"2023-06-01"}` {
		t.Fatalf("%s", f.posted[len(f.posted)-1])
	}
	var in control.SecretInput
	mustDecode(t, f.posted[len(f.posted)-1], &in)
	env, _ := secretseal.DecodeEnvelope(in.Ciphertext)
	opened, _ := secretseal.Open(f.seal, env, 0, f.h.now)
	if string(opened.Value) != plaintext {
		t.Fatal("with a scheme field the value is sent without a scheme prefix")
	}

	// A receipt for another envelope (a relay that swapped the ciphertext)
	// fails verification.
	receipt = nil
	f.h.api.handle("GET /api/v1/secrets/{id}/receipt", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		other, _ := secretseal.GenerateHostKey(f.target.ID, f.hostKey, f.h.now, time.Hour)
		pub, _ := secretseal.VerifyKeyRecord(ptr(other.Published()), f.hostPub, secretseal.HostKeyFingerprint(f.hostPub), f.target.ID, f.h.now)
		forged, _ := secretseal.SealAt(pub, f.target.ID, "anthropic", []byte("attacker-key"), f.h.now)
		opened, _ := secretseal.Open(other, &forged.Envelope, 0, f.h.now)
		raw, _ := json.Marshal(opened.Receipt("sfp1_" + strings.Repeat("cd", 16)))
		writeJSON(w, 200, map[string]any{"secret_id": "s1", "state": "stored", "receipt": json.RawMessage(raw)})
	})
	if r = f.set(plaintext+"\n", "--allow-any-path", "--wait"); r.code != ExitTrust || !strings.Contains(r.stderr, "receipt_invalid") {
		t.Fatalf("a receipt for another envelope must fail: %v", r)
	}
	mustDecode(t, f.posted[len(f.posted)-1], &body)
	if string(body["rules"]) != `[{"methods":["*"],"path":"/"}]` {
		t.Fatalf("the wildcard spelling: %s", body["rules"])
	}
}

func TestSecretSetBrokerSettingsAreCheckedBeforeAnythingIsRead(t *testing.T) {
	f := newSealFixture(t)
	f.pin()
	f.serve(f.hostPub, f.seal.Published())
	base := []string{"secret", "set", "anthropic", "--upstream", "api.anthropic.com", "--allow-profile", "python-dev"}
	if r := f.h.run(plaintext+"\n", base...); r.code != ExitUsage || !strings.Contains(r.stderr, "forwards nothing by default") {
		t.Fatalf("rules are required (deny by default): %v", r)
	}
	for _, bad := range [][]string{{"--rule", "POST"}, {"--rule", "*:/"}, {"--rule", "POST:v1"}, {"--basic-user", "u"}, {"--username", "u"},
		{"--scheme", "Digest", "--header", "Authorization"}, {"--scheme", "Basic", "--header", "Authorization"}, {"--scheme", "Bearer"},
		{"--allow-any-path", "--rule", "GET:/"}, {"--extra-header", "novalue"}, {"--extra-header", "a b=1"}, {"--extra-header", "x-v=1", "--extra-header", "x-v=2"}} {
		if r := f.set(plaintext+"\n", bad...); r.code != ExitUsage || len(f.posted) != 0 {
			t.Fatalf("%v: %v", bad, r)
		}
	}
	r := f.set(plaintext+"\n", "--header", "Authorization", "--scheme", "basic", "--username", "deploy", "--rule", "GET,POST:/api/:prefix")
	if r.code != 0 {
		t.Fatalf("%v", r)
	}
	var body map[string]json.RawMessage
	mustDecode(t, f.posted[0], &body)
	if string(body["scheme"]) != `"Basic"` || string(body["username"]) != `"deploy"` || string(body["rules"]) != `[{"methods":["GET","POST"],"path":"/api/","match":"prefix"}]` {
		t.Fatalf("%s", f.posted[0])
	}
}

func TestSecretSetExplainsTheServicesRefusals(t *testing.T) {
	for code, want := range map[string]string{
		"seal_key_changed":     "run agentgate secret set again",
		"seal_key_unavailable": "has not published a host-signed seal key",
		"invalid_ciphertext":   "never reuse an envelope",
		"invalid_secret":       "Fix the broker setting",
	} {
		f := newSealFixture(t)
		f.pin()
		f.serve(f.hostPub, f.seal.Published())
		status := map[string]int{"seal_key_changed": 409, "seal_key_unavailable": 409}[code]
		if status == 0 {
			status = 422
		}
		f.h.api.handle("POST /api/v1/secrets", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
			apiError(w, status, code, "The service refused the secret ("+code+").")
		})
		r := f.set(plaintext + "\n")
		if r.code == 0 || !strings.Contains(r.stderr, code) || !strings.Contains(r.stderr, want) {
			t.Fatalf("%s: %v", code, r)
		}
		assertNoSecret(t, f, r)
	}
}

func ptr[T any](v T) *T { return &v }

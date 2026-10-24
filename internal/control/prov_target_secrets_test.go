// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/ed25519"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/secretseal"
)

// sealTo seals a value to the published seal key of the named target.
func (f *provFixture) sealTo(h *fakeHost, target, name, value string) *secretseal.Sealed {
	f.t.Helper()
	published := must(f.s.TargetSealKey(target))
	rec := must(secretseal.ParseSignedKeyRecord(published["record"].(json.RawMessage)))
	pub := h.key.Public().(ed25519.PublicKey)
	known := must(secretseal.LoadKnownTargets(filepath.Join(f.t.TempDir(), "known.json")))
	if err := known.Pin(h.id, secretseal.HostKeyFingerprint(pub)); err != nil {
		f.t.Fatal(err)
	}
	sealed, _, err := secretseal.SealForTarget(known, false, rec, pub, h.id, name, []byte(value), f.now())
	if err != nil {
		f.t.Fatal(err)
	}
	return sealed
}

// secondTarget creates, enrolls and approves another target.
func (f *provFixture) secondTarget(name string) *fakeHost {
	f.t.Helper()
	value := must(f.s.CreateTarget(f.admin(), TargetInput{Name: name, Reason: "Enroll another synthetic host"}))
	token := value.(map[string]any)["enrollment"].(map[string]any)["token"].(string)
	h := newHost(f)
	resp := must(h.enroll(token))
	must(f.s.ApproveTargetKey(f.admin(), resp.TargetID, KeyApprovalInput{HostKeyID: resp.HostKeyID, Reason: "The fingerprint matches the host console"}))
	h.poll()
	return h
}

func TestLaunchersSeeOnlyNamesAndScopeOfATargetsSecrets(t *testing.T) {
	f := newProv(t)
	h, target := f.enrolledTarget()
	h.poll()
	f.profile("dev", false)
	f.profile("ops", false)
	value := "synthetic-credential-0123456789"
	model := secretInput("model-api", f.sealTo(h, "local", "model-api", value), "dev")
	f.storeSecret(h, model, nil)
	git := secretInput("git-token", f.sealTo(h, "local", "git-token", value), "ops")
	git.AllowedLaunchers = []string{"oidc:ada"}
	f.storeSecret(h, git, nil)
	bare := secretInput("bare-key", f.sealTo(h, "local", "bare-key", value), "dev")
	bare.Rules = nil
	f.storeSecret(h, bare, nil)
	must(f.s.CreateSecret(f.admin(), secretInput("late-key", f.sealTo(h, "local", "late-key", value), "dev")))
	other := f.secondTarget("other")
	f.storeSecret(other, func() SecretInput {
		in := secretInput("elsewhere", f.sealTo(other, "other", "elsewhere", value), "dev")
		in.Target = "other"
		return in
	}(), nil)

	launcher, viewer, editor := f.token(f.launcher(), "launcher"), f.token(f.viewer(), "viewer"), f.token(f.editor(), "editor")
	resp, body := f.apiRequest("GET", "/api/v1/targets/local/secrets?profile=dev", launcher, nil)
	if resp.StatusCode != 200 || body["target_id"] != target.ID || body["profile"] != "dev" {
		t.Fatalf("%d %v", resp.StatusCode, body)
	}
	raw, _ := json.Marshal(body)
	for _, leak := range []string{"fingerprint", "ciphertext", "envelope", "receipt", "allowed_profiles", "allowed_launchers", "/v1/messages", "oidc:ada", "sfp1_", "elsewhere", value} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("the launcher view carries %q: %s", leak, raw)
		}
	}
	got := map[string]map[string]any{}
	for _, item := range body["items"].([]any) {
		m := item.(map[string]any)
		got[m["name"].(string)] = m
	}
	if len(got) != 4 {
		t.Fatalf("items %v", got)
	}
	want := map[string]struct {
		usable bool
		reason string
	}{
		"model-api": {true, ""}, "git-token": {false, "not scoped to you"}, "bare-key": {false, "secret_rules_missing"}, "late-key": {false, "not confirmed it yet (pending)"},
	}
	for name, w := range want {
		item := got[name]
		reason, _ := item["reason"].(string)
		if item["usable"] != w.usable || !strings.Contains(reason, w.reason) || (w.usable && reason != "") {
			t.Fatalf("%s: %v", name, item)
		}
	}
	if got["model-api"]["rule_count"] != float64(2) || got["model-api"]["launcher_allowed"] != true || got["model-api"]["profile_allowed"] != true || got["model-api"]["upstreams"].([]any)[0] != "api.model.example" {
		t.Fatalf("model-api %v", got["model-api"])
	}
	// Another profile: model-api is not scoped to it.
	_, body = f.apiRequest("GET", "/api/v1/targets/"+target.ID+"/secrets?profile=ops", launcher, nil)
	for _, item := range body["items"].([]any) {
		m := item.(map[string]any)
		reason, _ := m["reason"].(string)
		if m["name"] == "model-api" && (m["usable"] != false || m["profile_allowed"] != false || !strings.Contains(reason, "profile ops")) {
			t.Fatalf("model-api for ops %v", m)
		}
	}
	// Without a profile, only the requester's scope is checked.
	_, body = f.apiRequest("GET", "/api/v1/targets/local/secrets", launcher, nil)
	for _, item := range body["items"].([]any) {
		if m := item.(map[string]any); m["profile_allowed"] != nil {
			t.Fatalf("a profile answer without a profile: %v", m)
		}
	}
	// The other target's secret is listed only for that target.
	_, body = f.apiRequest("GET", "/api/v1/targets/other/secrets", launcher, nil)
	if items := body["items"].([]any); len(items) != 1 || items[0].(map[string]any)["name"] != "elsewhere" {
		t.Fatalf("other target %v", body)
	}
	before := auditCount(f, "api.denied")
	for _, c := range []struct {
		name, token, path string
		status            int
	}{
		{"no credential", "", "/api/v1/targets/local/secrets", 401},
		{"viewer", viewer, "/api/v1/targets/local/secrets", 403},
		{"editor", editor, "/api/v1/targets/local/secrets", 403},
		{"unknown target", launcher, "/api/v1/targets/" + strings.Repeat("0", 32) + "/secrets", 404},
		{"malformed profile", launcher, "/api/v1/targets/local/secrets?profile=Bad%20Name", 422},
		{"two profiles", launcher, "/api/v1/targets/local/secrets?profile=dev&profile=ops", 422},
		{"oversize query", launcher, "/api/v1/targets/local/secrets?profile=dev&x=" + strings.Repeat("a", 300), 422},
	} {
		if resp, out := f.apiRequest("GET", c.path, c.token, nil); resp.StatusCode != c.status {
			t.Fatalf("%s: %d %v", c.name, resp.StatusCode, out)
		}
	}
	if auditCount(f, "api.denied") < before+6 {
		t.Fatal("refused listings are not audited")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// The web UI's tests use answers of the real service, not hand-written
// ones. This test drives the real service over HTTP and records its answers
// in web/qa/fixtures/api. With AGENTGATE_WRITE_WEB_FIXTURES=1 it rewrites
// them; otherwise it fails when a committed fixture's shape (its keys and
// value types, recursively) differs from what the service answers now.
const webFixtureDir = "../../web/qa/fixtures/api"

type webFixtures struct {
	t     *testing.T
	f     *provFixture
	files map[string]any
}

func (w *webFixtures) call(method, path, token string, body any, status int) map[string]any {
	w.t.Helper()
	var raw []byte
	if body != nil {
		switch b := body.(type) {
		case []byte:
			raw = b
		default:
			raw, _ = json.Marshal(b)
		}
	}
	resp, out := w.f.apiRequest(method, path, token, raw)
	if resp.StatusCode != status {
		w.t.Fatalf("%s %s: %d %v", method, path, resp.StatusCode, out)
	}
	return out
}

func (w *webFixtures) record(name string, v any) {
	raw, err := json.Marshal(v)
	if err != nil {
		w.t.Fatal(err)
	}
	var decoded any
	json.Unmarshal(raw, &decoded)
	w.files[name] = decoded
}

// shape reduces a JSON value to its keys and types. A list has the shape of
// its first element.
func shape(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, x := range t {
			out[k] = shape(x)
		}
		return out
	case []any:
		if len(t) == 0 {
			return []any{}
		}
		return []any{shape(t[0])}
	case string:
		return "string"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", v)
}

func shapeDiff(prefix string, a, b any, out *[]string) {
	am, aok := a.(map[string]any)
	bm, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range am {
			keys[k] = true
		}
		for k := range bm {
			keys[k] = true
		}
		names := []string{}
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			shapeDiff(prefix+"."+k, am[k], bm[k], out)
		}
		return
	}
	al, alok := a.([]any)
	bl, blok := b.([]any)
	if alok && blok && len(al) == 1 && len(bl) == 1 {
		shapeDiff(prefix+"[]", al[0], bl[0], out)
		return
	}
	if !reflect.DeepEqual(a, b) {
		ja, _ := json.Marshal(a)
		jb, _ := json.Marshal(b)
		*out = append(*out, fmt.Sprintf("%s: committed %s, service %s", prefix, ja, jb))
	}
}

func (w *webFixtures) finish() {
	w.t.Helper()
	if os.Getenv("AGENTGATE_WRITE_WEB_FIXTURES") == "1" {
		if err := os.MkdirAll(webFixtureDir, 0o755); err != nil {
			w.t.Fatal(err)
		}
		for name, v := range w.files {
			raw, _ := json.MarshalIndent(v, "", "  ")
			if err := os.WriteFile(filepath.Join(webFixtureDir, name), append(raw, '\n'), 0o644); err != nil {
				w.t.Fatal(err)
			}
		}
		return
	}
	names := []string{}
	for name := range w.files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw, err := os.ReadFile(filepath.Join(webFixtureDir, name))
		if err != nil {
			w.t.Fatalf("%s is missing; run AGENTGATE_WRITE_WEB_FIXTURES=1 go test ./internal/control -run TestWebFixtures", name)
		}
		var committed any
		if err = json.Unmarshal(raw, &committed); err != nil {
			w.t.Fatalf("%s: %v", name, err)
		}
		diffs := []string{}
		shapeDiff(strings.TrimSuffix(name, ".json"), shape(committed), shape(w.files[name]), &diffs)
		if len(diffs) > 0 {
			w.t.Fatalf("%s no longer matches the service's answer (regenerate with AGENTGATE_WRITE_WEB_FIXTURES=1):\n%s", name, strings.Join(diffs, "\n"))
		}
		if bytes.Contains(raw, []byte("synthetic-credential")) {
			w.t.Fatalf("%s holds a secret value", name)
		}
	}
}

func TestWebFixturesAreRealServiceAnswers(t *testing.T) {
	f := newProv(t)
	w := &webFixtures{t: t, f: f, files: map[string]any{}}
	editor := f.token(f.editor(), "editor")
	p := f.profileFrom("python-dev", "python-dev", true)
	parent := w.call("GET", "/api/v1/profiles/"+p.ID+"/versions/1", editor, nil, 200)
	request := map[string]any{"edits": []any{
		map[string]any{"action": "read", "values": []string{"/srv/data"}},
		map[string]any{"action": "deny-web", "values": []string{"http"}},
		map[string]any{"action": "mount", "values": []string{"repo"}, "mode": "read-only"},
		map[string]any{"action": "signal", "values": []string{"WINCH"}},
	}, "reason": "Read the data set", "dry_run": true}
	dry := w.call("POST", "/api/v1/profiles/"+p.ID+"/versions/1/grants", editor, request, 200)
	w.record("grant-dry-run.json", map[string]any{"parent": parent, "request": request, "response": dry})
	delete(request, "dry_run")
	applied := w.call("POST", "/api/v1/profiles/"+p.ID+"/versions/1/grants", editor, request, 200)
	w.record("grant-applied.json", map[string]any{"parent": parent, "request": request, "response": applied})

	// A target with a stored secret, as a launcher sees it.
	h, target := f.enrolledTarget()
	h.poll()
	f.profile("dev", false)
	launcher := f.token(f.launcher(), "launcher")
	f.storeSecret(h, secretInput("model-api", f.sealTo(h, "local", "model-api", "synthetic-credential-0123456789"), "python-dev"), nil)
	bare := secretInput("bare-key", f.sealTo(h, "local", "bare-key", "synthetic-credential-0123456789"), "python-dev")
	bare.Rules = nil
	f.storeSecret(h, bare, nil)
	w.record("target-secrets.json", w.call("GET", "/api/v1/targets/"+target.ID+"/secrets?profile=python-dev", launcher, nil, 200))

	// The secret flow as an administrator drives it: target, seal key,
	// POST /secrets with broker settings, the host's receipt.
	admin := f.token(f.admin(), "admin")
	w.record("target.json", w.call("GET", "/api/v1/targets/"+target.ID, admin, nil, 200))
	w.record("seal-key.json", w.call("GET", "/api/v1/targets/"+target.ID+"/seal-key", admin, nil, 200))
	create := map[string]any{"name": "docs-api", "target": target.ID, "upstreams": []string{"api.docs.example"}, "header": "Authorization", "scheme": "Basic", "username": "agent",
		"rules":         []any{map[string]any{"methods": []string{"GET", "HEAD"}, "path": "/v2/", "match": "prefix"}, map[string]any{"methods": []string{"POST"}, "path": "/v2/search", "match": "exact"}},
		"extra_headers": map[string]string{"docs-version": "2"}, "ciphertext": f.sealTo(h, target.ID, "docs-api", "synthetic-credential-0123456789").Envelope.Encode(),
		"allowed_profiles": []string{"python-dev"}, "allowed_launchers": []string{"oidc:lin"}, "reason": "Store the docs API key"}
	created := w.call("POST", "/api/v1/secrets", admin, create, 200)
	acceptPut(f, h)
	create["ciphertext"] = "(Envelope.Encode() of the value sealed in the browser)"
	w.record("secret-created.json", map[string]any{"request": create, "response": created})
	wild := map[string]any{"name": "wild-api", "target": target.ID, "upstreams": []string{"api.wild.example"}, "header": "x-api-key",
		"rules": []any{map[string]any{"methods": []string{"*"}, "path": "/"}}, "ciphertext": f.sealTo(h, target.ID, "wild-api", "synthetic-credential-0123456789").Envelope.Encode(),
		"allowed_profiles": []string{"python-dev"}, "allowed_launchers": []string{"oidc:lin"}, "reason": "Store a key with the wildcard"}
	wildOut := w.call("POST", "/api/v1/secrets", admin, wild, 200)
	acceptPut(f, h)
	wild["ciphertext"] = create["ciphertext"]
	w.record("secret-wildcard.json", map[string]any{"request": wild, "response": wildOut})
	w.record("secret-receipt.json", w.call("GET", "/api/v1/secrets/"+created["id"].(string)+"/receipt", admin, nil, 200))

	// A launch with brokered secrets and a read-only repository, planned,
	// created, approved, running with output.
	spec := specMap("python-dev")
	spec["name"] = "docs-agent"
	spec["access"] = map[string]any{"profile": "python-dev", "version": 2}
	spec["mounts"] = []any{map[string]any{"name": "repo", "source": "/srv/repos/app", "mode": "read-only"}}
	spec["secrets"] = []any{map[string]any{"ref": "docs-api", "expose": map[string]any{"env": "DOCS_BASE_URL"}}, map[string]any{"ref": "wild-api", "expose": map[string]any{"env": "WILD_BASE_URL"}}}
	w.record("launch-plan.json", map[string]any{"request": spec, "response": w.call("POST", "/api/v1/launch-plans", launcher, spec, 200)})
	launched := w.call("POST", "/api/v1/launches", launcher, spec, 200)
	w.record("launch-created.json", launched)
	id := launched["launch"].(map[string]any)["id"].(string)
	approver := f.token(f.approver(), "approver")
	w.call("POST", "/api/v1/launches/"+id+"/approve", approver, map[string]any{"reason": "Reviewed the broker rules"}, 200)
	var job hostproto.Job
	for _, j := range h.poll() {
		if j.Type == hostproto.JobLaunch && j.LaunchID == id {
			job = j
		}
	}
	running := ev(1, f, hostproto.EventState)
	running.State = StateRunning
	must(h.events(job.ID, running, logEvent(2, f, "collecting the docs"), logEvent(3, f, "wrote 3 files")))
	w.record("launch-detail.json", w.call("GET", "/api/v1/launches/"+id, launcher, nil, 200))
	w.record("launch-logs.json", w.call("GET", "/api/v1/launches/"+id+"/logs", launcher, nil, 200))
	other := specMap("python-dev")
	other["name"] = "quick-check"
	w.record("launch-plan-plain.json", map[string]any{"request": other, "response": w.call("POST", "/api/v1/launch-plans", launcher, other, 200)})
	pending := w.call("POST", "/api/v1/launches", launcher, other, 200)
	w.record("launch-created-plain.json", pending)
	w.record("launch-detail-pending.json", w.call("GET", "/api/v1/launches/"+pending["launch"].(map[string]any)["id"].(string), launcher, nil, 200))
	w.record("launches-page.json", w.call("GET", "/api/v1/launches?limit=1", launcher, nil, 200))
	w.record("launches-summary.json", w.call("GET", "/api/v1/launches/summary", launcher, nil, 200))

	// The log stream (SSE) of a launch that ends: ready, one log frame per
	// line, end.
	plain, _ := f.launch(f.launcher(), specMap("dev"))
	var plainJob hostproto.Job
	for _, j := range h.poll() {
		if j.Type == hostproto.JobLaunch && j.LaunchID == plain.ID {
			plainJob = j
		}
	}
	must(h.events(plainJob.ID, running, logEvent(2, f, "checking")))
	must(f.s.StopLaunch(f.launcher(), plain.ID, DecisionInput{Reason: "Done"}))
	stop := h.poll(plain.ID)[0]
	result := ev(1, f, hostproto.EventResult)
	result.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stopped", Receipt: h.receipt(stop, true)}
	must(h.events(stop.ID, result))
	_, stream := openLogStream(t, f, f.http.URL, "/api/v1/launches/"+plain.ID+"/logs", launcher, "")
	frames := map[string]any{}
	for {
		m, err := stream.next(t)
		if err != nil {
			t.Fatalf("the log stream ended without an end event: %v", err)
		}
		var data any
		if err = json.Unmarshal([]byte(m.data), &data); err != nil {
			t.Fatalf("frame %+v: %v", m, err)
		}
		if _, seen := frames[m.event]; !seen {
			frames[m.event] = data
		}
		if m.event == "end" {
			break
		}
	}
	w.record("launch-log-stream.json", frames)
	w.record("launch-detail-stopped.json", w.call("GET", "/api/v1/launches/"+plain.ID, launcher, nil, 200))
	w.record("launches-all.json", w.call("GET", "/api/v1/launches", launcher, nil, 200))

	// The refusals the web UI explains, each as the service answers it.
	errs := map[string]any{}
	refuse := func(name, code, method, path, token string, body any, status int) {
		out := w.call(method, path, token, body, status)
		if got := out["error"].(map[string]any)["code"]; got != code {
			t.Fatalf("%s: got %v", name, got)
		}
		errs[name] = map[string]any{"method": method, "status": status, "body": out}
	}
	bareSpec := specMap("python-dev")
	bareSpec["secrets"] = []any{map[string]any{"ref": "bare-key", "expose": map[string]any{"env": "BARE_BASE_URL"}}}
	refuse("secret_rules_missing", "secret_rules_missing", "POST", "/api/v1/launch-plans", launcher, bareSpec, 422)
	bad := map[string]any{}
	for k, v := range create {
		bad[k] = v
	}
	bad["name"], bad["extra_headers"] = "bad-api", map[string]string{"x-api-key": "not-here"}
	bad["ciphertext"] = f.sealTo(h, target.ID, "bad-api", "synthetic-credential-0123456789").Envelope.Encode()
	refuse("invalid_secret", "invalid_secret", "POST", "/api/v1/secrets", admin, bad, 422)
	bad["extra_headers"], bad["ciphertext"] = map[string]string{}, hostproto.EncodeSealed(bytes.Repeat([]byte{1}, 120))
	refuse("invalid_ciphertext", "invalid_ciphertext", "POST", "/api/v1/secrets", admin, bad, 422)
	pub, _ := secretseal.GenerateHostKey(target.ID, h.key, f.now(), time.Hour)
	rec := pub.Published()
	hostPub := h.key.Public().(ed25519.PublicKey)
	verified := must(secretseal.VerifyKeyRecord(&rec, hostPub, secretseal.HostKeyFingerprint(hostPub), target.ID, f.now()))
	stale := must(secretseal.SealAt(verified, target.ID, "bad-api", []byte("synthetic-credential-0123456789"), f.now()))
	bad["ciphertext"] = stale.Envelope.Encode()
	refuse("seal_key_changed", "seal_key_changed", "POST", "/api/v1/secrets", admin, bad, 409)
	fresh := must(f.s.CreateTarget(f.admin(), TargetInput{Name: "fresh-host", Reason: "Enroll a host that has not polled"}))
	token := fresh.(map[string]any)["enrollment"].(map[string]any)["token"].(string)
	unpolled := newHost(f)
	enrolled := must(unpolled.enroll(token))
	must(f.s.ApproveTargetKey(f.admin(), enrolled.TargetID, KeyApprovalInput{HostKeyID: enrolled.HostKeyID, Reason: "The fingerprint matches the host console"}))
	refuse("seal_key_missing", "seal_key_unavailable", "GET", "/api/v1/targets/"+enrolled.TargetID+"/seal-key", admin, nil, 404)
	early, _ := secretseal.GenerateHostKey(enrolled.TargetID, unpolled.key, f.now(), time.Hour)
	rec = early.Published()
	unpolledPub := unpolled.key.Public().(ed25519.PublicKey)
	verified = must(secretseal.VerifyKeyRecord(&rec, unpolledPub, secretseal.HostKeyFingerprint(unpolledPub), enrolled.TargetID, f.now()))
	bad["target"], bad["ciphertext"] = enrolled.TargetID, must(secretseal.SealAt(verified, enrolled.TargetID, "bad-api", []byte("synthetic-credential-0123456789"), f.now())).Envelope.Encode()
	refuse("seal_key_unavailable", "seal_key_unavailable", "POST", "/api/v1/secrets", admin, bad, 409)
	w.record("errors.json", errs)

	// Targets in their other states, and a secret the host has not stored yet.
	w.record("target-unpolled.json", w.call("GET", "/api/v1/targets/"+enrolled.TargetID, admin, nil, 200))
	created = w.call("POST", "/api/v1/targets", admin, map[string]any{"name": "new-host", "reason": "Enroll a new host"}, 200)
	enrollment := created["enrollment"].(map[string]any)
	enrollment["token"] = "agtenr_" + strings.Repeat("x", 43) // shown once; not committed
	w.record("target-created.json", created)
	w.record("target-new.json", w.call("GET", "/api/v1/targets/"+created["target"].(map[string]any)["id"].(string), admin, nil, 200))
	awaiting := must(f.s.CreateTarget(f.admin(), TargetInput{Name: "waiting-host", Reason: "Enroll a host that waits for approval"}))
	waiting := must(newHost(f).enroll(awaiting.(map[string]any)["enrollment"].(map[string]any)["token"].(string)))
	w.record("target-awaiting.json", w.call("GET", "/api/v1/targets/"+waiting.TargetID, admin, nil, 200))
	w.call("POST", "/api/v1/secrets", admin, map[string]any{"name": "pending-key", "target": target.ID, "upstreams": []string{"api.model.example"}, "header": "x-api-key",
		"rules":      []any{map[string]any{"methods": []string{"POST"}, "path": "/v1/messages", "match": "exact"}},
		"ciphertext": f.sealTo(h, target.ID, "pending-key", "synthetic-credential-0123456789").Envelope.Encode(), "allowed_profiles": []string{"python-dev"}, "allowed_launchers": []string{"oidc:lin"},
		"reason": "Store a key the host has not confirmed"}, 200)
	w.record("secrets.json", w.call("GET", "/api/v1/secrets", admin, nil, 200))
	old := f.secondTarget("old-host")
	held := secretInput("old-key", f.sealTo(old, old.id, "old-key", "synthetic-credential-0123456789"), "python-dev")
	held.Target = old.id
	f.storeSecret(old, held, nil)
	w.call("DELETE", "/api/v1/targets/"+old.id, admin, map[string]any{"reason": "Decommission the old host"}, 200)
	w.record("target-retiring.json", w.call("GET", "/api/v1/targets/"+old.id, admin, nil, 200))
	w.record("targets.json", w.call("GET", "/api/v1/targets", admin, nil, 200))
	w.finish()
}

// acceptPut is the fake host storing the envelope of the next secret-put
// job and answering with its receipt.
func acceptPut(f *provFixture, h *fakeHost) {
	f.t.Helper()
	put := h.poll()[0]
	var payload hostproto.SecretPutPayload
	json.Unmarshal(put.Payload, &payload)
	env := must(secretseal.DecodeEnvelope(payload.Ciphertext))
	receipt := must(h.hostStore().Accept(h.sealKey, env, f.now()))
	r := ev(1, f, hostproto.EventResult)
	hr := hostproto.SecretReceipt(*receipt)
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stored", SecretReceipt: &hr}
	must(h.events(put.ID, r))
}

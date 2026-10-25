// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/control"
)

// A pin is the client's out-of-band anchor for secret set. Every place the CLI
// pins must take the key from the operator (typed from the host console) or
// from this machine's own host agent, never from the service's answer. These
// tests play a hostile service that accepts what the operator typed and
// answers with a key it controls.

const attackerKey = "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func pins(t *testing.T, h *harness) *knownTargets {
	t.Helper()
	st := store{dir: h.dir, euid: os.Geteuid()}
	k, err := st.loadTrust()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// Regression for the review repro TestReviewApproveKeyPinsServiceAnswer and
// TestReviewApproveKeyPinsServiceSuppliedKey: the CLI pinned approved.HostKeyID.
func TestApproveKeyPinsTheTypedFingerprintNotTheServiceAnswer(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	pending := sampleTarget("awaiting_key_approval")
	h.api.reply("GET /api/v1/targets/{id}", 200, pending)
	h.api.handle("POST /api/v1/targets/{id}/approve-key", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		var in control.KeyApprovalInput
		json.Unmarshal(body, &in)
		if in.HostKeyID != hostKey {
			apiError(w, 409, "fingerprint_mismatch", "mismatch")
			return
		}
		out := sampleTarget("active")
		out.HostKeyID = attackerKey // the service substitutes its own key
		writeJSON(w, 200, out)
	})
	r := h.run("", "target", "approve-key", "local", "--host-key-id", hostKey)
	if r.code != ExitTrust || !strings.Contains(r.stderr, "host_key_mismatch") || !strings.Contains(r.stderr, "Nothing was pinned") {
		t.Fatalf("a substituted answer is a trust failure: %v", r)
	}
	if pin := pins(t, h).find(h.api.URL(), pending.ID); pin != nil {
		t.Fatalf("typed %s; pinned %+v", hostKey, pin)
	}

	// The same answer in --json mode is refused the same way.
	if r = h.run("", "--json", "target", "approve-key", "local", "--host-key-id", hostKey); r.code != ExitTrust {
		t.Fatalf("json: %v", r)
	}
	if len(pins(t, h).Targets) != 0 {
		t.Fatal("pinned in json mode")
	}

	// An honest answer pins exactly what the operator typed.
	h.api.handle("POST /api/v1/targets/{id}/approve-key", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		writeJSON(w, 200, sampleTarget("active"))
	})
	if r = h.run("", "target", "approve-key", "local", "--host-key-id", hostKey); r.code != 0 {
		t.Fatalf("%v", r)
	}
	if pin := pins(t, h).find(h.api.URL(), pending.ID); pin == nil || pin.HostKeyID != hostKey || pin.Source != "approve-key" {
		t.Fatalf("pin %+v", pin)
	}
}

func TestApproveKeyRefusesAnAnswerForAnotherTarget(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	pending := sampleTarget("awaiting_key_approval")
	h.api.reply("GET /api/v1/targets/{id}", 200, pending)
	h.api.handle("POST /api/v1/targets/{id}/approve-key", func(w http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		out := sampleTarget("active")
		out.ID = strings.Repeat("e", 32) // another target carries the typed key
		writeJSON(w, 200, out)
	})
	r := h.run("", "target", "approve-key", "local", "--host-key-id", hostKey)
	if r.code != ExitTrust || !strings.Contains(r.stderr, "host_key_mismatch") {
		t.Fatalf("%v", r)
	}
	if len(pins(t, h).Targets) != 0 {
		t.Fatal("pinned the key under a target id the service chose")
	}
}

func TestPinRefusesAKeyTheServiceDoesNotReport(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	active := sampleTarget("active")
	active.HostKeyID = attackerKey
	h.api.reply("GET /api/v1/targets/{id}", 200, active)
	r := h.run("", "target", "pin", "local", "--host-key-id", hostKey)
	if r.code != ExitTrust || !strings.Contains(r.stderr, "host_key_mismatch") {
		t.Fatalf("%v", r)
	}
	if len(pins(t, h).Targets) != 0 {
		t.Fatal("pinned a key the service does not report")
	}
}

// agentgate up pins the key this machine's own host agent reports. A service
// that shows another key for that target, once it is active or in its answer
// to --approve, gets a trust failure and no pin.
func TestUpRefusesToPinAServiceKeyThatDiffersFromTheLocalAgent(t *testing.T) {
	w := newUpWorld(t)
	w.approveAt = 1
	w.h.api.handle("GET /api/v1/targets/{id}", func(rw http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		if w.target.ID == "" {
			apiError(rw, 404, "not_found", "The target does not exist.")
			return
		}
		if w.installed {
			// Active with a key this machine's host agent never had.
			w.target.State, w.target.HostKeyID, w.target.Online = "active", attackerKey, true
		}
		writeJSON(rw, 200, w.target)
	})
	r := w.up(upPassword + "\n")
	if r.code != ExitTrust || !strings.Contains(r.stderr, "host_key_mismatch") {
		t.Fatalf("%v", r)
	}
	if len(pins(t, w.h).Targets) != 0 {
		t.Fatal("pinned the service's key")
	}

	// --approve: the service accepts the local key and answers with another.
	w = newUpWorld(t)
	w.approveAt = 1 << 30
	if r := w.up(upPassword+"\n", "--wait-timeout", "50ms"); r.code != ExitApprovalPending {
		t.Fatalf("first run: %v", r)
	}
	w.h.api.handle("POST /api/v1/targets/{id}/approve-key", func(rw http.ResponseWriter, r *http.Request, body []byte, _ []string) {
		out := w.target
		out.State, out.HostKeyID = "active", attackerKey
		writeJSON(rw, 200, out)
	})
	w.h.term.tty = [3]bool{true, true, true}
	r = w.up(hostKey[len(hostKey)-8:]+"\n", "--approve")
	if r.code != ExitTrust || !strings.Contains(r.stderr, "host_key_mismatch") {
		t.Fatalf("approve answer: %v", r)
	}
	if len(pins(t, w.h).Targets) != 0 {
		t.Fatal("pinned the key of the approval answer")
	}
}

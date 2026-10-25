// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"alloyium.local/kernel-poc/internal/control"
)

func targetsReply() map[string]any {
	return map[string]any{"items": []control.Target{{ID: "t1", Name: "local", State: "active", Capabilities: []string{"docker"}, HostKeyID: "ed25519:" + strings.Repeat("a", 32), HeartbeatSeconds: 10, Online: true}}}
}

func TestIdempotentReadsRetryWithRetryAfter(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	var calls atomic.Int32
	h.api.handle("GET /api/v1/targets", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		if calls.Add(1) < 3 {
			w.Header().Set("Retry-After", "0")
			apiError(w, 503, "request_capacity", "The request capacity is full.")
			return
		}
		writeJSON(w, 200, targetsReply())
	})
	r := h.run("", "target", "ls", "--verbose")
	if r.code != 0 || calls.Load() != 3 || !strings.Contains(r.stderr, "retry 1/3") {
		t.Fatalf("calls %d: %v", calls.Load(), r)
	}
	if strings.Contains(r.stderr, testToken) || !strings.Contains(r.stderr, "Bearer [redacted]") {
		t.Fatalf("verbose output must redact the token: %s", r.stderr)
	}
}

func TestRetriesStopAtTheCap(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	var calls atomic.Int32
	h.api.handle("GET /api/v1/targets", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		calls.Add(1)
		apiError(w, 503, "persistence_unavailable", "The operation did not commit.")
	})
	r := h.run("", "target", "ls")
	if r.code != ExitServer || calls.Load() != maxAttempts || !strings.Contains(r.stderr, "persistence_unavailable") || !strings.Contains(r.stderr, "request req-test") {
		t.Fatalf("calls %d: %v", calls.Load(), r)
	}
	calls.Store(0)
	h.api.handle("GET /api/v1/targets", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		calls.Add(1)
		w.Header().Set("Retry-After", "3600")
		apiError(w, 429, "rate_limited", "The request rate exceeds this node's limit.")
	})
	r = h.run("", "target", "ls")
	if r.code != ExitServer || calls.Load() != 1 || !strings.Contains(r.stderr, "retry after 1h0m0s") {
		t.Fatalf("a long Retry-After must not be waited out: calls %d %v", calls.Load(), r)
	}
}

func TestNonIdempotentWritesAreNotRetried(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	var calls atomic.Int32
	h.api.handle("POST /api/v1/targets", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		calls.Add(1)
		apiError(w, 503, "request_capacity", "busy")
	})
	if r := h.run("", "target", "add", "edge"); r.code != ExitServer || calls.Load() != 1 {
		t.Fatalf("target creation carries a one-time token and must not be retried: calls %d %v", calls.Load(), r)
	}
	keys := map[string]bool{}
	calls.Store(0)
	h.api.handle("POST /api/v1/profiles", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		keys[r.Header.Get("Idempotency-Key")] = true
		if calls.Add(1) == 1 {
			apiError(w, 503, "request_capacity", "busy")
			return
		}
		writeJSON(w, 200, map[string]any{"profile": control.Profile{ID: "p1", Name: "dev", RequireApproval: true, LatestVersion: 1}, "version": control.ProfileVersion{ID: "v1", Number: 1, Digest: strings.Repeat("d", 64)}})
	})
	if r := h.run("", "profile", "new", "dev", "--preset", "python-dev"); r.code != 0 || calls.Load() != 2 || len(keys) != 1 || keys[""] {
		t.Fatalf("an idempotent write retries with one key: calls %d keys %v %v", calls.Load(), keys, r)
	}
}

func TestRedirectsAreRefused(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	h.api.handle("GET /api/v1/targets", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		http.Redirect(w, r, "https://elsewhere.example/steal", http.StatusFound)
	})
	if r := h.run("", "target", "ls"); r.code != ExitServer || !strings.Contains(r.stderr, "redirect") {
		t.Fatalf("%v", r)
	}
}

func TestResponsesAreBounded(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	h.api.handle("GET /api/v1/targets", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"items":[],"pad":"`))
		w.Write([]byte(strings.Repeat("x", maxResponseBytes+10)))
		w.Write([]byte(`"}`))
	})
	if r := h.run("", "target", "ls"); r.code != ExitServer || !strings.Contains(r.stderr, "response_too_large") {
		t.Fatalf("%v", r)
	}
}

// realTLS runs the CLI without the test transport, so TLS verification,
// --ca-file and --pin-cert are the real code paths.
func realTLS(h *harness, args ...string) result {
	a, out, errOut := h.app("")
	a.Transport = nil
	code := a.Main(t0ctx, args)
	return result{out.String(), errOut.String(), code}
}

func TestTLSVerificationCAFileAndPin(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	h.api.reply("GET /api/v1/targets", 200, targetsReply())
	if r := realTLS(h, "target", "ls"); r.code != ExitTrust || !strings.Contains(r.stderr, "--ca-file") {
		t.Fatalf("an unknown CA must fail closed: %v", r)
	}
	cert := h.api.srv.Certificate()
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o600)
	if r := realTLS(h, "target", "ls", "--ca-file", caFile); r.code != 0 || !strings.Contains(r.stdout, "local") {
		t.Fatalf("--ca-file: %v", r)
	}
	sum := sha256.Sum256(cert.Raw)
	if r := realTLS(h, "target", "ls", "--ca-file", caFile, "--pin-cert", "sha256:"+hex.EncodeToString(sum[:])); r.code != 0 {
		t.Fatalf("matching pin: %v", r)
	}
	if r := realTLS(h, "target", "ls", "--ca-file", caFile, "--pin-cert", strings.Repeat("ab", 32)); r.code != ExitTrust || !strings.Contains(r.stderr, "certificate_pin_mismatch") {
		t.Fatalf("a different pin must fail closed: %v", r)
	}
	if r := realTLS(h, "target", "ls", "--pin-cert", "nothex"); r.code != ExitUsage {
		t.Fatalf("an invalid pin: %v", r)
	}
}

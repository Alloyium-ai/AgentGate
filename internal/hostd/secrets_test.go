// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// Regression for the second review's torn secret-store write: a secret-put
// whose write the disk cut short (here the file-size limit, as when the disk
// is full) used to leave the new value on disk under the previous value's
// version, fingerprint and policy, and every later launch passed the binding
// check and gave the broker the new value under the old policy. The broker
// must read exactly the value the binding's fingerprint names.
func TestATornSecretPutNeverReachesTheBroker(t *testing.T) {
	h := newBrokerHarness(t)
	h.store("model-api", fakeValue)
	_, sealed := h.sealedPut("model-api", "sk-test-FAKE-rotated-value-9876543210", h.clock.now().Add(time.Second))
	store, err := h.daemon.secretStore()
	if err != nil {
		t.Fatal(err)
	}
	key, err := h.daemon.currentSealKey()
	if err != nil {
		t.Fatal(err)
	}
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &syscall.Rlimit{Cur: 64, Max: old.Max}); err != nil {
		t.Skip("cannot set RLIMIT_FSIZE:", err)
	}
	_, acceptErr := store.Accept(key, &sealed.Envelope, h.clock.now().Add(time.Second))
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	if acceptErr == nil {
		t.Fatal("a write the file-size limit cut short succeeded")
	}
	job := h.brokerLaunchJob(testLaunch, nil, brokerPolicy(t, "oneshot", 30, brokerAddr))
	h.service.send(t, job)
	h.cycle()
	h.broker.mu.Lock()
	read := h.broker.read
	h.broker.mu.Unlock()
	// The intact binding still names the first value, so the launch starts
	// its broker with exactly that value.
	if len(read) != 1 || len(read[0]) != 1 {
		t.Fatalf("broker starts %d, results %+v", len(read), h.service.results(job.ID))
	}
	if read[0][0] != fakeValue {
		t.Fatalf("the broker read a value other than the bound one (%d bytes)", len(read[0][0]))
	}
}

// A record whose value no longer matches its fingerprint (edited or damaged
// on disk) fails the launch closed before any broker starts.
func TestALaunchRefusesAStoredValueThatDiffersFromItsBinding(t *testing.T) {
	h := newBrokerHarness(t)
	h.store("model-api", fakeValue)
	path := filepath.Join(h.root, testTarget, "model-api.secret")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	swapped := append(append(append([]byte{}, line...), '\n'), []byte("sk-test-FAKE-swapped-value-00000000")...)
	if err := os.WriteFile(path, swapped, 0o600); err != nil {
		t.Fatal(err)
	}
	job := h.brokerLaunchJob(testLaunch, nil, brokerPolicy(t, "oneshot", 30, brokerAddr))
	h.service.send(t, job)
	h.cycle()
	r := h.service.results(job.ID)
	if len(r) != 1 || r[0].Status != hostproto.ResultRejected || r[0].Reason != "secret_unavailable" {
		t.Fatalf("a swapped value: %+v", r)
	}
	if containsString(h.broker.called(), "start "+testLaunch) || h.runtime.called("run") != 0 {
		t.Fatal("a broker or launch started with a value that is not the bound one")
	}
	// The binding's own record must also match: a binding edited to another
	// fingerprint is refused the same way.
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	bindings, err := h.daemon.loadBindings()
	if err != nil {
		t.Fatal(err)
	}
	b := bindings["model-api"]
	b.Fingerprint = "sfp1_" + strings.Repeat("0", 32)
	bindings["model-api"] = b
	if err := h.daemon.saveBindings(bindings); err != nil {
		t.Fatal(err)
	}
	store, _ := h.daemon.secretStore()
	if v, _, err := h.daemon.boundSecret(store, bindings, "model-api", b.SecretID); err == nil || v != nil {
		t.Fatal("a binding with another fingerprint was accepted")
	}
}

// A store in the earlier two-file layout is refused loudly: secret-put names
// the reason, and the capability check reports it.
func TestALegacySecretStoreIsRefusedLoudly(t *testing.T) {
	h := newBrokerHarness(t)
	dir := filepath.Join(h.root, testTarget)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	os.Chmod(h.root, 0o700)
	if err := os.WriteFile(filepath.Join(dir, "model-api.meta.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.daemon.secretStore(); !errors.Is(err, secretseal.ErrLegacyStore) {
		t.Fatalf("open: %v", err)
	}
	put, _ := h.sealedPut("model-api", fakeValue, h.clock.now())
	h.service.send(t, put)
	h.cycle()
	if r := h.service.results(put.ID); len(r) != 1 || r[0].Status != hostproto.ResultFailed || r[0].Reason != "store_legacy_format" {
		t.Fatalf("secret-put on a legacy store: %+v", r)
	}
	if h.daemon.brokerAvailable(context.Background()) {
		t.Fatal("brokered secrets reported available on a legacy store")
	}
}

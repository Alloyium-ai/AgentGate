// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

package grant

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) (Claims, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	c := Claims{Issuer: Issuer, Audience: Audience, Deployment: "disposable-dev-poc", Node: "node-1", Boot: "boot-1", Run: "run-1", Domain: "42", Agent: "worker-1", AgentKey: base64.RawURLEncoding.EncodeToString(pub), JobDigest: Digest([]byte("job")), Generation: "1", Workspace: "/var/lib/poc/workspace/", Endpoint: "127.0.0.1:18081", DeadlineNS: "9007199254740993", Issued: now, Expires: now + 30, Nonce: strings.Repeat("a", 32)}
	return c, key
}

func TestGrantBinding(t *testing.T) {
	c, key := fixture(t)
	token, err := Sign(c, key)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	if _, err = Verify(token, pub, c, c.Issued); err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*Claims){"node": func(x *Claims) { x.Node = "other" }, "boot": func(x *Claims) { x.Boot = "other" }, "run": func(x *Claims) { x.Run = "other" }, "domain": func(x *Claims) { x.Domain = "43" }, "agent": func(x *Claims) { x.Agent = "other" }, "requester-job": func(x *Claims) { x.JobDigest = Digest([]byte("forged-requester-rights")) }, "workspace": func(x *Claims) { x.Workspace = "/etc/" }, "confirmation-key": func(x *Claims) { x.AgentKey = strings.Repeat("a", 43) }}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			wrong := c
			mutate(&wrong)
			if _, err := Verify(token, pub, wrong, c.Issued); err == nil {
				t.Fatal("accepted a stolen or substituted grant")
			}
		})
	}
}

func TestGrantTrustAndValidity(t *testing.T) {
	c, key := fixture(t)
	token, err := Sign(c, key)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.Public().(ed25519.PublicKey)
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = Verify(token, other.Public().(ed25519.PublicKey), c, c.Issued); err == nil {
		t.Fatal("accepted an unpinned issuer")
	}
	if _, err = Verify(token, pub, c, c.Expires); err == nil {
		t.Fatal("accepted an expired grant")
	}
	parts := strings.Split(token, ".")
	parts[0] = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	if _, err = Verify(strings.Join(parts, "."), pub, c, c.Issued); err == nil {
		t.Fatal("accepted an algorithm change")
	}
	c.DeadlineNS = "-1"
	if err = Validate(c, c.Issued); err == nil {
		t.Fatal("accepted an invalid deadline")
	}
}

func TestDurableSingleAdmission(t *testing.T) {
	c, key := fixture(t)
	token, err := Sign(c, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "admissions")
	var accepted atomic.Uint32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if Consume(dir, c, token) == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 1 {
		t.Fatalf("accepted %d concurrent replays", accepted.Load())
	}
	if err = Consume(dir, c, token); err == nil {
		t.Fatal("accepted a durable replay")
	}
}

func TestPinnedKeys(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "keys")
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err != nil {
		t.Fatal(err)
	}
	if err := Init(dir); err == nil {
		t.Fatal("overwrote enrolled keys")
	}
}
func TestBoundedDistributedIssueClock(t *testing.T) {
	c, _ := fixture(t)
	now := c.Issued
	c.Issued = now + 1
	c.Expires = now + 31
	if err := Validate(c, now); err != nil {
		t.Fatal("bounded issuer clock difference rejected")
	}
	c.Issued = now + 3
	if err := Validate(c, now); err == nil {
		t.Fatal("unbounded future grant accepted")
	}
	c.Issued = now
	c.Expires = now
	if err := Validate(c, now); err == nil {
		t.Fatal("expiry gained clock grace")
	}
}

func TestCustomerGrantRejectsLimitedBroadcastAndKeepsUnicast(t *testing.T) {
	c, key := fixture(t)
	c.Deployment = "agentgate-community-v1"
	for _, endpoint := range []string{"127.0.0.1:19081", "192.0.2.255:8443"} {
		c.Endpoint = endpoint
		token, err := Sign(c, key)
		if err != nil {
			t.Fatalf("unicast grant rejected: %s %v", endpoint, err)
		}
		if _, err = Verify(token, key.Public().(ed25519.PublicKey), c, c.Issued); err != nil {
			t.Fatal(err)
		}
	}
	c.Endpoint = "255.255.255.255:8443"
	if err := Validate(c, c.Issued); err == nil {
		t.Fatal("limited broadcast reached grant validation")
	}
	if _, err := Sign(c, key); err == nil {
		t.Fatal("limited broadcast reached grant signing")
	}
}

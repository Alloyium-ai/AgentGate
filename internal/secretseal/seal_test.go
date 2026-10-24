// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package secretseal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const fakeValue = "sk-test-FAKE-seal-0123456789abcdef"

var now = time.Date(2026, 10, 24, 12, 0, 0, 0, time.UTC)

type fixture struct {
	hostPub  ed25519.PublicKey
	hostPriv ed25519.PrivateKey
	key      *HostKey
	pin      string
	pub      *PublicKey
	store    *Store
	dir      string
}

func newFixture(t *testing.T, target string) *fixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := GenerateHostKey(target, priv, now, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pin := HostKeyFingerprint(pub)
	rec := key.Published()
	sp, err := VerifyKeyRecord(&rec, pub, pin, target, now)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{hostPub: pub, hostPriv: priv, key: key, pin: pin, pub: sp, store: store, dir: dir}
}

func noValue(t *testing.T, what string, b []byte) {
	t.Helper()
	if bytes.Contains(b, []byte(fakeValue)) || bytes.Contains(b, []byte(base64.StdEncoding.EncodeToString([]byte(fakeValue)))) {
		t.Fatalf("value appears in %s", what)
	}
}

func TestSealOpenStoreAndReceipt(t *testing.T) {
	f := newFixture(t, "local")
	sealed, err := SealAt(f.pub, "local", "anthropic", []byte(fakeValue), now)
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(sealed.Envelope)
	noValue(t, "envelope", wire)
	env, err := ParseEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := f.store.Accept(f.key, env, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	rwire, _ := json.Marshal(receipt)
	noValue(t, "receipt", rwire)
	parsed, err := ParseReceipt(rwire)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := sealed.VerifyReceipt(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if fp != f.store.Fingerprint("local", "anthropic", []byte(fakeValue)) || !strings.HasPrefix(fp, "sfp1_") {
		t.Fatal(fp)
	}
	path, _ := f.store.SecretPath("anthropic")
	got, err := os.ReadFile(path)
	if err != nil || string(got) != fakeValue {
		t.Fatal("stored value differs")
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
	meta, _ := os.ReadFile(filepath.Join(f.dir, "anthropic.meta.json"))
	noValue(t, "metadata", meta)
	// The fingerprint is keyed: a different host store gives a different one.
	other := newFixture(t, "local")
	if other.store.Fingerprint("local", "anthropic", []byte(fakeValue)) == fp {
		t.Fatal("fingerprint is not keyed per host")
	}
}

func TestSubstitutedHostKeyIsRefused(t *testing.T) {
	f := newFixture(t, "local")
	evilPub, evilPriv, _ := ed25519.GenerateKey(rand.Reader)
	evil, err := GenerateHostKey("local", evilPriv, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rec := evil.Published()
	// The service presents its own seal key with the real host key: no signature.
	if _, err := VerifyKeyRecord(&rec, f.hostPub, f.pin, "local", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("own key under real host key: %v", err)
	}
	// The service presents its own host key too: the pin does not match.
	if _, err := VerifyKeyRecord(&rec, evilPub, f.pin, "local", now); !errors.Is(err, ErrFingerprint) {
		t.Fatalf("own host key: %v", err)
	}
	// The service swaps the public key inside the genuinely signed record.
	real := f.key.Published()
	real.Record.PublicKey = evil.Published().Record.PublicKey
	real.Record.KeyID = evil.Published().Record.KeyID
	if _, err := VerifyKeyRecord(&real, f.hostPub, f.pin, "local", now); !errors.Is(err, ErrSignature) {
		t.Fatalf("swapped key: %v", err)
	}
	// The client helper refuses all of these too, and never pins on a mismatch.
	known, _ := LoadKnownTargets(filepath.Join(t.TempDir(), "known.json"))
	if err := known.Pin("local", f.pin); err != nil {
		t.Fatal(err)
	}
	if _, st, err := SealForTarget(known, true, &rec, evilPub, "local", "anthropic", []byte(fakeValue), now); st != PinMismatch || err == nil {
		t.Fatal("substituted host key accepted", st, err)
	}
	// An attacker's own host key cannot open what the client sealed.
	sealed, _ := SealAt(f.pub, "local", "anthropic", []byte(fakeValue), now)
	if _, err := Open(evil, &sealed.Envelope, 0, now); err == nil {
		t.Fatal("a different host key opened the envelope")
	}
}

func TestSubstitutedCiphertextFailsTheReceipt(t *testing.T) {
	f := newFixture(t, "local")
	sealed, _ := SealAt(f.pub, "local", "anthropic", []byte(fakeValue), now)
	e := sealed.Envelope
	// The relay knows the public key and can seal a value of its choosing
	// (for example its own account key) with exactly the client's context.
	forged, err := seal(f.pub, e.TargetID, e.Name, e.Version, e.Nonce, []byte("sk-test-FAKE-attacker-account-key"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := f.store.Accept(f.key, &forged.Envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	// Every public receipt field matches the client's envelope; only the tag,
	// keyed by the client's own HPKE exporter secret, exposes the swap.
	if receipt.Nonce != e.Nonce || receipt.Version != e.Version || receipt.Name != e.Name {
		t.Fatal("forged context differs")
	}
	if _, err := sealed.VerifyReceipt(receipt); !errors.Is(err, ErrReceipt) {
		t.Fatal("client accepted a receipt for a substituted ciphertext")
	}
}

func TestTamperingIsDetected(t *testing.T) {
	f := newFixture(t, "local")
	sealed, _ := SealAt(f.pub, "local", "anthropic", []byte(fakeValue), now)
	raw, _ := base64.RawURLEncoding.DecodeString(sealed.Envelope.Sealed)
	for i := 0; i < len(raw); i++ {
		b := append([]byte(nil), raw...)
		b[i] ^= 0x01
		env := sealed.Envelope
		env.Sealed = base64.RawURLEncoding.EncodeToString(b)
		if _, err := Open(f.key, &env, 0, now); err == nil {
			t.Fatalf("byte %d flip accepted", i)
		}
	}
	mutations := map[string]func(e *Envelope){
		"name":      func(e *Envelope) { e.Name = "openai" },
		"version":   func(e *Envelope) { e.Version++ },
		"nonce":     func(e *Envelope) { e.Nonce = strings.Repeat("0", 32) },
		"target":    func(e *Envelope) { e.TargetID = "other" },
		"key id":    func(e *Envelope) { e.KeyID = strings.Repeat("a", 64) },
		"truncated": func(e *Envelope) { e.Sealed = e.Sealed[:40] },
		"format":    func(e *Envelope) { e.Format = "agentgate.secretseal.v0" },
		"empty":     func(e *Envelope) { e.Sealed = "" },
	}
	for name, m := range mutations {
		env := sealed.Envelope
		m(&env)
		if _, err := Open(f.key, &env, 0, now); err == nil {
			t.Errorf("%s change accepted", name)
		}
	}
	if _, err := Open(f.key, &sealed.Envelope, 0, now); err != nil {
		t.Fatal(err)
	}
}

func TestReplayStaleAndWrongContext(t *testing.T) {
	f := newFixture(t, "local")
	first, _ := SealAt(f.pub, "local", "anthropic", []byte(fakeValue), now)
	second, _ := SealAt(f.pub, "local", "anthropic", []byte(fakeValue+"2"), now.Add(time.Minute))
	if _, err := f.store.Accept(f.key, &second.Envelope, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Accept(f.key, &second.Envelope, now.Add(time.Minute)); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	if _, err := f.store.Accept(f.key, &first.Envelope, now.Add(time.Minute)); !errors.Is(err, ErrReplay) {
		t.Fatalf("rollback: %v", err)
	}
	path, _ := f.store.SecretPath("anthropic")
	if got, _ := os.ReadFile(path); string(got) != fakeValue+"2" {
		t.Fatal("a refused envelope changed the stored value")
	}
	old, _ := SealAt(f.pub, "local", "other", []byte(fakeValue), now.Add(-25*time.Hour))
	if _, err := Open(f.key, &old.Envelope, 0, now); !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	future, _ := SealAt(f.pub, "local", "other", []byte(fakeValue), now.Add(10*time.Minute))
	if _, err := Open(f.key, &future.Envelope, 0, now); !errors.Is(err, ErrStale) {
		t.Fatalf("future: %v", err)
	}
	if _, err := Open(f.key, &first.Envelope, 0, now.Add(31*24*time.Hour)); !errors.Is(err, ErrStale) {
		t.Fatalf("expired key: %v", err)
	}
	other := newFixture(t, "other-target")
	if _, err := Open(other.key, &first.Envelope, 0, now); !errors.Is(err, ErrContext) {
		t.Fatalf("wrong host: %v", err)
	}
	if _, err := SealAt(f.pub, "other-target", "anthropic", []byte(fakeValue), now); !errors.Is(err, ErrContext) {
		t.Fatal("sealed for a target the key does not belong to")
	}
	for _, name := range []string{"", "Anthropic", "../x", strings.Repeat("a", 41)} {
		if _, err := SealAt(f.pub, "local", name, []byte(fakeValue), now); err == nil {
			t.Errorf("name %q accepted", name)
		}
	}
	if _, err := SealAt(f.pub, "local", "a", nil, now); !errors.Is(err, ErrValue) {
		t.Fatal("empty value")
	}
	if _, err := SealAt(f.pub, "local", "a", make([]byte, MaxValueBytes+1), now); !errors.Is(err, ErrValue) {
		t.Fatal("oversize value")
	}
}

func TestReceiptTampering(t *testing.T) {
	f := newFixture(t, "local")
	sealed, _ := SealAt(f.pub, "local", "anthropic", []byte(fakeValue), now)
	receipt, err := f.store.Accept(f.key, &sealed.Envelope, now)
	if err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]func(r *Receipt){
		"fingerprint": func(r *Receipt) { r.Fingerprint = "sfp1_" + strings.Repeat("0", 32) },
		"tag":         func(r *Receipt) { r.Tag = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) },
		"version":     func(r *Receipt) { r.Version++ },
		"name":        func(r *Receipt) { r.Name = "other" },
		"format":      func(r *Receipt) { r.Format = "x" },
	} {
		r := *receipt
		m(&r)
		if _, err := sealed.VerifyReceipt(&r); !errors.Is(err, ErrReceipt) {
			t.Errorf("%s change accepted", name)
		}
	}
	if _, err := sealed.VerifyReceipt(receipt); err != nil {
		t.Fatal(err)
	}
}

func TestKnownTargetsTrustOnFirstUse(t *testing.T) {
	f := newFixture(t, "local")
	path := filepath.Join(t.TempDir(), "agentgate", "known-targets.json")
	known, err := LoadKnownTargets(path)
	if err != nil {
		t.Fatal(err)
	}
	rec := f.key.Published()
	if _, st, err := SealForTarget(known, false, &rec, f.hostPub, "local", "anthropic", []byte(fakeValue), now); st != PinUnknown || err == nil {
		t.Fatal("sealed to an unpinned target without trust on first use")
	}
	sealed, st, err := SealForTarget(known, true, &rec, f.hostPub, "local", "anthropic", []byte(fakeValue), now)
	if err != nil || st != PinUnknown || sealed == nil {
		t.Fatal(st, err)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatal("pin file", err)
	}
	reloaded, err := LoadKnownTargets(path)
	if err != nil || reloaded.Check("local", f.pin) != PinMatch {
		t.Fatal("pin not persisted")
	}
	if _, st, err = SealForTarget(reloaded, true, &rec, f.hostPub, "local", "anthropic", []byte(fakeValue), now); st != PinMatch || err != nil {
		t.Fatal(st, err)
	}
	other := newFixture(t, "local")
	orec := other.key.Published()
	if _, st, err = SealForTarget(reloaded, true, &orec, other.hostPub, "local", "anthropic", []byte(fakeValue), now); st != PinMismatch || err == nil {
		t.Fatal("re-keyed host accepted under trust on first use")
	}
	if err := reloaded.Pin("local", other.pin); !errors.Is(err, ErrFingerprint) {
		t.Fatal("an existing pin was replaced")
	}
}

func TestStoreAndKeyCustody(t *testing.T) {
	base := t.TempDir()
	open := filepath.Join(base, "open")
	os.Mkdir(open, 0o755)
	if _, err := OpenStore(open); err == nil {
		t.Fatal("world-readable store accepted")
	}
	real := filepath.Join(base, "real")
	os.Mkdir(real, 0o700)
	os.Symlink(real, filepath.Join(base, "link"))
	if _, err := OpenStore(filepath.Join(base, "link")); err == nil {
		t.Fatal("symlinked store accepted")
	}
	s1, err := OpenStore(real)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := OpenStore(real)
	if err != nil || !bytes.Equal(s1.fpKey, s2.fpKey) {
		t.Fatal("fingerprint key not stable")
	}
	os.Chmod(filepath.Join(real, fingerprintKeyFile), 0o644)
	if _, err := OpenStore(real); err == nil {
		t.Fatal("exposed fingerprint key accepted")
	}
	f := newFixture(t, "local")
	priv, err := f.key.MarshalPrivate()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParseHostKey(priv, f.hostPub)
	if err != nil {
		t.Fatal(err)
	}
	sealed, _ := SealAt(f.pub, "local", "anthropic", []byte(fakeValue), now)
	if o, err := Open(k2, &sealed.Envelope, 0, now); err != nil || string(o.Value) != fakeValue {
		t.Fatal("restored key cannot open")
	}
	evilPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParseHostKey(priv, evilPub); err == nil {
		t.Fatal("stored key accepted under another host key")
	}
}

// vector is a fixed known-answer case. It pins the wire format: a change to
// the AAD, info, suite, fingerprint or receipt encoding breaks it.
type vector struct {
	HostSeed       string          `json:"host_ed25519_seed"`
	SealPrivate    string          `json:"seal_x25519_private"`
	TargetID       string          `json:"target_id"`
	NotBefore      string          `json:"not_before"`
	Record         SignedKeyRecord `json:"record"`
	Envelope       Envelope        `json:"envelope"`
	Plaintext      string          `json:"plaintext"`
	FingerprintKey string          `json:"fingerprint_key"`
	Fingerprint    string          `json:"fingerprint"`
	Receipt        Receipt         `json:"receipt"`
}

func vectorKeys(t *testing.T, v *vector) (*HostKey, ed25519.PublicKey) {
	seed, _ := hex.DecodeString(v.HostSeed)
	priv := ed25519.NewKeyFromSeed(seed)
	raw, _ := hex.DecodeString(v.SealPrivate)
	nb, _ := time.Parse(time.RFC3339, v.NotBefore)
	key, err := newHostKey(v.TargetID, raw, priv, nb, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return key, priv.Public().(ed25519.PublicKey)
}

func TestKnownAnswerVector(t *testing.T) {
	path := filepath.Join("testdata", "vector-v1.json")
	if os.Getenv("AGENTGATE_SECRETSEAL_WRITE_VECTOR") == "1" {
		v := vector{HostSeed: strings.Repeat("11", 32), SealPrivate: strings.Repeat("22", 32), TargetID: "vector-target",
			NotBefore: "2026-10-01T00:00:00Z", Plaintext: "sk-test-FAKE-vector-value", FingerprintKey: strings.Repeat("33", 32)}
		key, pub := vectorKeys(t, &v)
		v.Record = key.Published()
		sp, err := VerifyKeyRecord(&v.Record, pub, HostKeyFingerprint(pub), v.TargetID, time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := SealAt(sp, v.TargetID, "vector", []byte(v.Plaintext), time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		v.Envelope = sealed.Envelope
		fk, _ := hex.DecodeString(v.FingerprintKey)
		v.Fingerprint = Fingerprint(fk, v.TargetID, "vector", []byte(v.Plaintext))
		o, err := Open(key, &v.Envelope, 0, time.Date(2026, 10, 2, 0, 0, 1, 0, time.UTC))
		if err != nil {
			t.Fatal(err)
		}
		v.Receipt = *o.Receipt(v.Fingerprint)
		raw, _ := json.MarshalIndent(v, "", "  ")
		os.MkdirAll("testdata", 0o755)
		if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	key, pub := vectorKeys(t, &v)
	// Ed25519 is deterministic, so the signed record is reproduced exactly.
	if got := key.Published(); got != v.Record {
		t.Fatalf("record differs:\n%+v\n%+v", got, v.Record)
	}
	at := time.Date(2026, 10, 2, 0, 0, 1, 0, time.UTC)
	if _, err := VerifyKeyRecord(&v.Record, pub, HostKeyFingerprint(pub), v.TargetID, at); err != nil {
		t.Fatal(err)
	}
	o, err := Open(key, &v.Envelope, 0, at)
	if err != nil {
		t.Fatal(err)
	}
	if string(o.Value) != v.Plaintext {
		t.Fatal("plaintext differs")
	}
	fk, _ := hex.DecodeString(v.FingerprintKey)
	if fp := Fingerprint(fk, v.TargetID, "vector", o.Value); fp != v.Fingerprint {
		t.Fatal("fingerprint differs")
	}
	if r := o.Receipt(v.Fingerprint); *r != v.Receipt {
		t.Fatalf("receipt differs:\n%+v\n%+v", r, v.Receipt)
	}
}

func TestSuiteIdentifiers(t *testing.T) {
	// RFC 9180 section 7: DHKEM(X25519, HKDF-SHA256) 0x0020, HKDF-SHA256
	// 0x0001, ChaCha20Poly1305 0x0003.
	kdf, aead := suite()
	if hpke.DHKEM(ecdh.X25519()).ID() != 0x0020 || kdf.ID() != 0x0001 || aead.ID() != 0x0003 {
		t.Fatal("suite identifiers differ from the documented suite")
	}
}

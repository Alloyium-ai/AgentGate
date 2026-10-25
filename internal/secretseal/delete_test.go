// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package secretseal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A deleted secret keeps a tombstone with its last version: a relayed copy of
// the envelope that set it (still inside MaxAge) must not set it again.
func TestDeleteZeroesTheValueAndRefusesAReplayAfterwards(t *testing.T) {
	f := newFixture(t, "local")
	sealed, err := SealAt(f.pub, "local", "anthropic", testPolicy, []byte(fakeValue), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Accept(f.key, &sealed.Envelope, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	st, ok, err := f.store.Stored("anthropic")
	if err != nil || !ok || st.Version != sealed.Envelope.Version || st.Fingerprint == "" || st.PolicyDigest != testPolicy {
		t.Fatalf("stored %+v %v %v", st, ok, err)
	}
	path, _ := f.store.SecretPath("anthropic")
	link := filepath.Join(t.TempDir(), "held")
	// A process that still holds the file (a broker that already read it)
	// sees zeros, not the value, once it is deleted.
	held, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := f.store.Delete("anthropic", now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(fakeValue))
	if n, _ := held.ReadAt(buf, 0); n != len(fakeValue) || string(buf) == fakeValue {
		t.Fatal("the deleted value was not overwritten")
	}
	for _, b := range buf {
		if b != 0 {
			t.Fatal("the deleted value was not zeroed")
		}
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the value file remains")
	}
	if _, ok, err := f.store.Stored("anthropic"); ok || err != nil {
		t.Fatalf("a deleted secret is still reported: %v", err)
	}
	meta, _ := os.ReadFile(filepath.Join(f.dir, "anthropic.meta.json"))
	noValue(t, "tombstone", meta)
	if _, err := f.store.Accept(f.key, &sealed.Envelope, now.Add(3*time.Second)); !errors.Is(err, ErrReplay) {
		t.Fatalf("a replay after delete: %v", err)
	}
	// A newer envelope sets the name again.
	fresh, _ := SealAt(f.pub, "local", "anthropic", testPolicy, []byte(fakeValue+"-rotated"), now.Add(4*time.Second))
	if _, err := f.store.Accept(f.key, &fresh.Envelope, now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := f.store.Stored("anthropic"); !ok {
		t.Fatal("a newer envelope did not set the name again")
	}
	// Deleting twice, or a name never set, succeeds.
	if err := f.store.Delete("never-set", now); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Delete("anthropic", now.Add(6*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Delete("anthropic", now.Add(7*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Delete("../x", now); err == nil {
		t.Fatal("a hostile name reached the file system")
	}
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	// A symlinked value file is never followed.
	if err := os.Symlink(link, filepath.Join(f.dir, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := f.store.Delete("linked", now); err == nil {
		t.Fatal("a symlinked secret file was followed")
	}
}

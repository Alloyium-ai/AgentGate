// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNodeClientUsesPinnedPeerAndVerifiesReceipt(t *testing.T) {
	f := newFixture(t)
	a := f.issue(t)
	bundle := f.bundleSize(t, a, 3100)
	raw, _ := json.Marshal(bundle)
	if len(raw) <= 2<<20 {
		t.Fatal("large audit fixture is too small", len(raw))
	}
	path := filepath.Join(f.dir, "client.sock")
	listener, e := ListenUnix(path, nil)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: f.s, ReadHeaderTimeout: 15 * time.Second}
	done := make(chan struct{})
	go func() { server.Serve(listener); close(done) }()
	defer func() { server.Close(); <-done }()
	config := ClientConfig{SocketPath: path, AuthorityID: "authority", Epoch: f.store.Epoch(), NodeID: "node-one", SigningKey: f.node, PeerUID: uint32(os.Geteuid()), AuthorityKeys: f.s.authorityKeys(), NodeKeys: f.config.NodeKeys, Documents: f.deps, Registry: testRegistry, Timeout: 15 * time.Second}
	client, e := NewClient(config)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	state, e := client.State(context.Background(), "grant-one")
	if e != nil || !state.Known || state.Revoked {
		t.Fatal(state, e)
	}
	receipt, e := client.Countersign(context.Background(), bundle)
	if e != nil || !receipt.Accepted || receipt.NodeSealDigest != jobaudit.SealDigest(*bundle.Seal) {
		t.Fatal(receipt, e)
	}
	config.PeerUID++
	wrong, e := NewClient(config)
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	if _, e = wrong.State(context.Background(), "grant-one"); e == nil {
		t.Fatal("wrong peer UID accepted")
	}
	config.PeerUID--
	config.Epoch = "wrong-epoch"
	wrong, e = NewClient(config)
	if e != nil {
		t.Fatal(e)
	}
	defer wrong.Close()
	if _, e = wrong.State(context.Background(), "grant-one"); e == nil {
		t.Fatal("wrong epoch accepted")
	}
}
func TestStoreRejectsOtherEpochSignerAndConcurrentOwner(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.dir, "authority.db")
	if _, e := OpenStore(path, "fixture-epoch"); e == nil {
		t.Fatal("concurrent signer store owner accepted")
	}
	f.store.Close()
	if _, e := OpenStore(path, "different-epoch"); e == nil {
		t.Fatal("epoch replacement accepted")
	}
	s, e := OpenStore(path, "fixture-epoch")
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if e = s.bindSigner("other-key"); e == nil {
		t.Fatal("signer replacement accepted")
	}
}
func TestPrivatePathsRejectLinksAndOpenPermissions(t *testing.T) {
	f := newFixture(t)
	bad := filepath.Join(f.dir, "link")
	if e := os.Symlink("authority.db", bad); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadPrivate(bad, 1<<20); e == nil {
		t.Fatal("linked credential accepted")
	}
	file := filepath.Join(f.dir, "open-key")
	os.WriteFile(file, []byte("fixture"), 0644)
	os.Chmod(file, 0644)
	if _, e := ReadPrivate(file, 1<<20); e == nil {
		t.Fatal("open credential accepted")
	}
}
func TestUDSRestartRemovesOnlyOwnedRefusedSocket(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(f.dir, "restart.sock")
	listener, e := ListenUnix(path, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = ListenUnix(path, nil); e == nil {
		t.Fatal("active authority socket replaced")
	}
	listener.SetUnlinkOnClose(false)
	listener.Close()
	replacement, e := ListenUnix(path, nil)
	if e != nil {
		t.Fatal(e)
	}
	replacement.Close()
	regular := filepath.Join(f.dir, "regular")
	os.WriteFile(regular, []byte("fixture"), 0600)
	if _, e = ListenUnix(regular, nil); e == nil {
		t.Fatal("regular file replaced")
	}
}

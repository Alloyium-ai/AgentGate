// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/requestproof"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthenticatedRevokeUDSOwnershipReplayAndRestart(t *testing.T) {
	f := newFixture(t)
	f.issue(t)
	foreign := ed25519.NewKeyFromSeed([]byte(strings.Repeat("f", 32)))
	f.config.Subjects["agent-two"] = ProofSubject{Role: "agent", Key: foreign.Public().(ed25519.PublicKey)}
	var err error
	f.s, err = New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(f.dir, "revoke.sock")
	start := func() (func(), *http.Client) {
		listener, e := ListenUnix(path, nil)
		if e != nil {
			t.Fatal(e)
		}
		server := &http.Server{Handler: f.s, ReadHeaderTimeout: time.Second}
		done := make(chan struct{})
		go func() { server.Serve(listener); close(done) }()
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}}
		return func() { transport.CloseIdleConnections(); server.Close(); <-done }, &http.Client{Transport: transport, Timeout: time.Second}
	}
	closeServer, client := start()
	send := func(method, target, subject string, key ed25519.PrivateKey, value any, token string) (int, []byte, string) {
		raw := []byte{}
		if value != nil {
			raw, _ = json.Marshal(value)
		}
		if token == "" {
			token = requestproof.Sign(subject, method, target, "agentgate-authority.v1:authority", f.store.Epoch(), raw, key)
		}
		req, e := http.NewRequest(method, "http://authority"+target, bytes.NewReader(raw))
		if e != nil {
			t.Fatal(e)
		}
		req.Header.Set("Authorization", "Alloyium-Proof "+token)
		response, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer response.Body.Close()
		body, e := io.ReadAll(response.Body)
		if e != nil {
			t.Fatal(e)
		}
		return response.StatusCode, body, token
	}
	request := RevokeRequest{Protocol: RevokeProtocol, GrantID: "grant-one"}
	foreignStatus, foreignBody, _ := send("POST", "/v1/grants/revoke", "agent-two", foreign, request, "")
	unknownStatus, unknownBody, _ := send("POST", "/v1/grants/revoke", "agent-one", f.agent, RevokeRequest{Protocol: RevokeProtocol, GrantID: "unknown"}, "")
	if foreignStatus != 403 || unknownStatus != 403 || !bytes.Equal(foreignBody, unknownBody) {
		t.Fatal("foreign/unknown revoke leaked grant state", foreignStatus, unknownStatus)
	}
	nodeStatus, _, _ := send("POST", "/v1/grants/revoke", "node-one", f.node, request, "")
	if nodeStatus != 401 {
		t.Fatal("node proof revoked an agent grant", nodeStatus)
	}
	status, body, token := send("POST", "/v1/grants/revoke", "agent-one", f.agent, request, "")
	var state StateResponse
	if status != 200 || json.Unmarshal(body, &state) != nil || state.Protocol != StateProtocol || !state.Known || !state.Revoked || state.GrantID != "grant-one" {
		t.Fatal(status, string(body))
	}
	if _, revoked, e := f.store.Grant(context.Background(), "grant-one"); e != nil || !revoked {
		t.Fatal("reply preceded durable revoke", e)
	}
	status, _, _ = send("POST", "/v1/grants/revoke", "agent-one", f.agent, request, token)
	if status != 401 {
		t.Fatal("revoke proof replay accepted", status)
	}
	closeServer()
	if err = f.store.Close(); err != nil {
		t.Fatal(err)
	}
	f.store, err = OpenStore(filepath.Join(f.dir, "authority.db"), "fixture-epoch")
	if err != nil {
		t.Fatal(err)
	}
	defer f.store.Close()
	f.config.Store = f.store
	f.s, err = New(f.config)
	if err != nil {
		t.Fatal(err)
	}
	closeServer, client = start()
	defer closeServer()
	status, body, _ = send("GET", "/v1/grants/state?grant_id=grant-one", "node-one", f.node, nil, "")
	if status != 200 || json.Unmarshal(body, &state) != nil || !state.Known || !state.Revoked {
		t.Fatal("restart lost revoke", status, string(body))
	}
	status, _, _ = send("POST", "/v1/grants/revoke", "agent-one", f.agent, request, token)
	if status != 401 {
		t.Fatal("restart lost proof custody", status)
	}
}

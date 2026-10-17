// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/requestproof"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

type ClientConfig struct {
	SocketPath    string
	AuthorityID   string
	Epoch         string
	NodeID        string
	SigningKey    ed25519.PrivateKey
	PeerUID       uint32
	AuthorityKeys map[string]ed25519.PublicKey
	NodeKeys      map[string]ed25519.PublicKey
	Documents     ApprovedDocuments
	Registry      func(lifecycle.Binding) jobaudit.Registry
	Timeout       time.Duration
}
type Client struct {
	config ClientConfig
	http   *http.Client
}

func NewClient(c ClientConfig) (*Client, error) {
	if !identifier.MatchString(c.AuthorityID) || !identifier.MatchString(c.Epoch) || !identifier.MatchString(c.NodeID) || len(c.SigningKey) != ed25519.PrivateKeySize || !filepath.IsAbs(c.SocketPath) || filepath.Clean(c.SocketPath) != c.SocketPath || strings.HasPrefix(c.SocketPath, "/tmp/") || c.Timeout <= 0 || c.Timeout > 30*time.Second || c.Documents == nil || c.Registry == nil || len(c.AuthorityKeys) == 0 || len(c.NodeKeys) == 0 {
		return nil, errors.New("authority_client_invalid")
	}
	c.SigningKey = append(ed25519.PrivateKey{}, c.SigningKey...)
	var e error
	c.AuthorityKeys, e = copyClientKeys(c.AuthorityKeys)
	if e != nil {
		return nil, e
	}
	c.NodeKeys, e = copyClientKeys(c.NodeKeys)
	if e != nil {
		return nil, e
	}
	for _, a := range c.AuthorityKeys {
		if bytes.Equal(a, c.SigningKey.Public().(ed25519.PublicKey)) {
			return nil, errors.New("authority_client_key_roles_overlap")
		}
		for _, n := range c.NodeKeys {
			if bytes.Equal(a, n) {
				return nil, errors.New("authority_client_key_roles_overlap")
			}
		}
	}
	client := &Client{config: c}
	transport := &http.Transport{Proxy: nil, DialContext: client.dial, MaxConnsPerHost: 2, MaxIdleConns: 2, IdleConnTimeout: 30 * time.Second, ResponseHeaderTimeout: c.Timeout}
	client.http = &http.Client{Transport: transport, Timeout: c.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("authority_redirect_rejected") }}
	return client, nil
}
func copyClientKeys(keys map[string]ed25519.PublicKey) (map[string]ed25519.PublicKey, error) {
	out := map[string]ed25519.PublicKey{}
	for id, k := range keys {
		parts := strings.Split(id, "/")
		if len(parts) != 2 || !identifier.MatchString(parts[0]) || !identifier.MatchString(parts[1]) || len(k) != ed25519.PublicKeySize {
			return nil, errors.New("authority_client_key_invalid")
		}
		out[id] = append(ed25519.PublicKey{}, k...)
	}
	return out, nil
}
func (c *Client) dial(ctx context.Context, _, _ string) (net.Conn, error) {
	parent := filepath.Dir(c.config.SocketPath)
	real, e := filepath.EvalSymlinks(parent)
	if e != nil || real != parent {
		return nil, errors.New("authority_peer_path_invalid")
	}
	for _, path := range []string{parent, c.config.SocketPath} {
		st, e := os.Lstat(path)
		if e != nil {
			return nil, errors.New("authority_peer_unavailable")
		}
		mask := os.FileMode(0027)
		if path == c.config.SocketPath {
			mask = 0007
		}
		stat := unix.Stat_t{}
		if unix.Lstat(path, &stat) != nil || stat.Uid != c.config.PeerUID || st.Mode().Perm()&mask != 0 {
			return nil, errors.New("authority_peer_custody_invalid")
		}
		if path == c.config.SocketPath && (st.Mode()&os.ModeSocket == 0 || st.Mode().Perm()&0007 != 0) {
			return nil, errors.New("authority_peer_socket_invalid")
		}
	}
	conn, e := (&net.Dialer{}).DialContext(ctx, "unix", c.config.SocketPath)
	if e != nil {
		return nil, errors.New("authority_peer_unavailable")
	}
	fail := func() (net.Conn, error) { conn.Close(); return nil, errors.New("authority_peer_credentials_invalid") }
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return fail()
	}
	raw, e := uc.SyscallConn()
	if e != nil {
		return fail()
	}
	var cred *unix.Ucred
	var ce error
	e = raw.Control(func(fd uintptr) { cred, ce = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil || ce != nil || cred == nil || cred.Uid != c.config.PeerUID {
		return fail()
	}
	return conn, nil
}
func (c *Client) Close() { c.http.CloseIdleConnections() }
func (c *Client) request(ctx context.Context, method, path string, value any, out any) error {
	body := []byte{}
	var e error
	if value != nil {
		body, e = json.Marshal(value)
		if e != nil {
			return errors.New("authority_request_encoding_failed")
		}
	}
	if len(body) > MaxAuditBytes {
		return errors.New("authority_request_bound_exceeded")
	}
	req, e := http.NewRequestWithContext(ctx, method, "http://authority"+path, bytes.NewReader(body))
	if e != nil {
		return errors.New("authority_request_invalid")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Alloyium-Proof "+requestproof.Sign(c.config.NodeID, method, path, "agentgate-authority.v1:"+c.config.AuthorityID, c.config.Epoch, body, c.config.SigningKey))
	reply, e := c.http.Do(req)
	if e != nil {
		return errors.New("authority_request_unavailable")
	}
	defer reply.Body.Close()
	if reply.StatusCode != 200 {
		return errors.New("authority_request_rejected")
	}
	raw, e := io.ReadAll(io.LimitReader(reply.Body, (2<<20)+1))
	if e != nil || len(raw) > 2<<20 || lifecycle.DecodeTransport(bytes.NewReader(raw), out) != nil {
		return errors.New("authority_response_invalid")
	}
	return nil
}
func (c *Client) State(ctx context.Context, id string) (jobgrant.RevocationState, error) {
	if !identifier.MatchString(id) {
		return jobgrant.RevocationState{}, errors.New("authority_grant_id_invalid")
	}
	var r StateResponse
	if e := c.request(ctx, "GET", "/v1/grants/state?grant_id="+id, nil, &r); e != nil {
		return jobgrant.RevocationState{}, e
	}
	if r.Protocol != StateProtocol || r.GrantID != id || (!r.Known && r.Revoked) {
		return jobgrant.RevocationState{}, errors.New("authority_state_invalid")
	}
	return jobgrant.RevocationState{Known: r.Known, Revoked: r.Revoked}, nil
}
func (c *Client) Countersign(ctx context.Context, b jobaudit.Bundle) (jobaudit.AuthorityReceipt, error) {
	var out jobaudit.AuthorityReceipt
	if b.Header.Binding.NodeID != c.config.NodeID || b.Seal == nil || b.Grant == nil || b.Authority != nil {
		return out, errors.New("authority_bundle_invalid")
	}
	document, e := c.config.Documents.Resolve(ctx, b.Header.DocumentDigest)
	if e != nil {
		return out, errors.New("authority_document_unavailable")
	}
	var reply ReceiptResponse
	if e = c.request(ctx, "POST", "/v1/audit/receipt", b, &reply); e != nil {
		return out, e
	}
	out = reply.Receipt
	if reply.Protocol != ReceiptProtocol || out.AuthorityID != c.config.AuthorityID || !reflect.DeepEqual(out.Binding, b.Header.Binding) || out.NodeSealDigest != jobaudit.SealDigest(*b.Seal) {
		return jobaudit.AuthorityReceipt{}, errors.New("authority_receipt_binding_invalid")
	}
	b.Authority = &out
	trust := jobaudit.Trust{NodeKeys: c.config.NodeKeys, AuthorityKeys: c.config.AuthorityKeys, Registry: c.config.Registry(b.Header.Binding), Document: document}
	if verdict := jobaudit.VerifyOffline(b, trust); verdict.State != "VALID_COMPLETE" {
		return jobaudit.AuthorityReceipt{}, errors.New("authority_receipt_signature_or_evidence_invalid")
	}
	return out, nil
}

var _ jobgrant.RevocationProvider = (*Client)(nil)

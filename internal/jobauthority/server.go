// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/requestproof"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

type Server struct {
	config      Config
	failed      atomic.Bool
	receiptSlot chan struct{}
}

func New(c Config) (*Server, error) {
	if !identifier.MatchString(c.AuthorityID) || !identifier.MatchString(c.KeyID) || len(c.SigningKey) != ed25519.PrivateKeySize || c.Store == nil || c.Enrollment == nil || c.Documents == nil || c.Qualification == nil || c.Preparations == nil || c.Clock == nil || c.Registry == nil || c.MaxLifetime < time.Second || c.MaxLifetime > 24*time.Hour || c.RequestTimeout <= 0 || c.RequestTimeout > 30*time.Second {
		return nil, errors.New("authority_dependencies_invalid")
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(c.SigningKey[:32]), c.SigningKey) {
		return nil, errors.New("authority_signer_invalid")
	}
	public := c.SigningKey.Public().(ed25519.PublicKey)
	if len(c.Subjects) == 0 || len(c.NodeKeys) == 0 {
		return nil, errors.New("authority_pinned_subjects_required")
	}
	subjects := map[string]ProofSubject{}
	for id, p := range c.Subjects {
		if !identifier.MatchString(id) || (p.Role != "agent" && p.Role != "node") || len(p.Key) != ed25519.PublicKeySize || bytes.Equal(p.Key, public) {
			return nil, errors.New("authority_subject_invalid")
		}
		p.Key = append(ed25519.PublicKey{}, p.Key...)
		subjects[id] = p
	}
	nodes := map[string]ed25519.PublicKey{}
	for id, k := range c.NodeKeys {
		parts := strings.Split(id, "/")
		if len(parts) != 2 || !identifier.MatchString(parts[0]) || !identifier.MatchString(parts[1]) || len(k) != ed25519.PublicKeySize || bytes.Equal(k, public) {
			return nil, errors.New("authority_node_key_invalid")
		}
		subject, ok := subjects[parts[0]]
		if !ok || subject.Role != "node" {
			return nil, errors.New("authority_node_subject_invalid")
		}
		for _, p := range subjects {
			if p.Role == "agent" && bytes.Equal(p.Key, k) {
				return nil, errors.New("authority_node_agent_keys_overlap")
			}
		}
		nodes[id] = append(ed25519.PublicKey{}, k...)
	}
	for _, a := range subjects {
		for _, b := range subjects {
			if a.Role != b.Role && bytes.Equal(a.Key, b.Key) {
				return nil, errors.New("authority_subject_roles_overlap")
			}
		}
	}
	c.Subjects = subjects
	c.NodeKeys = nodes
	c.SigningKey = append(ed25519.PrivateKey{}, c.SigningKey...)
	identity := c.AuthorityID + "/" + c.KeyID + "/" + base64.RawURLEncoding.EncodeToString(public)
	if e := c.Store.bindSigner(identity); e != nil {
		return nil, e
	}
	return &Server{config: c, receiptSlot: make(chan struct{}, 1)}, nil
}
func problem(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": code}})
}
func response(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(v)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recover() != nil {
			s.failed.Store(true)
			problem(w, 500, "authority_internal_failure")
		}
	}()
	if s.failed.Load() {
		problem(w, 503, "authority_unavailable")
		return
	}
	if r.URL.Fragment != "" || r.URL.RawPath != "" || len(r.RequestURI) > 512 {
		problem(w, 400, "authority_request_target_invalid")
		return
	}
	role := ""
	switch {
	case r.Method == "POST" && r.URL.Path == "/v1/grants/issue" && r.URL.RawQuery == "":
		role = "agent"
	case r.Method == "POST" && r.URL.Path == "/v1/grants/revoke" && r.URL.RawQuery == "":
		role = "agent"
	case r.Method == "GET" && r.URL.Path == "/v1/grants/state":
		role = "node"
	case r.Method == "POST" && r.URL.Path == "/v1/audit/receipt" && r.URL.RawQuery == "":
		role = "node"
	default:
		problem(w, 404, "authority_route_unknown")
		return
	}
	bound := int64(2 << 20)
	if r.URL.Path == "/v1/audit/receipt" {
		select {
		case s.receiptSlot <- struct{}{}:
			defer func() { <-s.receiptSlot }()
		default:
			problem(w, 503, "authority_receipt_busy")
			return
		}
		bound = MaxAuditBytes
	}
	body, e := io.ReadAll(io.LimitReader(r.Body, bound+1))
	if e != nil || int64(len(body)) > bound || (r.Method == "GET" && len(body) != 0) {
		problem(w, 413, "authority_request_bound_exceeded")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.config.RequestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	subject, e := s.authenticate(r, body, role)
	if e != nil {
		problem(w, 401, e.Error())
		return
	}
	switch r.URL.Path {
	case "/v1/grants/issue":
		s.issue(w, r, subject, body)
	case "/v1/grants/revoke":
		s.revoke(w, r, subject, body)
	case "/v1/grants/state":
		s.state(w, r, subject)
	case "/v1/audit/receipt":
		s.receipt(w, r, subject, body)
	}
}
func (s *Server) authenticate(r *http.Request, body []byte, role string) (string, error) {
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 || !strings.HasPrefix(auth[0], "Alloyium-Proof ") {
		return "", errors.New("authority_proof_required")
	}
	token := strings.TrimPrefix(auth[0], "Alloyium-Proof ")
	c, e := requestproof.Parse(token)
	parts := strings.Split(token, ".")
	if e != nil || len(parts) != 3 {
		return "", errors.New("authority_proof_invalid")
	}
	claims, ce := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if ce != nil || lifecycle.DecodeTransport(bytes.NewReader(claims), &c) != nil {
		return "", errors.New("authority_proof_invalid")
	}
	p, ok := s.config.Subjects[c.Subject]
	if !ok || p.Role != role {
		return "", errors.New("authority_subject_rejected")
	}
	c, e = requestproof.Verify(token, p.Key, "agentgate-authority.v1:"+s.config.AuthorityID, s.config.Store.Epoch(), r.Method, r.URL.RequestURI(), body)
	nonce, e2 := base64.RawURLEncoding.Strict().DecodeString(c.Nonce)
	if e != nil || e2 != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != c.Nonce {
		return "", errors.New("authority_proof_invalid")
	}
	if e = s.config.Store.Consume(r.Context(), c.Subject, c.Nonce, c.Time+65, time.Now().Unix()); e != nil {
		return "", errors.New("authority_proof_replay_or_store_unavailable")
	}
	return c.Subject, nil
}

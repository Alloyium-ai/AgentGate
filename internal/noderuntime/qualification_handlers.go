// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"
)

type qualificationSession struct {
	node     *Node
	spec     lifecycle.QualificationFixtureSpec
	ctx      context.Context
	mu       sync.Mutex
	prepared bool
	started  bool
	waitDone chan struct{}
	version  *lifecycle.QualificationVersionSpec
}

func (s *qualificationSession) prepare(ctx context.Context) (out QualificationPrepared, err error) {
	if s.prepared {
		return out, errors.New("the fixed fixture preparation already exists")
	}
	s.prepared = true
	r, err := s.node.manager.PrepareFor(ctx, s.spec.Binding, time.Duration(s.node.config.PreparationLeaseMS)*time.Millisecond)
	if err != nil {
		return out, err
	}
	defer func() {
		if err != nil {
			_, _ = s.node.manager.Stop(context.WithoutCancel(ctx), s.spec.Binding.RunID, "prepare-response-failed")
		}
	}()
	tables, header, digest, err := s.node.backend.QualificationPreparation(ctx, r.Binding.RunID)
	if err != nil {
		return out, err
	}
	wire, err := tables.Wire()
	if err != nil {
		return out, err
	}
	mono, err := (Clock{}).NowNS()
	if err != nil {
		return out, err
	}
	out = QualificationPrepared{Protocol: s.preparedProtocol(), Purpose: s.purpose(), PermitDigest: s.node.fixture.Digest(), TargetDigest: s.spec.TargetDigest, Record: r, Quarantine: wire, AuditHeader: header, AuditHeaderDigest: digest, PreparedAtUnix: time.Now().Unix(), PreparedMonoNS: mono, NodeKeyID: s.node.sources.Signer.KeyID()}
	raw, err := s.preparedSigningBytes(out)
	if err != nil {
		return out, err
	}
	signature, err := s.node.sources.Signer.Sign(ctx, raw)
	if err != nil {
		return out, err
	}
	out.Signature = base64.RawURLEncoding.EncodeToString(signature)
	key, err := s.node.sources.WatchdogKey()
	if err != nil {
		return out, err
	}
	if s.version != nil {
		_, err = VerifyQualificationVersionPrepared(QualificationVersionPrepared(out), *s.version, s.node.sources.NodeKeys, key, time.Now().Unix(), time.Second)
	} else {
		_, err = VerifyQualificationPrepared(out, s.spec, s.node.sources.NodeKeys, key, time.Now().Unix(), time.Second)
	}
	return out, err
}
func qualificationInput(m lifecycle.Manifest) ([]byte, error) {
	for _, v := range []byte{'T', 'E'} {
		sum := sha256.Sum256([]byte{v})
		if hex.EncodeToString(sum[:]) == m.InputDigest {
			return []byte{v}, nil
		}
	}
	return nil, errors.New("the fixed worker input differs")
}
func (s *qualificationSession) start(ctx context.Context, r QualificationRunRequest) (out QualificationStatus, err error) {
	if r.Protocol != s.runProtocol() || !s.prepared || s.started {
		return out, errors.New("the fixed fixture run phase differs")
	}
	if err = s.node.fixture.CheckAuthorization(r.Authorization); err != nil {
		return out, err
	}
	s.started = true
	id := s.spec.Binding.RunID
	defer func() {
		if err != nil {
			_, stopErr := s.node.manager.Stop(context.WithoutCancel(ctx), id, "run-failed")
			err = errors.Join(err, stopErr)
		}
	}()
	input, err := s.input()
	if err != nil {
		return out, err
	}
	p, err := s.node.backend.Stage(ctx, r.Authorization, s.spec.Manifest, input)
	if err != nil {
		return out, err
	}
	if _, err = s.node.manager.Place(ctx, id, p); err != nil {
		return out, err
	}
	if _, err = s.node.manager.Install(ctx, id, r.Authorization); err != nil {
		return out, err
	}
	if _, err = s.node.manager.Release(ctx, id); err != nil {
		return out, err
	}
	out, err = s.status(ctx)
	if err != nil {
		return out, err
	}
	s.waitDone = make(chan struct{})
	go func() {
		defer close(s.waitDone)
		reason, _ := s.node.backend.QualificationWait(s.ctx, r.Authorization.Binding)
		_, _ = s.node.manager.Stop(context.WithoutCancel(s.ctx), id, reason)
	}()
	return out, nil
}
func (s *qualificationSession) status(ctx context.Context) (QualificationStatus, error) {
	r, ok := s.node.manager.Record(s.spec.Binding.RunID)
	out := QualificationStatus{Protocol: s.statusProtocol(), Purpose: s.purpose(), Record: r}
	if !ok {
		return out, errors.New("the fixed fixture record is absent")
	}
	if r.State == "stopped" {
		if len(r.Evidence) == 0 {
			return out, errors.New("the fixed fixture stop evidence is absent")
		}
		t, err := s.node.backend.Terminal(ctx, r.Binding, r.Evidence[len(r.Evidence)-1].Digest)
		if err != nil {
			return out, err
		}
		out.Terminal = &t
	}
	return out, nil
}
func (s *qualificationSession) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" || r.URL.Host != "fixture" && r.URL.Host != "" {
		http.Error(w, "fixture_route_rejected", 400)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Method == http.MethodGet && r.URL.Path == "/fixture/status" {
		if r.ContentLength > 0 {
			http.Error(w, "fixture_body_rejected", 400)
			return
		}
		out, err := s.status(r.Context())
		s.reply(w, out, err)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "fixture_method_rejected", 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	defer r.Body.Close()
	var out any
	var err error
	switch r.URL.Path {
	case "/fixture/prepare":
		var empty struct{}
		err = lifecycle.DecodeTransport(r.Body, &empty)
		if err == nil {
			out, err = s.prepare(r.Context())
		}
	case "/fixture/start":
		var request QualificationRunRequest
		err = lifecycle.DecodeTransport(r.Body, &request)
		if err == nil {
			out, err = s.start(r.Context(), request)
		}
	case "/fixture/stop":
		var request QualificationStopRequest
		err = lifecycle.DecodeTransport(r.Body, &request)
		if err == nil && (request.Protocol != s.stopProtocol() || (request.Reason != "client-stop" && request.Reason != "cancelled")) {
			err = errors.New("the fixed fixture stop cause differs")
		}
		if err == nil {
			_, err = s.node.manager.Stop(r.Context(), s.spec.Binding.RunID, request.Reason)
		}
		if err == nil {
			out, err = s.status(r.Context())
		}
	default:
		http.Error(w, "fixture_route_rejected", 404)
		return
	}
	s.reply(w, out, err)
}
func (*qualificationSession) reply(w http.ResponseWriter, value any, err error) {
	if err != nil {
		cause := err.Error()
		if len(cause) > 512 {
			cause = cause[:512]
		}
		http.Error(w, "fixture_operation_rejected: "+cause, 409)
		return
	}
	var raw bytes.Buffer
	if err = json.NewEncoder(&raw).Encode(value); err != nil {
		http.Error(w, "fixture_encoding_rejected", 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw.Bytes())
}

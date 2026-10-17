// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeaudit"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"reflect"
	"sync"
	"time"
)

type qualificationAuthority struct {
	sources *Sources
	spec    lifecycle.QualificationFixtureSpec
	http    *http.Client
	conn    net.Conn
	purpose string
}

func newQualificationAuthority(conn net.Conn, s *Sources, spec lifecycle.QualificationFixtureSpec) *qualificationAuthority {
	return newQualificationAuthorityPurpose(conn, s, spec, lifecycle.QualificationFixturePurpose)
}

func newQualificationAuthorityPurpose(conn net.Conn, s *Sources, spec lifecycle.QualificationFixtureSpec, purpose string) *qualificationAuthority {
	var mu sync.Mutex
	used := false
	t := &http.Transport{Proxy: nil, MaxConnsPerHost: 1, MaxIdleConns: 1, ResponseHeaderTimeout: time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			mu.Lock()
			defer mu.Unlock()
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if used {
				return nil, errors.New("the fixed authority descriptor cannot reconnect")
			}
			used = true
			return conn, nil
		}}
	return &qualificationAuthority{sources: s, spec: spec, conn: conn, purpose: purpose, http: &http.Client{Transport: t, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("the fixed authority cannot redirect") }}}
}
func (a *qualificationAuthority) Close() { a.http.CloseIdleConnections(); _ = a.conn.Close() }
func (a *qualificationAuthority) request(ctx context.Context, path string, value, out any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) > 256<<20 {
		return errors.New("the fixed authority request exceeds its bound")
	}
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://fixture"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	r.Header.Set("Content-Type", "application/json")
	response, err := a.http.Do(r)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return errors.New("the fixed authority rejected its request")
	}
	return readQualificationReply(response.Body, out)
}
func (a *qualificationAuthority) State(ctx context.Context, id string) (jobgrant.RevocationState, error) {
	if id != a.spec.Binding.GrantID {
		return jobgrant.RevocationState{}, errors.New("the fixed authority grant differs")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var out QualificationStateResponse
	if err := a.request(ctx, "/fixture/state", QualificationStateRequest{Protocol: QualificationStateProtocol, GrantID: id}, &out); err != nil {
		return jobgrant.RevocationState{}, err
	}
	if out.Protocol != QualificationStateProtocol || out.GrantID != id || !out.Known && out.Revoked {
		return jobgrant.RevocationState{}, errors.New("the fixed authority state differs")
	}
	return jobgrant.RevocationState{Known: out.Known, Revoked: out.Revoked}, nil
}
func (a *qualificationAuthority) Countersign(ctx context.Context, b jobaudit.Bundle) (jobaudit.AuthorityReceipt, error) {
	var out jobaudit.AuthorityReceipt
	expected := a.spec.Binding
	expected.CgroupID = b.Header.Binding.CgroupID
	if b.Seal == nil || b.Grant == nil || b.Authority != nil || b.Header.FixturePurpose != a.purpose || !reflect.DeepEqual(expected, b.Header.Binding) {
		return out, errors.New("the fixed authority bundle scope differs")
	}
	if err := a.request(ctx, "/fixture/receipt", b, &out); err != nil {
		return out, err
	}
	document, err := a.sources.Resolve(ctx, b.Header.DocumentDigest)
	if err != nil {
		return out, err
	}
	b.Authority = &out
	trust := jobaudit.Trust{NodeKeys: a.sources.NodeKeys, AuthorityKeys: a.sources.AuthorityKeys, Registry: nodecontrol.Registry(nodeaudit.Registry(), expected), Document: document}
	if verdict := jobaudit.VerifyOffline(b, trust); verdict.State != "VALID_COMPLETE" {
		return jobaudit.AuthorityReceipt{}, errors.New("the fixed authority receipt or raw audit differs")
	}
	return out, nil
}

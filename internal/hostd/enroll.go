// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// Enroll binds this host's key to a target with a one-time token and pins the
// service job key. The token is used once and never stored or logged.
func Enroll(ctx context.Context, stateDir string, cfg Config, service Service, token, hostname string, caps []string,
	now func() time.Time, random io.Reader) (Identity, error) {
	var id Identity
	if !hostproto.TokenPattern.MatchString(token) {
		return id, errors.New("hostd: the enrollment token format is invalid (agtenr_ and 43 characters)")
	}
	origin, err := ServiceOrigin(cfg.ServiceURL, cfg.AllowLoopbackHTTP)
	if err != nil {
		return id, err
	}
	keys, err := loadOrCreateKeys(stateDir, random)
	if err != nil {
		return id, err
	}
	nonce, err := newNonce(random)
	if err != nil {
		return id, err
	}
	public := keys.Signing.Public().(ed25519.PublicKey)
	request := hostproto.EnrollRequest{Token: token, PublicKey: hostproto.EncodeKey(public),
		EncryptionKey: hostproto.EncodeKey(keys.Encryption.PublicKey().Bytes()), Hostname: hostname,
		Capabilities: caps, AgentVersion: Version, Nonce: nonce, TimestampMS: now().UnixMilli()}
	if err = request.Check(now()); err != nil {
		return id, err
	}
	env, err := hostproto.Seal(hostproto.DomainEnroll, keys.Signing, request)
	if err != nil {
		return id, err
	}
	callCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	response, err := service.Enroll(callCtx, env)
	if err != nil {
		return id, errors.New(strings.ReplaceAll(err.Error(), token, "[token]"))
	}
	if err = hostproto.VerifyEnrollResponse(token, response); err != nil {
		return id, err
	}
	if response.HostKeyID != hostproto.KeyID(public) {
		return id, errors.New("hostd: the service enrolled a different host key")
	}
	id = Identity{ServiceURL: origin, TargetID: response.TargetID, TargetName: response.TargetName,
		HostKeyID: response.HostKeyID, JobKey: response.JobKey, JobKeyID: response.JobKeyID,
		PollSeconds: response.PollIntervalSeconds, EnrolledAtMS: now().UnixMilli()}
	if err = saveIdentity(stateDir, id); err != nil {
		return id, fmt.Errorf("hostd: enrolled but the identity was not saved: %w", err)
	}
	return id, nil
}

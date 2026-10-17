// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"crypto/ed25519"
	"errors"
	"time"
)

type signedPreparations struct {
	keys   map[string]ed25519.PublicKey
	clock  jobgrant.Clock
	maxAge time.Duration
}

func NewPreparations(keys map[string]ed25519.PublicKey, clock jobgrant.Clock, maxAge time.Duration) (Preparations, error) {
	if clock == nil || maxAge < time.Second || maxAge > 15*time.Second || maxAge%time.Second != 0 || len(keys) == 0 {
		return nil, errors.New("authority_preparation_trust_invalid")
	}
	copy, e := copyClientKeys(keys)
	if e != nil {
		return nil, e
	}
	return &signedPreparations{copy, clock, maxAge}, nil
}
func (v *signedPreparations) Verify(ctx context.Context, p lifecycle.PrepareResponse) (NodeTime, error) {
	if e := ctx.Err(); e != nil {
		return NodeTime{}, e
	}
	wall, _, e := v.clock.Now()
	if e != nil {
		return NodeTime{}, errors.New("authority_clock_unavailable")
	}
	sample, e := lifecycle.VerifyPrepared(p, v.keys, p.Binding, wall.Unix(), v.maxAge)
	if e != nil {
		return NodeTime{}, errors.New("authority_node_preparation_invalid")
	}
	return NodeTime{time.Unix(sample.Wall, 0), sample.MonoNS}, nil
}

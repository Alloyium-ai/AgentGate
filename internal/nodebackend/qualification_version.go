// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"context"
	"errors"

	"alloyium.local/kernel-poc/internal/lifecycle"
)

// NewQualificationVersionBackend accepts only the opaque pinned-version permit.
// It exposes no normal admission operations and keeps every shared guard.
func NewQualificationVersionBackend(ctx context.Context, c Config, p *lifecycle.QualificationFixturePermit) (*Backend, error) {
	if p == nil || p.Purpose() != lifecycle.QualificationVersionPurpose || c.Credentials != nil || c.Resolver != nil {
		return nil, errors.New("the native version backend requires its isolated permit and no credential or resolver source")
	}
	return newQualificationBackend(ctx, c, p)
}

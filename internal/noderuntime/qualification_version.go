// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"context"
	"errors"
	"path/filepath"

	"alloyium.local/kernel-poc/internal/lifecycle"
)

func (n *Node) qualificationVersionPermit(ctx context.Context, spec lifecycle.QualificationVersionSpec) (*lifecycle.QualificationFixturePermit, error) {
	if err := n.validateQualificationBinding(ctx, lifecycle.QualificationFixtureSpec(spec)); err != nil {
		return nil, err
	}
	permit, err := lifecycle.NewQualificationVersionPermit(ctx, spec)
	if err != nil {
		return nil, err
	}
	if err = n.sources.VerifyRuntime(ctx, spec.Binding, spec.Manifest); err != nil {
		return nil, err
	}
	return permit, nil
}

func validateQualificationVersionNodePaths(c Config, spec lifecycle.QualificationVersionSpec) error {
	if _, err := lifecycle.QualificationVersionScopeDigest(spec); err != nil {
		return err
	}
	if c.ArtifactRoot != filepath.Join(spec.OwnedRoot, "streams") || c.Credentials != nil || c.Resolver != nil {
		return errors.New("the native version stream, credential or resolver scope differs")
	}
	return validateQualificationOwnedPaths(c, spec.OwnedRoot)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"crypto/ed25519"
	"errors"
	"reflect"

	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/qualification"
)

func verifyServiceLifecycleAudit(request qualification.Request, recipe serviceLifecycleRecipe, raw []byte, nodes, authorities map[string]ed25519.PublicKey) ([]qualification.Coverage, error) {
	if err := verifyServiceLifecycleRecipe(request, recipe); err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 8<<20 || uniqueJSON(raw) != nil {
		return nil, errors.New("the lifecycle audit encoding differs")
	}
	bundle, err := jobauthority.DecodeAuditBundle(raw)
	if err != nil {
		return nil, err
	}
	expected := recipe.Spec.Binding
	expected.CgroupID = bundle.Header.Binding.CgroupID
	scope, err := lifecycle.QualificationFixtureScopeDigest(recipe.Spec)
	if err != nil {
		return nil, err
	}
	if expected.CgroupID == 0 || !reflect.DeepEqual(expected, bundle.Header.Binding) || bundle.Header.FixturePurpose != lifecycle.QualificationFixturePurpose || bundle.Header.QualificationDigest != scope {
		return nil, errors.New("the lifecycle audit fixture binding or purpose differs")
	}
	// Only this local audit input uses the already validated executed root.
	// The outer candidate request and its artifact map remain unchanged.
	executed := request
	executed.Binding.ArtifactDigests = recipe.Spec.Binding.ArtifactDigests
	return VerifyServiceFixtureAudit(executed, recipe.Document, expected, raw, nodes, authorities)
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"errors"
	"reflect"
	"time"

	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
)

// The caller derives NodeTime only after it verifies the separate node-signed
// fixture preparation response. Authority host monotonic time is never a substitute.
func (a *serviceLifecycleAuthority) issue(ctx context.Context, binding lifecycle.Binding, header jobaudit.Header, sample jobauthority.NodeTime) (lifecycle.Authorization, error) {
	var zero lifecycle.Authorization
	if a.checkBinding(binding) != nil || !reflect.DeepEqual(header.Binding, binding) || header.FixturePurpose != lifecycle.QualificationFixturePurpose || header.DocumentDigest != binding.PolicyDigest || header.QualificationDigest != a.scope || !reflect.DeepEqual(header.RequiredCapabilities, a.recipe.Document.RequiredCapabilities) {
		return zero, errors.New("the lifecycle grant differs from the node fixture preparation")
	}
	if sample.MonoNS == 0 || sample.MonoNS < header.CreatedMonoNS || sample.MonoNS >= binding.DeadlineNS || sample.Wall.IsZero() || sample.Wall.Unix() <= 0 || sample.Wall.After(time.Now().Add(time.Second)) || time.Since(sample.Wall) > 3*time.Second {
		return zero, errors.New("the signed lifecycle preparation clock sample is unavailable or stale")
	}
	headerDigest, err := jobaudit.HeaderDigest(header)
	if err != nil {
		return zero, err
	}
	claims := jobgrant.Claims{Binding: binding, DocumentDigest: binding.PolicyDigest, RequiredCapabilities: a.recipe.Document.RequiredCapabilities, QualificationDigest: a.scope, AuditHeaderDigest: headerDigest, IssuedAt: sample.Wall.Unix(), NotBefore: sample.Wall.Unix(), ExpiresAt: sample.Wall.Unix() + 5, IssuedMonoNS: sample.MonoNS, DeadlineNS: binding.DeadlineNS}
	envelope, err := jobgrant.Sign(serviceLifecycleAuthorityID, serviceLifecycleAuthorityKeyID, a.key, claims, a.recipe.Document)
	if err != nil {
		return zero, err
	}
	grant, err := jobgrant.Encode(envelope)
	if err != nil {
		return zero, err
	}
	authorization := lifecycle.Authorization{Binding: binding, Grant: grant, Document: append([]byte{}, a.recipe.Spec.Document...), RequiredCapabilities: append([]string{}, a.recipe.Document.RequiredCapabilities...)}
	if err = a.store.SaveGrant(ctx, authorization); err != nil {
		return zero, err
	}
	stored, revoked, err := a.store.Grant(ctx, binding.GrantID)
	if err != nil || revoked || !reflect.DeepEqual(stored, authorization) {
		return zero, errors.New("the durable lifecycle grant readback differs")
	}
	a.record(serviceLifecycleAuthorityCall{Operation: "issue", GrantID: binding.GrantID, Known: true, Authorization: &stored, MonoNS: serviceMono()})
	return stored, nil
}

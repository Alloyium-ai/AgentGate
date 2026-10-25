// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"testing"

	"alloyium.local/kernel-poc/internal/lifecycle"
)

func TestLifecycleFixtureCannotCreditDifferentExecutedPolicy(t *testing.T) {
	request := adapterRequest(t)
	canonical, err := request.Document.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	recipe := serviceLifecycleRecipe{Document: request.Document, Spec: lifecycle.QualificationFixtureSpec{
		Binding:         lifecycle.Binding{PolicyDigest: request.Binding.PolicyDigest},
		CandidateDigest: request.Binding.PolicyDigest,
		Document:        canonical,
	}}
	if !serviceLifecycleExecutedCandidate(request, recipe) {
		t.Fatal("the identical executed document was rejected")
	}
	recipe.Spec.Document = []byte(`{"different":"document"}`)
	if serviceLifecycleExecutedCandidate(request, recipe) {
		t.Fatal("the signed scene document differed from the candidate")
	}
	recipe.Spec.Document = canonical
	recipe.Spec.Binding.PolicyDigest = "different"
	if serviceLifecycleExecutedCandidate(request, recipe) {
		t.Fatal("the executed grant was bound to another policy")
	}
	recipe.Spec.Binding.PolicyDigest = request.Binding.PolicyDigest
	changed := request.Document
	lifetime := *request.Document.Lifecycle
	lifetime.DurationSeconds++
	changed.Lifecycle = &lifetime
	recipe.Document = changed
	if serviceLifecycleExecutedCandidate(request, recipe) {
		t.Fatal("the fixed scene silently gained candidate coverage")
	}
}

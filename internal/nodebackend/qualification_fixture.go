// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"errors"
	"reflect"
)

// NewQualificationFixtureBackend cannot supply normal admission operations.
// The permit requires the actual measured node and one static fixed worker.
func NewQualificationFixtureBackend(ctx context.Context, c Config, p *lifecycle.QualificationFixturePermit) (*Backend, error) {
	if p == nil || p.Purpose() != lifecycle.QualificationFixturePurpose {
		return nil, errors.New("the fixed worker backend requires its own permit purpose")
	}
	return newQualificationBackend(ctx, c, p)
}

func newQualificationBackend(ctx context.Context, c Config, p *lifecycle.QualificationFixturePermit) (*Backend, error) {
	if p == nil || p.Digest() == "" || c.Qualification == nil || c.MaxRuns != 1 || c.Limits.MemoryBytes > 256<<20 || c.Limits.PIDs > 16 || c.Limits.CPUQuotaUS > 100000 {
		return nil, errors.New("the fixed qualification permit is absent")
	}
	verifier, ok := c.Verifier.(*jobgrant.Verifier)
	if !ok || verifier.QualificationFixtureDigest() != p.Digest() {
		return nil, errors.New("the fixture backend requires its signature verifier")
	}
	snapshot, err := c.Qualification.Current(ctx, p.InitialBinding())
	if err != nil {
		return nil, err
	}
	if snapshot.Target.Digest() != p.TargetDigest() || snapshot.CompilerDigest != c.CompilerDigest || !reflect.DeepEqual(snapshot.ArtifactDigests, c.ArtifactDigests) {
		return nil, errors.New("the fixed fixture target differs")
	}
	for _, cap := range snapshot.Target.Report().Capabilities {
		if cap.State == "enforced" {
			return nil, errors.New("the fixture backend cannot borrow an enforced report")
		}
	}
	backend, err := New(c)
	if err != nil {
		return nil, err
	}
	backend.fixture = p
	return backend, nil
}
func (b *Backend) QualificationFixtureDigest() string {
	if b == nil || b.fixture == nil {
		return ""
	}
	return b.fixture.Digest()
}

func (b *Backend) QualificationPreparation(ctx context.Context, runID string) (enforcement.QuarantineReadback, []byte, string, error) {
	var zero enforcement.QuarantineReadback
	if b.fixture == nil {
		return zero, nil, "", errors.New("normal backends have no fixed qualification preparation")
	}
	if err := ctx.Err(); err != nil {
		return zero, nil, "", err
	}
	r, err := b.get(runID)
	if err != nil {
		return zero, nil, "", err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.phase != "prepared" || b.fixture.CheckBinding(r.binding, false) != nil {
		return zero, nil, "", errors.New("the fixed qualification run is not prepared")
	}
	raw, err := r.group.ReadQuarantine()
	if err != nil {
		return zero, nil, "", err
	}
	return raw, append([]byte{}, r.headerBytes...), r.headerDigest, nil
}

// QualificationWait uses the normal monitor and its exact terminal classifier.
func (b *Backend) QualificationWait(ctx context.Context, binding lifecycle.Binding) (string, error) {
	if b.fixture == nil || b.fixture.CheckBinding(binding, false) != nil {
		return "runtime-monitor-failed", errors.New("the fixed qualification wait binding differs")
	}
	_, err := b.Wait(ctx, binding)
	r, _ := b.get(binding.RunID)
	return stopReasonAfterWait(ctx.Err(), err, r), err
}

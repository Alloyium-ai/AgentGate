// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"context"
	"errors"
)

func (b *Backend) verifyRuntime(ctx context.Context, binding lifecycle.Binding, m lifecycle.Manifest) error {
	if b.fixture != nil {
		if err := b.fixture.CheckBinding(binding, false); err != nil {
			return err
		}
		if err := b.fixture.CheckManifest(m); err != nil {
			return err
		}
	}
	if b.config.Runtimes != nil {
		return b.config.Runtimes.VerifyRuntime(ctx, binding, m)
	}
	return errors.New("the runtime has no enrolled file measurement provider")
}

func (b *Backend) measureRuntime(ctx context.Context, binding lifecycle.Binding, m lifecycle.Manifest) (runtimeclosure.Measurement, error) {
	provider, ok := b.config.Runtimes.(interface {
		MeasureRuntime(context.Context, lifecycle.Binding, lifecycle.Manifest) (runtimeclosure.Measurement, error)
	})
	if !ok {
		return runtimeclosure.Measurement{}, errors.New("the runtime file measurement provider is absent")
	}
	measurement, err := provider.MeasureRuntime(ctx, binding, m)
	if err != nil {
		return measurement, err
	}
	set, err := runtimeclosure.New(measurement.Files)
	total := int64(0)
	for _, file := range measurement.Files {
		total += file.Bytes
	}
	if err != nil || measurement.Protocol != runtimeclosure.Version || measurement.TotalBytes != total || measurement.Digest != set.Digest() || measurement.Digest != binding.ArtifactDigests["runtime."+m.AgentKind+".files"] {
		return runtimeclosure.Measurement{}, errors.New("the staged runtime file measurement differs")
	}
	return measurement, nil
}

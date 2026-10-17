// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodecontrol

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"errors"
)

// RuntimeFiles binds the measured set to the exact signed launch manifest.
// It records custody and creates no file or syscall allowance.
type RuntimeFiles struct {
	Manifest    lifecycle.Manifest         `json:"manifest"`
	Measurement runtimeclosure.Measurement `json:"measurement"`
}

func (p RuntimeFiles) Validate(binding lifecycle.Binding) error {
	md, err := p.Manifest.Digest()
	if err != nil || p.Manifest.Validate() != nil || md != binding.JobDigest {
		return errors.New("the runtime file proof manifest differs")
	}
	set, err := runtimeclosure.New(p.Measurement.Files)
	if err != nil {
		return err
	}
	var total int64
	for _, file := range p.Measurement.Files {
		total += file.Bytes
	}
	if p.Measurement.Protocol != runtimeclosure.Version || p.Measurement.Digest != set.Digest() || p.Measurement.Digest != binding.ArtifactDigests["runtime."+p.Manifest.AgentKind+".files"] || p.Measurement.TotalBytes != total {
		return errors.New("the runtime file proof measurement differs")
	}
	return nil
}

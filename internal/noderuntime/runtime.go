// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
)

func (s *Sources) VerifyRuntime(ctx context.Context, b lifecycle.Binding, m lifecycle.Manifest) error {
	_, err := s.MeasureRuntime(ctx, b, m)
	return err
}
func (s *Sources) MeasureRuntime(ctx context.Context, b lifecycle.Binding, m lifecycle.Manifest) (runtimeclosure.Measurement, error) {
	var zero runtimeclosure.Measurement
	enrolled, err := s.Enrollment(ctx, b.AgentID)
	if err != nil {
		return zero, err
	}
	r, ok := enrolled.Runtimes[m.AgentKind]
	if !ok || r.Version != m.RuntimeVersion || r.Executable != m.Executable || r.ExecutableDigest != m.ExecutableDigest || r.ImageDigest != m.ImageDigest {
		return zero, errors.New("the staged runtime differs from its exact enrollment")
	}
	if err = jobartifacts.VerifyExecutable(r.Executable, r.ExecutableDigest); err != nil {
		return zero, err
	}
	if !nodeapi.RuntimeFilesMatch(r, m, b) {
		return zero, errors.New("the exact runtime file binding differs")
	}
	set, err := runtimeclosure.New(r.Files)
	if err != nil {
		return zero, err
	}
	if err = verifyRuntimeInterpreter(r.Executable, set.Files()); err != nil {
		return zero, err
	}
	if m.AgentKind != "pi" {
		return set.Verify(ctx)
	}
	if len(r.ArgumentsPrefix) == 0 || r.ArgumentsPrefix[0] != r.EntryScript || !slices.Equal(m.Arguments, r.ArgumentsPrefix) || !filepath.IsAbs(r.PackageRoot) || filepath.Clean(r.PackageRoot) != r.PackageRoot || !strings.HasPrefix(r.EntryScript, r.PackageRoot+"/") || b.ArtifactDigests["runtime.pi.entry"] != r.EntryScriptDigest || b.ArtifactDigests["runtime.pi.package"] != r.PackageDigest {
		return zero, errors.New("the Pi entry script, package or complete argv differs")
	}
	for _, name := range []string{"NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"} {
		if m.Environment[name] != "" {
			return zero, errors.New("the qualified Pi runtime rejects a dynamic loader environment")
		}
	}
	if err = jobartifacts.VerifyDataFile(r.EntryScript, r.EntryScriptDigest, jobartifacts.MaxTreeFileBytes); err != nil {
		return zero, err
	}
	if err = jobartifacts.VerifyTree(ctx, r.PackageRoot, r.PackageDigest); err != nil {
		return zero, err
	}
	return set.Verify(ctx)
}

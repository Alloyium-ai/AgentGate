// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
)

// RuntimeFilesMatch binds exact file metadata. It grants no file permission.
func RuntimeFilesMatch(r RuntimeArtifact, m lifecycle.Manifest, b lifecycle.Binding) bool {
	set, err := runtimeclosure.New(r.Files)
	if err != nil || set.Digest() != r.FilesDigest || b.ArtifactDigests["runtime."+m.AgentKind+".files"] != r.FilesDigest {
		return false
	}
	for _, key := range []string{"NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"} {
		if m.Environment[key] != "" {
			return false
		}
	}
	return true
}

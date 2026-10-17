// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"path/filepath"
	"slices"
	"strings"
)

func piRuntimeMatches(runtime RuntimeArtifact, manifest lifecycle.Manifest, binding lifecycle.Binding) bool {
	root, entry := runtime.PackageRoot, runtime.EntryScript
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" || root == "/tmp" || strings.HasPrefix(root, "/tmp/") || !filepath.IsAbs(entry) || filepath.Clean(entry) != entry || !strings.HasPrefix(entry, root+"/") || strings.ContainsRune(root+entry, 0) {
		return false
	}
	if !digestPattern.MatchString(runtime.EntryScriptDigest) || !digestPattern.MatchString(runtime.PackageDigest) || binding.ArtifactDigests["runtime.pi.entry"] != runtime.EntryScriptDigest || binding.ArtifactDigests["runtime.pi.package"] != runtime.PackageDigest {
		return false
	}
	for _, name := range []string{"NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"} {
		if manifest.Environment[name] != "" {
			return false
		}
	}
	prefix := runtime.ArgumentsPrefix
	// The controlled one-shot path fixes every flag. Extra flags can load code.
	// Node flags before the script, including -e/--eval, cannot claim this Pi runtime.
	return len(prefix) > 0 && len(prefix) <= 128 && prefix[0] == entry && slices.Equal(prefix, manifest.Arguments)
}

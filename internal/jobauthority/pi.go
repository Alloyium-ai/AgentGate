// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobauthority

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"path/filepath"
	"reflect"
	"strings"
)

var piLoaderEnvironment = []string{"NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH"}

func validPiPins(r RuntimePin) bool {
	if !canonicalPiPath(r.PackageRoot) || !canonicalPiPath(r.EntryScript) || !digestPattern.MatchString(r.EntryScriptDigest) || !digestPattern.MatchString(r.PackageDigest) || len(r.ArgumentsPrefix) == 0 || r.ArgumentsPrefix[0] != r.EntryScript {
		return false
	}
	relative, err := filepath.Rel(r.PackageRoot, r.EntryScript)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	for _, arg := range r.ArgumentsPrefix {
		if strings.ContainsRune(arg, 0) {
			return false
		}
	}
	return true
}
func canonicalPiPath(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && path != "/tmp" && !strings.HasPrefix(path, "/tmp/") && !strings.ContainsRune(path, 0)
}
func piRuntimeMatches(r RuntimePin, m lifecycle.Manifest, b lifecycle.Binding) bool {
	if !validPiPins(r) || !reflect.DeepEqual(r.ArgumentsPrefix, m.Arguments) || b.ArtifactDigests["runtime.pi.entry"] != r.EntryScriptDigest || b.ArtifactDigests["runtime.pi.package"] != r.PackageDigest {
		return false
	}
	for _, key := range piLoaderEnvironment {
		if m.Environment[key] != "" {
			return false
		}
	}
	return true
}

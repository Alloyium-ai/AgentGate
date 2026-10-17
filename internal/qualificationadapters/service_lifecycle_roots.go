// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"encoding/hex"
	"errors"
	"reflect"
	"regexp"
	"strings"

	"alloyium.local/kernel-poc/internal/domainstore"
)

var serviceLifecyclePrefix = regexp.MustCompile(`^(?:agj-|alloyium-poc-job-)[a-f0-9]{16}-$`)

func validServiceLifecycleRoot(proof domainstore.RootProof) bool {
	raw, err := hex.DecodeString(proof.QualificationReceiptDigest)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == proof.QualificationReceiptDigest && proof.BootID != "" && proof.MountID != 0 && proof.Device != 0 && proof.RootInode != 0 && proof.MountRoot == "/" && proof.MountPoint == domainstore.RootPath && proof.NamespaceDevice != 0 && proof.NamespaceInode != 0 && proof.NamespaceDevice == proof.InitNamespaceDevice && proof.NamespaceInode == proof.InitNamespaceInode && proof.JobDepth == 1 && serviceLifecyclePrefix.MatchString(proof.OwnedPrefix)
}
func verifyServiceLifecycleRoots(candidate, fixture domainstore.RootProof) error {
	if !validServiceLifecycleRoot(candidate) || !validServiceLifecycleRoot(fixture) || strings.HasPrefix(candidate.OwnedPrefix, fixture.OwnedPrefix) || strings.HasPrefix(fixture.OwnedPrefix, candidate.OwnedPrefix) {
		return errors.New("the candidate and fixture root prefixes must be qualified and disjoint")
	}
	normalized := fixture
	normalized.OwnedPrefix = candidate.OwnedPrefix
	if !reflect.DeepEqual(normalized, candidate) {
		return errors.New("the fixture root changes more than the owned prefix")
	}
	return nil
}
func verifyServiceLifecycleArtifacts(candidate, fixture map[string]string, candidateRoot, fixtureRoot domainstore.RootProof) error {
	if err := verifyServiceLifecycleRoots(candidateRoot, fixtureRoot); err != nil {
		return err
	}
	if len(candidate) != len(fixture) || candidate["domain-root"] != candidateRoot.Digest() || fixture["domain-root"] != fixtureRoot.Digest() {
		return errors.New("the lifecycle root artifact bindings differ")
	}
	for name, digest := range candidate {
		if name != "domain-root" && fixture[name] != digest {
			return errors.New("the lifecycle fixture replaces a candidate artifact")
		}
	}
	return nil
}

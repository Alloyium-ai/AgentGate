// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"alloyium.local/kernel-poc/internal/domainstore"
	"testing"
)

func serviceLifecycleRootPair() (domainstore.RootProof, domainstore.RootProof) {
	candidate := domainstore.RootProof{BootID: "unit-boot", MountID: 1, Device: 2, RootInode: 3, MountRoot: "/", MountPoint: domainstore.RootPath, NamespaceDevice: 4, NamespaceInode: 5, InitNamespaceDevice: 4, InitNamespaceInode: 5, JobDepth: 1, OwnedPrefix: "alloyium-poc-job-0123456789abcdef-", QualificationReceiptDigest: digestJSON("root")}
	fixture := candidate
	fixture.OwnedPrefix = "alloyium-poc-job-fedcba9876543210-"
	return candidate, fixture
}
func TestLifecycleRootsRequireDisjointNamespacesOnTheSameMeasuredRoot(t *testing.T) {
	candidate, fixture := serviceLifecycleRootPair()
	if err := verifyServiceLifecycleRoots(candidate, fixture); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*domainstore.RootProof){
		"same-prefix": func(p *domainstore.RootProof) { p.OwnedPrefix = candidate.OwnedPrefix },
		"boot":        func(p *domainstore.RootProof) { p.BootID = "other-boot" },
		"mount":       func(p *domainstore.RootProof) { p.MountID++ },
		"device":      func(p *domainstore.RootProof) { p.Device++ },
		"inode":       func(p *domainstore.RootProof) { p.RootInode++ },
		"namespace":   func(p *domainstore.RootProof) { p.NamespaceInode++; p.InitNamespaceInode++ },
		"depth":       func(p *domainstore.RootProof) { p.JobDepth++ },
		"receipt":     func(p *domainstore.RootProof) { p.QualificationReceiptDigest = digestJSON("other") },
	} {
		t.Run(name, func(t *testing.T) {
			changed := fixture
			change(&changed)
			if verifyServiceLifecycleRoots(candidate, changed) == nil {
				t.Fatal("a fixture reused or changed the candidate root")
			}
		})
	}
	artifacts := map[string]string{"domain-root": candidate.Digest(), "node": digestJSON("node"), "runtime.codex.files": digestJSON("closure")}
	executed := map[string]string{"domain-root": fixture.Digest(), "node": artifacts["node"], "runtime.codex.files": artifacts["runtime.codex.files"]}
	if err := verifyServiceLifecycleArtifacts(artifacts, executed, candidate, fixture); err != nil {
		t.Fatal(err)
	}
	executed["node"] = digestJSON("changed")
	if verifyServiceLifecycleArtifacts(artifacts, executed, candidate, fixture) == nil {
		t.Fatal("the fixture changed a code artifact")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
)

func serviceLifecycleRecipeFixture(t *testing.T) serviceLifecycleRecipe {
	t.Helper()
	if os.Geteuid() != 0 || os.Getenv("AGENTGATE_TEST_SCRATCH") == "" {
		t.Skip("the isolated root container is required")
	}
	root, err := os.MkdirTemp("/var/lib", "kernel-poc-qualification-unit-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
	})
	if err = os.Mkdir(filepath.Join(root, "streams"), 0700); err != nil {
		t.Fatal(err)
	}
	request := adapterRequest(t)
	request.Binding.NodeID = "qualification-unit-node"
	request.Binding.BootID = "qualification-unit-boot"
	request.Binding.SourceRevision = "0123456789abcdef0123456789abcdef01234567"
	proof := domainstore.RootProof{BootID: request.Binding.BootID, OwnedPrefix: "alloyium-poc-job-0123456789abcdef-", MountID: 1, Device: 2, RootInode: 3, MountRoot: "/", MountPoint: domainstore.RootPath, NamespaceDevice: 4, NamespaceInode: 5, InitNamespaceDevice: 4, InitNamespaceInode: 5, JobDepth: 1, QualificationReceiptDigest: digestJSON("root-receipt")}
	fixtureProof := proof
	fixtureProof.OwnedPrefix = "alloyium-poc-job-fedcba9876543210-"
	files, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"qualification-lifecycle-worker", "node", "watchdog", "authority", "held-helper", "exec-broker", "files", "peers", "sockets", "custody", "process", "syscalls"} {
		request.Binding.ArtifactDigests[name] = digestJSON(name)
	}
	request.Binding.ArtifactDigests["runtime.codex.files"] = files.Digest()
	request.Binding.ArtifactDigests["domain-root"] = proof.Digest()
	public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	layout := serviceLifecycleLayout{OwnedRoot: root, ArtifactRoot: filepath.Join(root, "streams"), Worker: "/var/lib/kernel-poc-fixture-artifacts/qualification-lifecycle-worker", ImageDigest: "sha256:" + digestJSON("image"), TargetDigest: digestJSON("target"), AgentID: "qualification-unit-agent", AgentKey: base64.RawURLEncoding.EncodeToString(public), RunID: "qualification-unit-run", GrantID: "qualification-unit-grant", Generation: 1, DeadlineNS: serviceMono() + uint64(20*time.Second), CandidateRootProof: proof, RootProof: fixtureProof, Input: 'T'}
	originalArtifacts := serviceJSON(request.Binding.ArtifactDigests)
	recipe, err := newServiceLifecycleRecipe(request, layout)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyServiceLifecycleRecipe(request, recipe); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(originalArtifacts, serviceJSON(request.Binding.ArtifactDigests)) {
		t.Fatal("the recipe changed the outer candidate artifact map")
	}
	if err := verifyServiceLifecycleArtifacts(request.Binding.ArtifactDigests, recipe.Spec.Binding.ArtifactDigests, proof, fixtureProof); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*serviceLifecycleLayout){func(l *serviceLifecycleLayout) { l.Input = 'X' }, func(l *serviceLifecycleLayout) { l.Worker = "/var/lib/other" }, func(l *serviceLifecycleLayout) { l.ArtifactRoot = filepath.Dir(root) }, func(l *serviceLifecycleLayout) { l.RootProof.BootID = "another-boot" }} {
		changed := layout
		change(&changed)
		if _, err := newServiceLifecycleRecipe(request, changed); err == nil {
			t.Fatal("an unbounded fixture recipe passed")
		}
	}
	changed := request
	changed.Binding.ArtifactDigests = map[string]string{}
	for name, value := range request.Binding.ArtifactDigests {
		changed.Binding.ArtifactDigests[name] = value
	}
	changed.Binding.ArtifactDigests["runtime.codex.files"] = digestJSON("nonempty-runtime")
	if _, err := newServiceLifecycleRecipe(changed, layout); err == nil {
		t.Fatal("the fixture replaced an existing runtime closure")
	}
	if recipe.Spec.CandidateDigest == recipe.Spec.Binding.PolicyDigest {
		t.Fatal("the fixture borrowed the candidate policy digest")
	}
	if len(recipe.Document.Network.Rules) != 0 || len(recipe.Document.Sockets.Rules) != 0 || len(recipe.Document.Runtime.Memory.Anonymous) != 0 || len(recipe.Document.Runtime.IPC.Pipes) != 0 || len(*recipe.Document.Runtime.Signals) != 0 {
		t.Fatal("the fixture granted an unrelated right")
	}
	return recipe
}
func TestServiceLifecycleRecipePreservesCandidateMeasurements(t *testing.T) {
	_ = serviceLifecycleRecipeFixture(t)
}

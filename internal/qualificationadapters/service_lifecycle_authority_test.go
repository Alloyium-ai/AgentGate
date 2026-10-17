// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
)

func serviceLifecycleHeader(t *testing.T, recipe serviceLifecycleRecipe) jobaudit.Header {
	t.Helper()
	binding := recipe.Spec.Binding
	binding.CgroupID = 42
	streams := []jobaudit.Stream{}
	for name, format := range jobaudit.ResourceFormats() {
		streams = append(streams, jobaudit.Stream{Name: name, Kind: "resource", Version: format.Version, ArtifactDigest: binding.ArtifactDigests[name]})
	}
	for name, format := range jobaudit.ObservationFormats() {
		streams = append(streams, jobaudit.Stream{Name: name, Kind: "observation", Version: format.Version, ArtifactDigest: binding.ArtifactDigests[name]})
	}
	streams = append(streams, jobaudit.Stream{Name: "node", Kind: "control", Version: nodecontrol.Version, ArtifactDigest: binding.ArtifactDigests["node"]})
	scope, err := lifecycle.QualificationFixtureScopeDigest(recipe.Spec)
	if err != nil {
		t.Fatal(err)
	}
	return jobaudit.Header{Protocol: jobaudit.HeaderProtocol, FixturePurpose: "agentgate.fixed-lifecycle-qualification.v1", Binding: binding, DocumentDigest: binding.PolicyDigest, QualificationDigest: scope, RequiredCapabilities: recipe.Document.RequiredCapabilities, RequiredStreams: streams, CreatedMonoNS: serviceMono()}
}
func TestServiceLifecycleAuthorityUsesDurableGrantAndRevoke(t *testing.T) {
	recipe := serviceLifecycleRecipeFixture(t)
	root := filepath.Join(recipe.Spec.OwnedRoot, "authority")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 1
	node := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	authority, err := newServiceLifecycleAuthority(root, recipe, map[string]ed25519.PublicKey{recipe.Spec.Binding.NodeID + "/one": node})
	if err != nil {
		t.Fatal(err)
	}
	defer authority.close()
	ctx := context.Background()
	state, err := authority.state(ctx, recipe.Spec.Binding.GrantID)
	if err != nil || state.Known {
		t.Fatal(state, err)
	}
	header := serviceLifecycleHeader(t, recipe)
	sample := jobauthority.NodeTime{Wall: time.Now(), MonoNS: serviceMono()}
	authorization, err := authority.issue(ctx, header.Binding, header, sample)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := jobgrant.Decode(authorization.Grant)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = jobgrant.VerifySigned(grant, authority.keys(), recipe.Document); err != nil {
		t.Fatal(err)
	}
	if _, err = authority.issue(ctx, header.Binding, header, sample); err == nil {
		t.Fatal("a duplicate grant replaced durable custody")
	}
	if err = authority.revoke(ctx, header.Binding.GrantID); err != nil {
		t.Fatal(err)
	}
	if err = authority.revoke(ctx, "another-grant"); err == nil {
		t.Fatal("the authority revoked a foreign grant")
	}
	var workers sync.WaitGroup
	for index := 0; index < 8; index++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			state, err := authority.state(ctx, header.Binding.GrantID)
			if err != nil || !state.Known || !state.Revoked {
				t.Error(state, err)
			}
		}()
	}
	workers.Wait()
	calls, err := authority.observations()
	if err != nil || len(calls) != 12 {
		t.Fatal(len(calls), err)
	}
	if err := verifyServiceLifecycleAuthority(recipe, header, authority.public, calls); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func([]serviceLifecycleAuthorityCall){
		"signature": func(c []serviceLifecycleAuthorityCall) { c[1].Authorization.Grant += "x" },
		"owner":     func(c []serviceLifecycleAuthorityCall) { c[1].GrantID = "other" },
		"state":     func(c []serviceLifecycleAuthorityCall) { c[len(c)-1].Revoked = false },
		"clock":     func(c []serviceLifecycleAuthorityCall) { c[1].MonoNS = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			var changed []serviceLifecycleAuthorityCall
			if err := lifecycle.DecodeTransport(bytes.NewReader(serviceJSON(calls)), &changed); err != nil {
				t.Fatal(err)
			}
			change(changed)
			if verifyServiceLifecycleAuthority(recipe, header, authority.public, changed) == nil {
				t.Fatal("a substituted authority record passed")
			}
		})
	}
	if _, err := authority.countersign(ctx, jobaudit.Bundle{Header: header}); err == nil {
		t.Fatal("an absent actual node seal received an authority receipt")
	}
	epoch := authority.store.Epoch()
	if err = authority.close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := jobauthority.OpenStore(filepath.Join(root, "authority.db"), epoch)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	stored, revoked, err := reopened.Grant(ctx, header.Binding.GrantID)
	if err != nil || !revoked || !reflect.DeepEqual(stored, authorization) {
		t.Fatal(revoked, err)
	}
	for _, value := range authority.key {
		if value != 0 {
			t.Fatal("the parent retained its private signer after close")
		}
	}
}

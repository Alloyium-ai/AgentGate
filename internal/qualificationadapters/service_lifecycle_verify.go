// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"reflect"

	"alloyium.local/kernel-poc/internal/childwire"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
)

// This verifier repeats the fixed recipe without reading a removed scratch tree.
// It cannot create a permit, release a workload or return capability coverage.
func verifyServiceLifecycleRecipe(request qualification.Request, recipe serviceLifecycleRecipe) error {
	if err := validateRequest(request); err != nil {
		return err
	}
	spec := recipe.Spec
	if spec.CandidateDigest != request.Binding.PolicyDigest || spec.SourceRevision != request.Binding.SourceRevision || spec.Binding.NodeID != request.Binding.NodeID || spec.Binding.BootID != request.Binding.BootID || spec.Binding.SchemaDigest != request.Binding.SchemaDigest || verifyServiceLifecycleArtifacts(request.Binding.ArtifactDigests, spec.Binding.ArtifactDigests, recipe.CandidateRoot, recipe.FixtureRoot) != nil {
		return errors.New("the lifecycle raw candidate binding differs")
	}
	if _, err := lifecycle.QualificationFixtureScopeDigest(spec); err != nil {
		return err
	}
	directory := filepath.Join(spec.OwnedRoot, "streams", "job-"+digestBytes([]byte(spec.Binding.NodeID+"\n"+spec.Binding.RunID)))
	streams := jobartifacts.Streams{Directory: directory, Paths: childwire.IOPaths{Input: filepath.Join(directory, "input"), Output: filepath.Join(directory, "output"), Error: filepath.Join(directory, "error")}}
	if !reflect.DeepEqual(recipe.Streams, streams) || (len(recipe.Input) != 1 || recipe.Input[0] != 'T' && recipe.Input[0] != 'E') || digestBytes(recipe.Input) != spec.Manifest.InputDigest {
		return errors.New("the lifecycle raw stream paths or fixed input differ")
	}
	expected := serviceLifecycleDocument(spec.Manifest, streams, spec.Binding.ArtifactDigests["held-helper"])
	canonical, err := expected.Canonical()
	if err != nil {
		return err
	}
	supplied, err := recipe.Document.Canonical()
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, spec.Document) || !bytes.Equal(supplied, canonical) {
		return errors.New("the lifecycle raw document differs from the compiled recipe")
	}
	files, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil {
		return err
	}
	expectedRuntime := nodeapi.RuntimeArtifact{Version: lifecycle.QualificationFixtureRuntime, Executable: spec.Manifest.Executable, ExecutableDigest: spec.Manifest.ExecutableDigest, ImageDigest: spec.Manifest.ImageDigest, Files: files.Files(), FilesDigest: files.Digest()}
	if spec.Binding.ArtifactDigests["runtime.codex.files"] != files.Digest() || !reflect.DeepEqual(recipe.Runtime, expectedRuntime) {
		return errors.New("the lifecycle raw static runtime differs")
	}
	return nil
}

func verifyServiceLifecycleAuthority(recipe serviceLifecycleRecipe, header jobaudit.Header, public ed25519.PublicKey, calls []serviceLifecycleAuthorityCall) error {
	scope, err := lifecycle.QualificationFixtureScopeDigest(recipe.Spec)
	if err != nil {
		return err
	}
	if len(public) != ed25519.PublicKeySize || header.FixturePurpose != lifecycle.QualificationFixturePurpose || header.QualificationDigest != scope || header.Binding.CgroupID == 0 {
		return errors.New("the lifecycle authority raw scope differs")
	}
	expected := recipe.Spec.Binding
	expected.CgroupID = header.Binding.CgroupID
	if !reflect.DeepEqual(expected, header.Binding) {
		return errors.New("the lifecycle authority raw binding differs")
	}
	headerDigest, err := jobaudit.HeaderDigest(header)
	if err != nil {
		return err
	}
	keys := map[string]ed25519.PublicKey{serviceLifecycleAuthorityID + "/" + serviceLifecycleAuthorityKeyID: public}
	issued, revoked := false, false
	var last uint64
	for _, call := range calls {
		if call.GrantID != expected.GrantID || call.MonoNS == 0 || call.MonoNS < last {
			return errors.New("the lifecycle authority raw identity or order differs")
		}
		last = call.MonoNS
		switch call.Operation {
		case "issue":
			if issued || revoked || !call.Known || call.Revoked || call.Authorization == nil || call.Receipt != nil {
				return errors.New("the lifecycle authority issue readback differs")
			}
			authorization := call.Authorization
			grant, err := jobgrant.Decode(authorization.Grant)
			if err != nil {
				return err
			}
			claims, err := jobgrant.VerifySigned(grant, keys, recipe.Document)
			if err != nil {
				return err
			}
			if !reflect.DeepEqual(authorization.Binding, expected) || !reflect.DeepEqual(claims.Binding, expected) || !bytes.Equal(authorization.Document, recipe.Spec.Document) || !reflect.DeepEqual(authorization.RequiredCapabilities, recipe.Document.RequiredCapabilities) || claims.QualificationDigest != scope || claims.AuditHeaderDigest != headerDigest || claims.NotBefore != claims.IssuedAt || claims.ExpiresAt != claims.IssuedAt+5 {
				return errors.New("the lifecycle authority signed grant differs")
			}
			issued = true
		case "state":
			if call.Known != issued || call.Revoked != revoked || call.Authorization != nil || call.Receipt != nil {
				return errors.New("the lifecycle authority state readback differs")
			}
		case "revoke":
			if !issued || !call.Known || !call.Revoked || call.Authorization != nil || call.Receipt != nil {
				return errors.New("the lifecycle authority revocation readback differs")
			}
			revoked = true
		case "countersign":
			if !issued || !call.Known || call.Revoked != revoked || call.Authorization != nil || call.Receipt == nil || !reflect.DeepEqual(call.Receipt.Binding, expected) || call.Receipt.AuthorityID != serviceLifecycleAuthorityID || call.Receipt.KeyID != serviceLifecycleAuthorityKeyID || !call.Receipt.Accepted {
				return errors.New("the lifecycle authority receipt readback differs")
			}
			// The enclosing audit verifier checks the receipt signature against the
			// actual complete node bundle and its exact seal digest.
		default:
			return errors.New("the lifecycle authority raw operation is unknown")
		}
	}
	if !issued {
		return errors.New("the lifecycle authority issued no signed grant")
	}
	return nil
}

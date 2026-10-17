// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func credentialFixture(t *testing.T) (Manifest, Binding, CredentialReference, CredentialPolicy) {
	t.Helper()
	scratch := os.Getenv("AGENTGATE_TEST_SCRATCH")
	if scratch == "" && canonicalPrivate(os.Getenv("TMPDIR")) {
		scratch = os.Getenv("TMPDIR")
	}
	if scratch == "" {
		t.Skip("set AGENTGATE_TEST_SCRATCH to an owned private directory")
	}
	root, err := os.MkdirTemp(scratch, "credentials-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	sourceRoot := filepath.Join(root, "broker")
	if err = os.Mkdir(sourceRoot, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sourceRoot, "agent-login.json")
	secret := []byte("synthetic-custody-test-only")
	if err = os.WriteFile(path, secret, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(secret)
	manifest := manifestFixture()
	manifest.Workspace = filepath.Join(root, "job")
	binding := fixtureBinding()
	binding.CgroupID = 101
	binding.JobDigest, err = manifest.Digest()
	if err != nil {
		t.Fatal(err)
	}
	reference := CredentialReference{ID: "provider-login", AgentID: binding.AgentID, AgentKind: manifest.AgentKind, SourcePath: path, ExposedPath: filepath.Join(manifest.Workspace, "home", "auth.json"), Digest: hex.EncodeToString(digest[:])}
	binding.ArtifactDigests["credential."+reference.ID] = reference.Digest
	runtimeUID := uint32(os.Getuid())
	if runtimeUID == 0 {
		runtimeUID = 65534
	}
	return manifest, binding, reference, CredentialPolicy{SourceRoot: sourceRoot, SourceUID: uint32(os.Getuid()), RuntimeUID: runtimeUID}
}
func TestCredentialCustodyPinsSealedBytesBeforeSourceChanges(t *testing.T) {
	manifest, binding, reference, policy := credentialFixture(t)
	pinned, err := PinCredential(manifest, binding, reference, policy)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	seals, err := unix.FcntlInt(pinned.File.Fd(), unix.F_GET_SEALS, 0)
	if err != nil || seals&(unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL) != (unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL) {
		t.Fatal("credential descriptor is not sealed", err)
	}
	if _, err = pinned.File.WriteAt([]byte("changed"), 0); err == nil {
		t.Fatal("sealed credential changed")
	}
	if err = os.WriteFile(reference.SourcePath, []byte("replacement credential bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	bytes, err := io.ReadAll(pinned.File)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(bytes)
	if hex.EncodeToString(digest[:]) != reference.Digest {
		t.Fatal("source mutation changed pinned credential bytes")
	}
}
func TestCredentialCustodyRejectsCrossAgentUnboundLinkedAndPublicSources(t *testing.T) {
	for _, failure := range []string{"agent", "digest", "source-link", "public-source", "exposed-path", "root-runtime", "job"} {
		t.Run(failure, func(t *testing.T) {
			manifest, binding, reference, policy := credentialFixture(t)
			switch failure {
			case "agent":
				reference.AgentID = "another-agent"
			case "digest":
				delete(binding.ArtifactDigests, "credential."+reference.ID)
			case "source-link":
				link := reference.SourcePath + ".link"
				if err := os.Symlink(reference.SourcePath, link); err != nil {
					t.Fatal(err)
				}
				reference.SourcePath = link
			case "public-source":
				if err := os.Chmod(reference.SourcePath, 0644); err != nil {
					t.Fatal(err)
				}
			case "exposed-path":
				reference.ExposedPath = filepath.Join(policy.SourceRoot, "exposed.json")
			case "root-runtime":
				policy.RuntimeUID = 0
			case "job":
				binding.JobDigest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			}
			pinned, err := PinCredential(manifest, binding, reference, policy)
			if pinned != nil {
				pinned.Close()
			}
			if err == nil {
				t.Fatal("invalid credential custody accepted")
			}
		})
	}
}

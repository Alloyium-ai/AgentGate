// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type CredentialReference struct {
	ID          string `json:"id"`
	AgentID     string `json:"agent_id"`
	AgentKind   string `json:"agent_kind"`
	SourcePath  string `json:"source_path"`
	ExposedPath string `json:"exposed_path"`
	Digest      string `json:"digest"`
}
type CredentialPolicy struct {
	SourceRoot string
	SourceUID  uint32
	RuntimeUID uint32
}
type PinnedCredential struct {
	File       *os.File
	Reference  CredentialReference
	RuntimeUID uint32
}

func (p *PinnedCredential) Close() error { return p.File.Close() }
func beneath(root, path string) bool {
	return path != root && strings.HasPrefix(path, root+string(filepath.Separator))
}
func canonicalPrivate(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && path != "/" && path != "/tmp" && !strings.HasPrefix(path, "/tmp/") && !strings.ContainsRune(path, 0)
}

// PinCredential validates custody and returns a sealed descriptor. The backend
// mounts this descriptor read-only at the exact exposed path after policy checks.
// It must never reopen SourcePath after this measurement.
func PinCredential(manifest Manifest, binding Binding, reference CredentialReference, policy CredentialPolicy) (*PinnedCredential, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	if err := binding.validate(false); err != nil {
		return nil, err
	}
	jobDigest, err := manifest.Digest()
	if err != nil || jobDigest != binding.JobDigest {
		return nil, errors.New("credential custody differs from the signed job manifest")
	}
	if !identifier.MatchString(reference.ID) || len(reference.ID) > 64 || reference.AgentID != binding.AgentID || reference.AgentKind != manifest.AgentKind || policy.RuntimeUID == 0 || !validDigest(reference.Digest) {
		return nil, errors.New("credential identity or runtime custody is invalid")
	}
	if !canonicalPrivate(policy.SourceRoot) || !canonicalPrivate(reference.SourcePath) || !canonicalPrivate(reference.ExposedPath) || !beneath(policy.SourceRoot, reference.SourcePath) || !beneath(manifest.Workspace, reference.ExposedPath) || beneath(policy.SourceRoot, manifest.Workspace) || beneath(manifest.Workspace, policy.SourceRoot) || policy.SourceRoot == manifest.Workspace {
		return nil, errors.New("credential source and exposed paths do not meet their private boundaries")
	}
	if binding.ArtifactDigests["credential."+reference.ID] != reference.Digest {
		return nil, errors.New("credential bytes lack an exact signed artifact binding")
	}
	root, err := filepath.EvalSymlinks(policy.SourceRoot)
	if err != nil || root != policy.SourceRoot {
		return nil, errors.New("credential source root is linked or unavailable")
	}
	var rootInfo unix.Stat_t
	if err = unix.Stat(policy.SourceRoot, &rootInfo); err != nil || rootInfo.Mode&unix.S_IFMT != unix.S_IFDIR || rootInfo.Uid != policy.SourceUID || rootInfo.Mode&0077 != 0 {
		return nil, errors.New("credential source root ownership is invalid")
	}
	actual, err := filepath.EvalSymlinks(reference.SourcePath)
	if err != nil || actual != reference.SourcePath {
		return nil, errors.New("credential source is linked or unavailable")
	}
	sourceFD, err := unix.Open(reference.SourcePath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("credential source cannot open safely")
	}
	source := os.NewFile(uintptr(sourceFD), "credential-source")
	defer source.Close()
	var info unix.Stat_t
	if err = unix.Fstat(sourceFD, &info); err != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != policy.SourceUID || info.Mode&0077 != 0 || info.Nlink != 1 || info.Size < 1 || info.Size > MaxInputBytes {
		return nil, errors.New("credential source metadata is invalid")
	}
	pinnedFD, err := unix.MemfdCreate("agentgate-credential", unix.MFD_ALLOW_SEALING|unix.MFD_CLOEXEC)
	if err != nil {
		return nil, errors.New("sealed credential storage is unavailable")
	}
	pinned := os.NewFile(uintptr(pinnedFD), "credential-custody")
	retained := false
	defer func() {
		if !retained {
			pinned.Close()
		}
	}()
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(pinned, hash), io.LimitReader(source, MaxInputBytes+1))
	if err != nil || size != info.Size || size > MaxInputBytes || hex.EncodeToString(hash.Sum(nil)) != reference.Digest {
		return nil, errors.New("credential bytes differ from the signed artifact")
	}
	if err = unix.Fchown(pinnedFD, int(policy.RuntimeUID), -1); err != nil {
		return nil, errors.New("credential runtime owner cannot bind")
	}
	if err = unix.Fchmod(pinnedFD, 0400); err != nil {
		return nil, errors.New("credential runtime mode cannot bind")
	}
	if _, err = unix.FcntlInt(uintptr(pinnedFD), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_WRITE); err != nil {
		return nil, errors.New("credential storage cannot seal")
	}
	if _, err = pinned.Seek(0, io.SeekStart); err != nil {
		return nil, errors.New("credential custody cannot rewind")
	}
	retained = true
	return &PinnedCredential{File: pinned, Reference: reference, RuntimeUID: policy.RuntimeUID}, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/buildinfo"
	"alloyium.local/kernel-poc/internal/childwire"
	"alloyium.local/kernel-poc/internal/credentialstage"
	"alloyium.local/kernel-poc/internal/dockerplacement"
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
)

type CredentialConfig struct {
	Policy     lifecycle.CredentialPolicy      `json:"policy"`
	References []lifecycle.CredentialReference `json:"references"`
}

func needsCredentials(document policy.Document) bool {
	return document.Runtime != nil && document.Runtime.Bootstrap != nil && slices.Contains(document.Runtime.Bootstrap.Operations, "credential_namespace")
}

func (c CredentialConfig) validate(artifacts map[string]string) error {
	if c.Policy.RuntimeUID != 65534 || c.Policy.SourceUID == c.Policy.RuntimeUID || !filepath.IsAbs(c.Policy.SourceRoot) || filepath.Clean(c.Policy.SourceRoot) != c.Policy.SourceRoot || c.Policy.SourceRoot == "/" || c.Policy.SourceRoot == "/tmp" || strings.HasPrefix(c.Policy.SourceRoot, "/tmp/") || len(c.References) == 0 || len(c.References) > 16 {
		return errors.New("the credential broker configuration is invalid")
	}
	ids := map[string]bool{}
	for _, ref := range c.References {
		if ref.ID == "" || ids[ref.ID] || ref.AgentID == "" || (ref.AgentKind != "codex" && ref.AgentKind != "claude" && ref.AgentKind != "pi") || !validDigest(ref.Digest) || artifacts["credential."+ref.ID] != ref.Digest || !strings.HasPrefix(ref.SourcePath, c.Policy.SourceRoot+"/") || filepath.Clean(ref.SourcePath) != ref.SourcePath || !filepath.IsAbs(ref.ExposedPath) || filepath.Clean(ref.ExposedPath) != ref.ExposedPath {
			return errors.New("a credential reference differs from the measured registry")
		}
		ids[ref.ID] = true
	}
	return nil
}

func (b *Backend) prepareCredentials(ctx context.Context, r *run, a lifecycle.Authorization, m lifecycle.Manifest) error {
	if !needsCredentials(r.document) {
		return nil
	}
	if b.config.Credentials == nil {
		return errors.New("the credential namespace has no configured broker custody")
	}
	refs := []lifecycle.CredentialReference{}
	for _, ref := range b.config.Credentials.References {
		if ref.AgentID == r.binding.AgentID && ref.AgentKind == m.AgentKind {
			refs = append(refs, ref)
		}
	}
	if len(refs) == 0 {
		return errors.New("the exact enrolled runtime has no credential references")
	}
	stageConfig := credentialstage.Config{CredentialPolicy: b.config.Credentials.Policy, CheckRead: func(check context.Context, binding lifecycle.Binding, manifest lifecycle.Manifest, ref lifecycle.CredentialReference) error {
		if err := check.Err(); err != nil {
			return err
		}
		if !reflect.DeepEqual(binding, r.binding) || !reflect.DeepEqual(manifest, m) || r.document.Files == nil || policy.FileEffect(*r.document.Files, ref.ExposedPath, "read") != "allow" {
			return errors.New("the credential read differs from the effective signed policy")
		}
		return nil
	}, VerifyStopped: func(check context.Context, binding lifecycle.Binding, e lifecycle.Evidence) error {
		return b.verifyCredentialStop(check, r, binding, e)
	}}
	stage, err := stageConfig.Prepare(ctx, a, m, refs)
	if err != nil {
		return err
	}
	r.credentials = stage
	return r.control(ctx, "credential_staged", stage.Measurement())
}

func (b *Backend) startChild(ctx context.Context, r *run, m lifecycle.Manifest) (*enforcement.Child, error) {
	if m.AgentKind == "ssh" {
		return b.startDockerChild(ctx, r, m)
	}
	if r.credentials == nil {
		return r.group.StartChild(ctx, r.plan, b.config.Helper, b.config.ArtifactDigests["held-helper"], m, r.streams.Paths)
	}
	measurement := r.credentials.Measurement()
	if !reflect.DeepEqual(measurement.Binding, r.binding) {
		return nil, errors.New("the credential namespace binding differs")
	}
	file, err := r.credentials.NamespaceFD()
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return r.group.StartChildNamespace(ctx, r.plan, b.config.Helper, b.config.ArtifactDigests["held-helper"], m, r.streams.Paths, file, childwire.NamespaceIdentity{Device: measurement.NamespaceDevice, Inode: measurement.NamespaceInode})
}

func dockerIdentity(file *os.File) (childwire.NamespaceIdentity, error) {
	var st unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &st) != nil {
		return childwire.NamespaceIdentity{}, errors.New("the measured Docker descriptor is unavailable")
	}
	return childwire.NamespaceIdentity{Device: uint64(st.Dev), Inode: st.Ino}, nil
}

func dockerStreamPaths(host childwire.IOPaths, target dockerplacement.Target) (childwire.IOPaths, error) {
	translate := func(path string) (string, error) {
		if target.ArtifactPath == "" || target.ArtifactSource == "" || filepath.Clean(path) != path ||
			!strings.HasPrefix(path, target.ArtifactSource+"/") {
			return "", errors.New("the Docker stream path is outside its measured mount")
		}
		return filepath.Join(target.ArtifactPath, strings.TrimPrefix(path, target.ArtifactSource+"/")), nil
	}
	input, err := translate(host.Input)
	if err != nil {
		return childwire.IOPaths{}, err
	}
	output, err := translate(host.Output)
	if err != nil {
		return childwire.IOPaths{}, err
	}
	diagnostic, err := translate(host.Error)
	if err != nil {
		return childwire.IOPaths{}, err
	}
	return childwire.IOPaths{Input: input, Output: output, Error: diagnostic}, nil
}

func (b *Backend) startDockerChild(ctx context.Context, r *run, m lifecycle.Manifest) (*enforcement.Child, error) {
	target := b.config.PilotTarget
	if target == nil || r.document.Network == nil || r.document.Network.Pilot == nil ||
		m.ImageDigest != target.ImageDigest || m.Workspace != target.Workspace || r.credentials != nil ||
		!target.MatchesPilot(r.document.Network.Pilot.TaskboardTaskID, r.document.Network.Pilot.TaskboardIP, r.document.Network.Pilot.TaskboardPort) {
		return nil, errors.New("the signed SSH manifest differs from the measured Docker target")
	}
	if err := b.artifacts.OnlyJob(r.binding); err != nil {
		return nil, err
	}
	handles, err := dockerplacement.Open(ctx, *target)
	if err != nil {
		return nil, err
	}
	defer handles.Close()
	if err := matchPreparedPilotTarget(r.pilotTarget, handles.Measurement); err != nil {
		return nil, err
	}
	if buildinfo.SourceRevision == "" || handles.Measurement.ImageSourceRevision != buildinfo.SourceRevision {
		return nil, errors.New("the Docker target image source differs from the node")
	}
	descriptors := childwire.DockerDescriptors{Mount: handles.Mount, Network: handles.Network, PID: handles.PID, Root: handles.Root}
	for _, item := range []struct {
		file *os.File
		id   *childwire.NamespaceIdentity
	}{
		{handles.Mount, &descriptors.Identity.Mount},
		{handles.Network, &descriptors.Identity.Network},
		{handles.PID, &descriptors.Identity.PID},
		{handles.Root, &descriptors.Identity.Root},
	} {
		*item.id, err = dockerIdentity(item.file)
		if err != nil {
			return nil, err
		}
	}
	streamPaths, err := dockerStreamPaths(r.streams.Paths, *target)
	if err != nil {
		return nil, err
	}
	return r.group.StartChildDocker(ctx, r.plan, b.config.Helper, b.config.ArtifactDigests["held-helper"], m, streamPaths, descriptors)
}

func (b *Backend) verifyCredentialStop(ctx context.Context, r *run, binding lifecycle.Binding, e lifecycle.Evidence) error {
	if !reflect.DeepEqual(binding, r.binding) || lifecycle.VerifyReadback(e, binding, "stopped") != nil {
		return errors.New("the credential stop binding differs")
	}
	if r.child != nil && r.child.Held != nil {
		exited, err := r.child.Held.Exited()
		if err != nil || !exited {
			return errors.New("an unplaced held helper still retains credential custody")
		}
	}
	reservation, err := b.domains.Resolve(ctx, binding)
	if err != nil {
		return err
	}
	fd, err := unix.Open(filepath.Join(domainstore.RootPath, reservation.Name), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Ino != binding.CgroupID {
		return errors.New("the credential cleanup domain inode differs")
	}
	raw, err := readAt(fd, "cgroup.events")
	if err != nil || !strings.Contains(string(raw), "populated 0") {
		return errors.New("the credential cleanup domain remains populated")
	}
	return b.pins.VerifyRemoved(ctx, binding)
}

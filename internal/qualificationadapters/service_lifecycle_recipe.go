// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"

	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/nodebackend"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/runtimeclosure"
	"alloyium.local/kernel-poc/internal/testpolicy"
)

type serviceLifecycleLayout struct {
	OwnedRoot, ArtifactRoot, Worker, ImageDigest, TargetDigest string
	AgentID, AgentKey, RunID, GrantID                          string
	Generation, DeadlineNS                                     uint64
	CandidateRootProof                                         domainstore.RootProof
	RootProof                                                  domainstore.RootProof
	Input                                                      byte
}
type serviceLifecycleRecipe struct {
	CandidateRoot domainstore.RootProof `json:"candidate_root"`
	FixtureRoot   domainstore.RootProof `json:"fixture_root"`
	Spec          lifecycle.QualificationFixtureSpec
	Document      policy.Document
	Runtime       nodeapi.RuntimeArtifact
	Streams       jobartifacts.Streams
	Input         []byte
}

// The recipe adds no candidate permission or artifact. It uses the same measured
// physical root with a disjoint prefix and the candidate's empty static closure.
func newServiceLifecycleRecipe(request qualification.Request, layout serviceLifecycleLayout) (serviceLifecycleRecipe, error) {
	var recipe serviceLifecycleRecipe
	if err := validateRequest(request); err != nil {
		return recipe, err
	}
	if filepath.Dir(layout.OwnedRoot) != "/var/lib" || !strings.HasPrefix(filepath.Base(layout.OwnedRoot), "kernel-poc-qualification-") || filepath.Clean(layout.OwnedRoot) != layout.OwnedRoot || layout.ArtifactRoot != filepath.Join(layout.OwnedRoot, "streams") || filepath.Base(layout.Worker) != "qualification-lifecycle-worker" || (layout.Input != 'T' && layout.Input != 'E') {
		return recipe, errors.New("the lifecycle fixture layout differs from the fixed recipe")
	}
	files, err := runtimeclosure.New([]runtimeclosure.File{})
	if err != nil {
		return recipe, err
	}
	if request.Binding.ArtifactDigests["runtime.codex.files"] != files.Digest() || request.Binding.ArtifactDigests["domain-root"] != layout.CandidateRootProof.Digest() || layout.RootProof.BootID != request.Binding.BootID {
		return recipe, errors.New("the lifecycle fixture root or existing static closure differs from the candidate")
	}
	if err = verifyServiceLifecycleRoots(layout.CandidateRootProof, layout.RootProof); err != nil {
		return recipe, err
	}
	if _, err = base64.RawURLEncoding.Strict().DecodeString(layout.AgentKey); err != nil {
		return recipe, errors.New("the lifecycle fixture agent key differs")
	}
	manifest := lifecycle.Manifest{Protocol: "agentgate.job.manifest.v1", AgentKind: "codex", RuntimeVersion: lifecycle.QualificationFixtureRuntime, Executable: layout.Worker, ExecutableDigest: request.Binding.ArtifactDigests["qualification-lifecycle-worker"], ImageDigest: layout.ImageDigest, Arguments: []string{}, Environment: map[string]string{}, Workspace: layout.OwnedRoot, InputDigest: digestBytes([]byte{layout.Input})}
	jobDigest, err := manifest.Digest()
	if err != nil {
		return recipe, err
	}
	artifacts := map[string]string{}
	for name, value := range request.Binding.ArtifactDigests {
		artifacts[name] = value
	}
	artifacts["domain-root"] = layout.RootProof.Digest()
	binding := lifecycle.Binding{AgentID: layout.AgentID, AgentKey: layout.AgentKey, JobDigest: jobDigest, GrantID: layout.GrantID, RunID: layout.RunID, NodeID: request.Binding.NodeID, BootID: request.Binding.BootID, PolicyDigest: request.Binding.PolicyDigest, SchemaDigest: request.Binding.SchemaDigest, CompilerDigest: nodebackend.CompilerDigest(artifacts["node"]), ArtifactDigests: artifacts, Generation: layout.Generation, DeadlineNS: layout.DeadlineNS}
	store, err := jobartifacts.New(layout.ArtifactRoot, binding.NodeID, 1<<20)
	if err != nil {
		return recipe, err
	}
	streams, err := store.Paths(binding)
	closeErr := store.Close()
	if err != nil || closeErr != nil {
		return recipe, errors.Join(err, closeErr)
	}
	document := serviceLifecycleDocument(manifest, streams, artifacts["held-helper"])
	binding.PolicyDigest, err = document.Digest()
	if err != nil {
		return recipe, err
	}
	raw, err := document.Canonical()
	if err != nil {
		return recipe, err
	}
	spec := lifecycle.QualificationFixtureSpec{Binding: binding, Manifest: manifest, Document: raw, CandidateDigest: request.Binding.PolicyDigest, TargetDigest: layout.TargetDigest, SourceRevision: request.Binding.SourceRevision, OwnedRoot: layout.OwnedRoot}
	if _, err = lifecycle.QualificationFixtureScopeDigest(spec); err != nil {
		return recipe, err
	}
	runtime := nodeapi.RuntimeArtifact{Version: manifest.RuntimeVersion, Executable: manifest.Executable, ExecutableDigest: manifest.ExecutableDigest, ImageDigest: manifest.ImageDigest, Files: files.Files(), FilesDigest: files.Digest()}
	if !nodeapi.RuntimeFilesMatch(runtime, manifest, binding) || verifyServiceLifecycleArtifacts(request.Binding.ArtifactDigests, binding.ArtifactDigests, layout.CandidateRootProof, layout.RootProof) != nil {
		return recipe, errors.New("the lifecycle fixture changed a requested artifact")
	}
	return serviceLifecycleRecipe{CandidateRoot: layout.CandidateRootProof, FixtureRoot: layout.RootProof, Spec: spec, Document: document, Runtime: runtime, Streams: streams, Input: []byte{layout.Input}}, nil
}

func serviceLifecycleDocument(manifest lifecycle.Manifest, streams jobartifacts.Streams, helper string) policy.Document {
	document := testpolicy.Deny()
	document.Lifecycle.DurationSeconds = 30
	document.Runtime.Seccomp.AllowSyscalls = []string{"read", "write", "close", "openat", "fstat", "dup2", "execve", "exit_group", "getpid", "getppid", "clone", "futex", "clock_gettime", "lseek"}
	document.Runtime.Bootstrap = &policy.BootstrapPolicy{Profile: "measured-held-exec.v1", HelperDigest: helper, Operations: []string{"barrier_read", "listener_send", "filter_finalize", "working_directory"}, MaxHoldSeconds: 10}
	document.Runtime.Memory = &policy.MemoryPolicy{Default: "deny", Anonymous: []string{}, Heap: "deny"}
	eventfds := []string{}
	document.Runtime.IPC = &policy.IPCPolicy{Default: "deny", Pipes: []string{}, EventFDs: &eventfds}
	signals := []int{}
	document.Runtime.Signals = &signals
	document.Files.Rules = []policy.FileRule{
		{ID: "fixture-input", Selector: policy.Selector{Kind: "exact", Path: streams.Paths.Input}, Operations: []string{"read"}, Effect: "allow"},
		{ID: "fixture-output", Selector: policy.Selector{Kind: "exact", Path: streams.Paths.Output}, Operations: []string{"read", "write"}, Effect: "allow"},
		{ID: "fixture-error", Selector: policy.Selector{Kind: "exact", Path: streams.Paths.Error}, Operations: []string{"read", "write"}, Effect: "allow"},
		{ID: "fixture-worker-image", Selector: policy.Selector{Kind: "exact", Path: manifest.Executable}, Operations: []string{"read", "mmap", "map_execute"}, Effect: "allow"},
	}
	document.Programs.Rules = []policy.ProgramRule{{ID: "fixture-worker-exec", Selector: policy.Selector{Kind: "exact", Path: manifest.Executable}, Effect: "allow"}}
	document.RequiredCapabilities, _ = policy.Requirements(document)
	return document
}

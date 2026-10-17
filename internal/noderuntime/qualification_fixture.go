// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package noderuntime

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"errors"
	"reflect"
	"strings"
)

func (n *Node) qualificationPermit(ctx context.Context, spec lifecycle.QualificationFixtureSpec) (*lifecycle.QualificationFixturePermit, error) {
	if err := n.validateQualificationBinding(ctx, spec); err != nil {
		return nil, err
	}
	permit, err := lifecycle.NewQualificationFixturePermit(ctx, spec)
	if err != nil {
		return nil, err
	}
	if err = n.sources.VerifyRuntime(ctx, spec.Binding, spec.Manifest); err != nil {
		return nil, err
	}
	return permit, nil
}

func (n *Node) validateQualificationBinding(ctx context.Context, spec lifecycle.QualificationFixtureSpec) error {
	c := n.config
	if c.Credentials != nil || c.Resolver != nil || len(c.Enrollments) != 1 || len(c.Enrollments[0].Runtimes) != 1 || len(c.Documents) != 1 || c.Documents[spec.Binding.PolicyDigest] == "" || c.Enrollments[0].AgentID != spec.Binding.AgentID || c.Enrollments[0].AgentKey != spec.Binding.AgentKey || spec.Binding.NodeID != c.NodeID || spec.Binding.BootID != n.sources.Proof.BootID || spec.Binding.CompilerDigest != n.sources.Compiler || !reflect.DeepEqual(spec.Binding.ArtifactDigests, n.sources.Config.ArtifactDigests) || spec.SourceRevision != c.Qualification.SourceRevision {
		return errors.New("the node fixture configuration differs from the fixed binding")
	}
	snapshot, err := n.sources.Snapshot(ctx)
	if err != nil {
		return err
	}
	if snapshot.Target.Digest() != spec.TargetDigest {
		return errors.New("the node fixture target differs")
	}
	for _, cap := range snapshot.Target.Report().Capabilities {
		if cap.State == "enforced" {
			return errors.New("the node fixture cannot borrow an enforced report")
		}
	}
	return nil
}

func validateQualificationNodePaths(c Config, spec lifecycle.QualificationFixtureSpec) error {
	if _, err := lifecycle.QualificationFixtureScopeDigest(spec); err != nil {
		return err
	}
	return validateQualificationOwnedPaths(c, spec.OwnedRoot)
}

func validateQualificationOwnedPaths(c Config, root string) error {
	paths := []string{c.Journal, c.DomainState, c.AuditRoot, c.ArtifactRoot, c.SocketPath, c.WatchdogSocket, c.WatchdogStore, c.NodeKeyFile, c.Qualification.ReportFile, c.Authority.SocketPath}
	if c.WatchdogKeyFile != "" {
		paths = append(paths, c.WatchdogKeyFile)
	}
	for _, path := range c.Documents {
		paths = append(paths, path)
	}
	for _, path := range paths {
		if !canonical(path) || !strings.HasPrefix(path, root+"/") {
			return errors.New("the fixed qualification state leaves its owned root")
		}
	}
	if len(c.NodeKeys) != 1 || len(c.AuthorityKeys) != 1 {
		return errors.New("the qualification fixture requires isolated signing roles")
	}
	return nil
}

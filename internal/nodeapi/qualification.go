// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodeapi

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"bytes"
	"context"
	"errors"
	"reflect"
	"time"
)

func runtimeMatches(enrollment Enrollment, manifest lifecycle.Manifest, binding lifecycle.Binding) bool {
	runtime, ok := enrollment.Runtimes[manifest.AgentKind]
	return ok && runtime.Version == manifest.RuntimeVersion && runtime.Executable == manifest.Executable && runtime.ExecutableDigest == manifest.ExecutableDigest && runtime.ImageDigest == manifest.ImageDigest && RuntimeFilesMatch(runtime, manifest, binding) && (manifest.AgentKind != "pi" || piRuntimeMatches(runtime, manifest, binding)) && (manifest.AgentKind != "ssh" || lifecycle.SSHRuntimeMatches(runtime.ArgumentsPrefix, manifest) && sshEnvironmentEqual(runtime.Environment, manifest.Environment))
}

func sshEnvironmentEqual(enrolled, requested map[string]string) bool {
	if len(enrolled) != len(requested) {
		return false
	}
	for key, value := range enrolled {
		if requested[key] != value {
			return false
		}
	}
	return true
}
func (s *Server) bindingMatches(enrollment Enrollment, binding lifecycle.Binding) bool {
	return binding.AgentID == enrollment.AgentID && binding.AgentKey == enrollment.AgentKey && binding.NodeID == s.config.Identity.NodeID && binding.BootID == s.config.Identity.BootID
}
func (s *Server) qualified(ctx context.Context, binding lifecycle.Binding, required []string) error {
	if s.failed.Load() || len(required) == 0 || len(required) > 64 {
		return errors.New("node_runtime_unavailable")
	}
	target, err := s.operations.Target(ctx)
	if err != nil || !digestPattern.MatchString(target.Digest()) {
		return errors.New("node_target_unavailable")
	}
	report := target.Report()
	if report.Node != s.config.Identity.NodeID || report.Boot != s.config.Identity.BootID || report.PolicySchemaDigest != binding.SchemaDigest || binding.SchemaDigest != policy.SchemaDigest() || (time.Now().Unix() >= report.ValidUntil || report.IssuedAt > time.Now().Unix()+30) || !digestPattern.MatchString(report.InventorySHA256) || !digestPattern.MatchString(report.BTFSHA256) || !digestPattern.MatchString(report.KernelConfigSHA256) {
		return errors.New("node_target_unqualified")
	}
	artifactBound := false
	for _, digest := range binding.ArtifactDigests {
		if digest == report.ArtifactSHA256 {
			artifactBound = true
			break
		}
	}
	if !artifactBound {
		return errors.New("node_target_artifact_differs")
	}
	seen := map[string]bool{}
	for _, id := range required {
		capability, ok := report.Capabilities[id]
		if seen[id] || !ok || capability.State != "enforced" || len(capability.Mechanisms) == 0 || !digestPattern.MatchString(capability.ReceiptSHA256) {
			return errors.New("node_required_capability_unqualified")
		}
		seen[id] = true
	}
	return nil
}
func sameBinding(left, right lifecycle.Binding) bool { return reflect.DeepEqual(left, right) }
func validPrepared(request lifecycle.PrepareRequest, response lifecycle.PrepareResponse, clock lifecycle.Clock) bool {
	expected := request.Binding
	expected.CgroupID = response.Binding.CgroupID
	now, err := clock.NowNS()
	return err == nil && validAuditHeader(request, response, now) && response.Protocol == lifecycle.PreparedProtocol && expected.CgroupID != 0 && sameBinding(expected, response.Binding) && response.ManifestDigest == expected.JobDigest && response.PreparationDeadlineNS > now && response.PreparationDeadlineNS <= expected.DeadlineNS && response.Evidence.Phase == "quarantined" && sameBinding(response.Evidence.Binding, expected) && response.Evidence.Quarantined && !response.Evidence.Released && response.Evidence.Empty && !response.Evidence.RightsRemoved && response.Evidence.MandatoryHooks && response.Evidence.Lost == 0 && digestPattern.MatchString(response.Evidence.ReadbackDigest) && response.Evidence.Digest == lifecycle.EvidenceDigest(response.Evidence)
}

func validAuditHeader(request lifecycle.PrepareRequest, response lifecycle.PrepareResponse, now uint64) bool {
	var header jobaudit.Header
	if lifecycle.DecodeTransport(bytes.NewReader(response.AuditHeader), &header) != nil {
		return false
	}
	raw, err := jobaudit.HeaderBytes(header)
	if err != nil || !bytes.Equal(raw, response.AuditHeader) {
		return false
	}
	digest, err := jobaudit.HeaderDigest(header)
	return err == nil && digest == response.AuditHeaderDigest && sameBinding(header.Binding, response.Binding) && header.DocumentDigest == response.Binding.PolicyDigest && reflect.DeepEqual(header.RequiredCapabilities, request.RequiredCapabilities) && header.CreatedMonoNS <= now
}

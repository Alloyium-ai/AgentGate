// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/policy"
	"alloyium.local/kernel-poc/internal/qualification"
	"golang.org/x/sys/unix"
)

func serviceLifecycleExecutedCandidate(request qualification.Request, recipe serviceLifecycleRecipe) bool {
	requested, err := request.Document.Canonical()
	if err != nil {
		return false
	}
	executed, err := recipe.Document.Canonical()
	if err != nil {
		return false
	}
	return recipe.Spec.Binding.PolicyDigest == request.Binding.PolicyDigest &&
		recipe.Spec.CandidateDigest == request.Binding.PolicyDigest &&
		bytes.Equal(requested, executed) && bytes.Equal(requested, recipe.Spec.Document)
}

func (a *serviceLifecycleAdapter) Verify(request qualification.Request, result qualification.Result) ([]qualification.Coverage, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	if len(result.Raw) == 0 || len(result.Raw) > qualification.MaxRawBytes || uniqueJSON(result.Raw) != nil || !reflect.DeepEqual(result.Binding, request.Binding) || result.StartedMonoNS == 0 || result.FinishedMonoNS <= result.StartedMonoNS {
		return nil, errors.New("the lifecycle result encoding, binding or times differ")
	}
	var receipt serviceLifecycleReceipt
	decoder := json.NewDecoder(bytes.NewReader(result.Raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return nil, err
	}
	if a.ID() == "" || receipt.Protocol != serviceLifecycleReceiptVersion || receipt.AdapterID != a.ID() || !reflect.DeepEqual(receipt.Binding, request.Binding) || len(receipt.Scenes) != 1 {
		return nil, errors.New("the lifecycle receipt scope differs")
	}
	cases := map[string]map[string]bool{}
	add := func(capability string, names ...string) {
		if cases[capability] == nil {
			cases[capability] = map[string]bool{}
		}
		for _, name := range names {
			cases[capability][name] = true
		}
	}
	for _, scene := range receipt.Scenes {
		if scene.Mode != a.mode {
			return nil, errors.New("the fixed lifecycle scenario differs")
		}
		if scene.Error != "" {
			continue
		}
		if a.mode == "watchdog-loss" {
			if err := verifyServiceLifecycleLoss(request, result, receipt, scene); err != nil {
				return nil, err
			}
			add("lifecycle.baseline.v1", "watchdog-loss-stops-descendants")
			continue
		}
		if a.mode == "node-loss" {
			if err := verifyServiceLifecycleNodeLoss(request, result, receipt, scene); err != nil {
				return nil, err
			}
			add("lifecycle.baseline.v1", "node-loss-stops-descendants", "incomplete-recovery-terminal")
			continue
		}
		if a.mode == "prepare-reply-loss" {
			if err := verifyServiceLifecyclePrepareReplyLoss(request, result, receipt, scene); err != nil {
				return nil, err
			}
			add("lifecycle.baseline.v1", "lost-prepare-reply-expires")
			continue
		}
		if err := verifyServiceLifecycleScene(request, result, receipt, scene); err != nil {
			return nil, err
		}
		add("lifecycle.baseline.v1", "prepare-quarantines", "install-readback-before-release")
		add("process.job-domain.v1", "placement-pid-starttime-readback", "child-in-same-root", "grandchild-in-same-root")
		add("lifecycle.terminate.v1", "whole-domain-stop", "child-and-grandchild-terminated", "empty-before-rights-removal", "counter-availability-preserved", "repeat-stop-idempotent")
		add("identity.job.v1", "valid-binding-accepted")
		audit, err := verifyServiceLifecycleAudit(request, scene.Recipe, scene.Audit, scene.NodeKeys, map[string]ed25519.PublicKey{serviceLifecycleAuthorityID + "/" + serviceLifecycleAuthorityKeyID: scene.AuthorityPublic})
		if err != nil {
			return nil, err
		}
		for _, coverage := range audit {
			add(coverage.CapabilityID, coverage.Cases...)
		}
		if a.mode == "expiry" && verifyServiceLifecycleCutoff(scene) == nil {
			add("lifecycle.baseline.v1", "grant-wall-and-mono-cutoff")
		}
		if verifyServiceLifecycleFrames(scene) == nil && verifyServiceLifecycleInheritanceOutcomes(request, scene) == nil {
			add("runtime.explicit-syscalls.v2", "fork-inherits-filter", "grandchild-inherits-filter")
		}
		if a.mode == "revoke" {
			if scene.Stopped.Terminal.State != "revoked" {
				return nil, errors.New("the actual revoked lifecycle terminal differs")
			}
			add("lifecycle.baseline.v1", "revoked-grant-stops")
		}
	}
	// Fixed lifecycle scenes run their own deliberately narrow document. Their
	// verified observations are useful diagnostics, but a candidate report may
	// claim a case only when that exact requested document was executed.
	for _, scene := range receipt.Scenes {
		if scene.Error != "" {
			continue
		}
		if !serviceLifecycleExecutedCandidate(request, scene.Recipe) {
			return nil, nil
		}
	}
	coverage := []qualification.Coverage{}
	for _, contract := range request.Contracts {
		names := []string{}
		for _, name := range contract.Cases {
			if cases[contract.CapabilityID][name] {
				names = append(names, name)
			}
		}
		if len(names) > 0 {
			coverage = append(coverage, qualification.Coverage{CapabilityID: contract.CapabilityID, ContractVersion: qualification.ContractVersion, Cases: names, ReceiptSHA256: digestBytes(result.Raw)})
		}
	}
	return coverage, nil
}
func verifyServiceLifecycleScene(request qualification.Request, result qualification.Result, receipt serviceLifecycleReceipt, scene serviceLifecycleScene) error {
	if err := verifyServiceLifecycleActive(request, result, receipt, scene); err != nil {
		return err
	}
	binding := scene.Prepared.Record.Binding
	var err error
	for _, status := range []noderuntime.QualificationStatus{scene.Stopped, scene.Repeat} {
		if status.Protocol != noderuntime.QualificationStatusProtocol || status.Purpose != lifecycle.QualificationFixturePurpose || status.Record.State != "stopped" || !reflect.DeepEqual(status.Record.Binding, binding) || status.Terminal == nil || !reflect.DeepEqual(status.Terminal.Binding, binding) || !status.Terminal.DomainEmpty || !status.Terminal.RightsRemoved || status.Terminal.EvidenceVerdict != "VALID_COMPLETE" {
			return errors.New("the actual lifecycle stopped record or audit differs")
		}
		if len(status.Record.Evidence) == 0 {
			return errors.New("the lifecycle stop readback is absent")
		}
		evidence := status.Record.Evidence[len(status.Record.Evidence)-1]
		if lifecycle.VerifyReadback(evidence, binding, "stopped") != nil || !evidence.CountersAvailable || evidence.Lost != 0 {
			return errors.New("the lifecycle stop counters or readback differ")
		}
	}
	if !bytes.Equal(scene.Stopped.Terminal.Output, scene.Wire) || digestBytes(scene.Wire) != scene.Stopped.Terminal.OutputDigest {
		return errors.New("the actual lifecycle output digest differs")
	}
	if !reflect.DeepEqual(scene.Stopped.Record, scene.Repeat.Record) || !reflect.DeepEqual(scene.Stopped.Terminal, scene.Repeat.Terminal) {
		return errors.New("the repeated lifecycle stop changed its terminal")
	}
	if err = verifyServiceLifecycleSceneMode(scene); err != nil {
		return err
	}
	if scene.AuditFile != nil && (scene.AuditFile.StartedNS < result.StartedMonoNS || scene.AuditFile.FinishedNS > result.FinishedMonoNS) {
		return errors.New("the actual audit file read falls outside its result clocks")
	}
	if err = verifyServiceLifecycleAuditFile(scene); err != nil {
		return err
	}
	if err = verifyServiceLifecycleAuditLinks(scene); err != nil {
		return err
	}
	if err = verifyServiceLifecycleMaps(scene); err != nil {
		return err
	}
	if err = verifyServiceLifecycleActors(scene, binding, result); err != nil {
		return err
	}
	var prepareCall *serviceLifecycleHTTPCall
	for index := range scene.Calls {
		call := &scene.Calls[index]
		if call.MonoNS < result.StartedMonoNS || call.MonoNS > result.FinishedMonoNS || call.Status != 200 {
			return errors.New("the actual lifecycle HTTP observation differs")
		}
		if err = verifyServiceLifecycleHTTPCall(*call, scene); err != nil {
			return err
		}
		if call.Path == "/fixture/prepare" {
			if prepareCall != nil {
				return errors.New("the lifecycle prepare repeats")
			}
			prepareCall = call
			var actual noderuntime.QualificationPrepared
			if lifecycle.DecodeTransport(bytes.NewReader(call.Response), &actual) != nil || !reflect.DeepEqual(actual, scene.Prepared) {
				return errors.New("the actual prepare response bytes differ")
			}
		}
	}
	if prepareCall == nil || prepareCall.MonoNS < scene.Prepared.PreparedMonoNS || prepareCall.MonoNS >= scene.Prepared.Record.PreparationDeadlineNS {
		return errors.New("the actual lifecycle preparation observation is stale")
	}
	return nil
}
func verifyServiceLifecycleActive(request qualification.Request, result qualification.Result, receipt serviceLifecycleReceipt, scene serviceLifecycleScene) error {
	image, err := serviceLifecycleImageDigest(receipt.ServiceImage)
	if err != nil || scene.Recipe.Spec.Manifest.ImageDigest != image {
		return errors.New("the lifecycle executed image digest differs")
	}
	if err := verifyServiceLifecycleRecipe(request, scene.Recipe); err != nil {
		return err
	}
	if len(scene.CleanupErrors) != 0 || scene.FinalDomainErrno != int(unix.ENOENT) || len(scene.FinalPins) != 0 {
		return errors.New("the lifecycle actual cleanup differs")
	}
	if err := scene.Start.Validate(); err != nil {
		return err
	}
	if !reflect.DeepEqual(scene.Start.Spec, scene.Recipe.Spec) || scene.Start.NodeConfigFile != filepath.Join(scene.Recipe.Spec.OwnedRoot, "private/node.json") {
		return errors.New("the sealed lifecycle start differs")
	}
	prepared, err := noderuntime.VerifyQualificationPrepared(scene.Prepared, scene.Recipe.Spec, scene.NodeKeys, scene.WatchdogPublic, scene.Prepared.PreparedAtUnix, 2*time.Second)
	if err != nil {
		return err
	}
	public, err := base64.RawURLEncoding.Strict().DecodeString(receipt.TargetPublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return errors.New("the lifecycle unavailable target key differs")
	}
	target, err := policy.VerifyTarget(receipt.TargetEnvelope, public, policy.TargetBinding{Node: request.Binding.NodeID, Boot: request.Binding.BootID, Challenge: scene.NodeConfig.Qualification.Challenge}, prepared.Wall)
	if err != nil {
		return err
	}
	if target.Digest() != scene.Recipe.Spec.TargetDigest || target.Report().SourceRevision != request.Binding.SourceRevision {
		return errors.New("the lifecycle signed unavailable target differs")
	}
	for _, capability := range target.Report().Capabilities {
		if capability.State == "enforced" {
			return errors.New("the lifecycle fixture borrowed an enforced target")
		}
	}
	binding := scene.Prepared.Record.Binding
	if scene.Active.Protocol != noderuntime.QualificationStatusProtocol || scene.Active.Purpose != lifecycle.QualificationFixturePurpose || scene.Active.Record.State != "active" || !reflect.DeepEqual(scene.Active.Record.Binding, binding) {
		return errors.New("the actual lifecycle release state differs")
	}
	var header jobaudit.Header
	if err = lifecycle.DecodeTransport(bytes.NewReader(scene.Prepared.AuditHeader), &header); err != nil {
		return err
	}
	if err = verifyServiceLifecycleAuthority(scene.Recipe, header, scene.AuthorityPublic, scene.AuthorityCalls); err != nil {
		return err
	}
	if scene.NodeSnapshot.PID <= 1 || scene.NodeSnapshot.StartTimeTicks == 0 || scene.NodeSnapshot.ExecutableSHA256 != request.Binding.ArtifactDigests["node"] || scene.NodeSnapshot.MonoNS < result.StartedMonoNS || scene.NodeSnapshot.MonoNS > result.FinishedMonoNS {
		return errors.New("the measured lifecycle node process differs")
	}
	if scene.Active.Record.Authorization == nil {
		return errors.New("the released fixture lacks its actual signed grant")
	}
	issued := false
	for _, call := range scene.AuthorityCalls {
		if call.Operation == "issue" {
			if call.Authorization == nil || !reflect.DeepEqual(*call.Authorization, *scene.Active.Record.Authorization) {
				return errors.New("the actual released authorization differs from durable authority custody")
			}
			issued = true
		}
	}
	if !issued {
		return errors.New("the actual released fixture has no stored authorization")
	}
	if err = verifyServiceLifecyclePhases(scene.Active.Record); err != nil {
		return err
	}
	if scene.WatchdogState != nil {
		if scene.WatchdogState.StartedNS < result.StartedMonoNS || scene.WatchdogState.FinishedNS > result.FinishedMonoNS {
			return errors.New("the watchdog readback falls outside its result clocks")
		}
		if err = verifyServiceLifecycleWatchdog(scene, scene.Active.Record.Evidence[len(scene.Active.Record.Evidence)-1].EffectiveDeadlineNS); err != nil {
			return err
		}
	}
	return nil
}
func verifyServiceLifecyclePhases(record lifecycle.Record) error {
	phases := []string{"quarantined", "placed", "installed", "active"}
	if len(record.Evidence) != len(phases) || record.Process == nil {
		return errors.New("the lifecycle actual phase readbacks are incomplete")
	}
	for index, phase := range phases {
		e := record.Evidence[index]
		if lifecycle.VerifyReadback(e, record.Binding, phase) != nil || e.FixturePurpose != lifecycle.QualificationFixturePurpose {
			return errors.New("the actual lifecycle phase binding or purpose differs")
		}
		if index > 0 && !reflect.DeepEqual(e.Process, record.Process) {
			return errors.New("the placed lifecycle process changed")
		}
	}
	return nil
}
func verifyServiceLifecycleActors(scene serviceLifecycleScene, binding lifecycle.Binding, result qualification.Result) error {
	actors, err := DecodeLifecycleRecords(scene.Wire)
	if err != nil {
		return err
	}
	if len(scene.Actors) != 3 || len(scene.After) != 3 || scene.Active.Record.Process == nil || scene.DomainInode != binding.CgroupID {
		return errors.New("the lifecycle tree or root readback is incomplete")
	}
	if !serviceLifecycleActorsTerminated(scene.Actors, scene.After) {
		return errors.New("the actual lifecycle process termination is unconfirmed")
	}
	name, err := domainstore.ReservationName(scene.Recipe.FixtureRoot.OwnedPrefix, binding)
	if err != nil {
		return err
	}
	domain := filepath.Join(domainstore.RootPath, name)
	if scene.Domain != domain {
		return errors.New("the lifecycle final domain path differs")
	}
	for index, actor := range actors {
		snapshot := scene.Actors[index]
		if snapshot.PID != int(actor.PID) || snapshot.MonoNS < result.StartedMonoNS || snapshot.MonoNS > result.FinishedMonoNS || !memberSnapshot(snapshot, domain) || snapshot.Executable != scene.Recipe.Spec.Manifest.Executable || snapshot.ExecutableSHA256 != scene.Recipe.Spec.Manifest.ExecutableDigest {
			return errors.New("the lifecycle actual process or artifact binding differs")
		}
		if err = validateServiceLifecycleActor(snapshot, actor.ParentPID); err != nil {
			return err
		}
		after := scene.After[index]
		if after.PID != snapshot.PID {
			return errors.New("the lifecycle termination PID differs")
		}
		if after.Error != "" && after.Errno != int(unix.ENOENT) {
			return errors.New("the lifecycle termination process readback is unavailable")
		}
		if after.Error == "" && (after.StartTicks == 0 || after.StartTicks == snapshot.StartTimeTicks && !strings.HasPrefix(processFields(after.Status)["State"], "Z")) {
			return errors.New("an actual lifecycle descendant survived")
		}
		if index == 0 && actor.ParentPID != uint32(scene.NodeSnapshot.PID) {
			return errors.New("the actual lifecycle worker parent differs from the measured node")
		}
	}
	if scene.Active.Record.Process.PID != scene.Actors[0].PID || scene.Active.Record.Process.StartTimeTicks != scene.Actors[0].StartTimeTicks {
		return errors.New("the actual placement PID start time differs")
	}
	return verifyServiceLifecycleActorOutcomes(scene)
}

func verifyServiceLifecycleAuditLinks(scene serviceLifecycleScene) error {
	return verifyServiceLifecycleAuditTerminal(scene, scene.Stopped.Record, scene.Stopped.Terminal)
}

func verifyServiceLifecycleAuditTerminal(scene serviceLifecycleScene, record lifecycle.Record, terminal *lifecycle.Terminal) error {
	bundle, err := jobauthority.DecodeAuditBundle(scene.Audit)
	if err != nil {
		return err
	}
	if bundle.Seal == nil || terminal == nil || bundle.Seal.Terminal.State != terminal.State || bundle.Seal.Terminal.ExitCode != terminal.ExitCode || bundle.Seal.Terminal.OutputDigest != terminal.OutputDigest {
		return errors.New("the actual lifecycle terminal differs from the node seal")
	}
	header, err := jobaudit.HeaderBytes(bundle.Header)
	if err != nil || !bytes.Equal(header, scene.Prepared.AuditHeader) {
		return errors.New("the actual lifecycle prepared and sealed audit headers differ")
	}
	phases := map[string]bool{}
	var stopped *lifecycle.Evidence
	for _, event := range bundle.Events {
		if event.Stream != nodecontrol.Stream {
			continue
		}
		var record nodecontrol.Record
		if lifecycle.DecodeTransport(bytes.NewReader(event.Raw), &record) != nil {
			return errors.New("the lifecycle raw control record differs")
		}
		phases[record.Phase] = true
		if record.Phase == "stopped" {
			var payload struct {
				Evidence         lifecycle.Evidence
				DiagnosticDigest string
				Errors           []string
			}
			if lifecycle.DecodeTransport(bytes.NewReader(record.Payload), &payload) != nil || len(payload.Errors) != 0 {
				return errors.New("the actual stopped audit control is incomplete")
			}
			observed := payload.Evidence
			stopped = &observed
		}
	}
	for _, name := range []string{"quarantine_readback", "grant_expiry_bound", "runtime_files_verified", "held", "placed", "installed", "release_intent", "stopped"} {
		if !phases[name] {
			return errors.New("an actual lifecycle control phase is absent: " + name)
		}
	}
	if len(record.Evidence) == 0 || stopped == nil || !reflect.DeepEqual(*stopped, record.Evidence[len(record.Evidence)-1]) || terminal.EvidenceDigest != stopped.Digest {
		return errors.New("the actual stopped audit evidence differs from the journal")
	}
	return nil
}
func verifyServiceLifecycleHTTPCall(call serviceLifecycleHTTPCall, scene serviceLifecycleScene) error {
	switch call.Path {
	case "/fixture/prepare":
		if call.Method != "POST" || !bytes.Equal(call.Request, []byte("{}")) {
			return errors.New("the actual prepare command differs")
		}
	case "/fixture/start":
		var input noderuntime.QualificationRunRequest
		var output noderuntime.QualificationStatus
		if call.Method != "POST" || lifecycle.DecodeTransport(bytes.NewReader(call.Request), &input) != nil || input.Protocol != noderuntime.QualificationRunProtocol || scene.Active.Record.Authorization == nil || !reflect.DeepEqual(input.Authorization, *scene.Active.Record.Authorization) || lifecycle.DecodeTransport(bytes.NewReader(call.Response), &output) != nil || !reflect.DeepEqual(output, scene.Active) {
			return errors.New("the actual lifecycle start exchange differs")
		}
	case "/fixture/status":
		var output noderuntime.QualificationStatus
		if call.Method != "GET" || len(call.Request) != 0 || lifecycle.DecodeTransport(bytes.NewReader(call.Response), &output) != nil || output.Protocol != noderuntime.QualificationStatusProtocol || output.Purpose != lifecycle.QualificationFixturePurpose || !reflect.DeepEqual(output.Record.Binding, scene.Prepared.Record.Binding) {
			return errors.New("the actual lifecycle status exchange differs")
		}
	case "/fixture/stop":
		var input noderuntime.QualificationStopRequest
		var output noderuntime.QualificationStatus
		if call.Method != "POST" || lifecycle.DecodeTransport(bytes.NewReader(call.Request), &input) != nil || input.Protocol != noderuntime.QualificationStopProtocol || input.Reason != "client-stop" || lifecycle.DecodeTransport(bytes.NewReader(call.Response), &output) != nil || !reflect.DeepEqual(output, scene.Stopped) && !reflect.DeepEqual(output, scene.Repeat) {
			return errors.New("the actual lifecycle stop exchange differs")
		}
	default:
		return errors.New("the actual lifecycle command path is unknown")
	}
	return nil
}

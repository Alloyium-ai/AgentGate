// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/nodebackend"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/qualification"
	"alloyium.local/kernel-poc/internal/requestproof"
)

func changedServiceAuthorization(base lifecycle.Authorization, name string) (lifecycle.Authorization, error) {
	var changed lifecycle.Authorization
	if err := lifecycle.DecodeTransport(bytes.NewReader(serviceJSON(base)), &changed); err != nil {
		return changed, err
	}
	switch name {
	case "wrong-job":
		changed.Binding.JobDigest = digestJSON(name)
	case "wrong-policy":
		changed.Binding.PolicyDigest = digestJSON(name)
	case "wrong-node":
		changed.Binding.NodeID += "-other"
	case "wrong-boot":
		changed.Binding.BootID += "-other"
	case "wrong-agent":
		changed.Binding.AgentID += "-other"
	case "wrong-agent-key": // The verifier checks this separately against the authority key.
	case "wrong-generation":
		changed.Binding.Generation++
	case "wrong-artifact":
		changed.Binding.ArtifactDigests["node"] = digestJSON(name)
	case "unknown-revocation":
	default:
		return changed, errors.New("the identity case is unknown")
	}
	return changed, nil
}

func verifyIdentity(request qualification.Request, r serviceReceipt) error {
	var envelope jobgrant.Envelope
	var auth lifecycle.Authorization
	var signed jobgrant.Claims
	if len(r.AuthorityKey) != ed25519.PublicKeySize || len(r.AgentKey) != ed25519.PublicKeySize || len(r.NodeKey) != ed25519.PublicKeySize || bytes.Equal(r.AuthorityKey, r.AgentKey) || bytes.Equal(r.NodeKey, r.AgentKey) || bytes.Equal(r.NodeKey, r.AuthorityKey) {
		return errors.New("the identity signing keys differ")
	}
	for _, item := range []struct {
		raw []byte
		dst any
	}{{r.Grant, &envelope}, {r.Authorization, &auth}, {r.SignedClaims, &signed}} {
		if err := lifecycle.DecodeTransport(bytes.NewReader(item.raw), item.dst); err != nil {
			return err
		}
	}
	if len(r.KeyRoles) != 3 {
		return errors.New("the key role calls are incomplete")
	}
	nodes := map[string]ed25519.PublicKey{"qualification-node/one": r.NodeKey}
	authorities := map[string]ed25519.PublicKey{"qualification-authority/one": r.AuthorityKey}
	for index, item := range []struct {
		name string
		key  []byte
	}{{"separate-agent-key", r.AgentKey}, {"node-role-reuse", r.NodeKey}, {"authority-role-reuse", r.AuthorityKey}} {
		call := r.KeyRoles[index]
		encoded := base64.RawURLEncoding.EncodeToString(item.key)
		outcome := noderuntime.VerifyAgentKeyRoles(encoded, nodes, authorities)
		if call.Name != item.name || !bytes.Equal(call.Input, serviceJSON(encoded)) || call.Error != serviceError(outcome) || (index == 0 && outcome != nil) || (index > 0 && outcome == nil) {
			return errors.New("the actual enrollment key role outcome differs")
		}
	}
	claims, err := jobgrant.VerifySigned(envelope, map[string]ed25519.PublicKey{"qualification-authority/one": r.AuthorityKey}, request.Document)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(claims, signed) || !reflect.DeepEqual(claims.Binding, auth.Binding) || auth.Binding.JobDigest != digestJSON(request.Binding) || auth.Binding.CompilerDigest != nodebackend.CompilerDigest(request.Binding.ArtifactDigests["node"]) || !reflect.DeepEqual(auth.Binding.ArtifactDigests, request.Binding.ArtifactDigests) || auth.Binding.NodeID != request.Binding.NodeID || auth.Binding.BootID != request.Binding.BootID || auth.Binding.AgentID != "qualification-agent" || auth.Binding.AgentKey != base64.RawURLEncoding.EncodeToString(r.AgentKey) || auth.Binding.Generation != 1 || auth.Binding.CgroupID != 1 {
		return errors.New("the signed identity candidate binding differs")
	}
	encoded, err := jobgrant.Encode(envelope)
	if err != nil || auth.Grant != encoded {
		return errors.New("the signed grant bytes differ")
	}
	document, err := request.Document.Canonical()
	if err != nil || !bytes.Equal(auth.Document, document) || !reflect.DeepEqual(auth.RequiredCapabilities, request.Document.RequiredCapabilities) {
		return errors.New("the signed identity document differs")
	}
	names := []string{"valid-signature", "wrong-job", "wrong-policy", "wrong-node", "wrong-boot", "wrong-agent", "wrong-agent-key", "wrong-generation", "wrong-artifact", "unknown-revocation", "reserve-generation", "generation-replay-after-reopen"}
	if len(r.Calls) != len(names) {
		return errors.New("the identity calls are incomplete")
	}
	for index, name := range names {
		call := r.Calls[index]
		if call.Name != name {
			return errors.New("the identity call order differs")
		}
		if index == 0 {
			if call.Error != "" || len(call.Input) != 0 {
				return errors.New("the valid signed grant did not verify")
			}
			continue
		}
		if index >= 10 {
			continue
		}
		expected, e := changedServiceAuthorization(auth, name)
		if e != nil {
			return e
		}
		if name == "wrong-agent-key" {
			expected.Binding.AgentKey = base64.RawURLEncoding.EncodeToString(r.AuthorityKey)
		}
		var actual lifecycle.Authorization
		if e = lifecycle.DecodeTransport(bytes.NewReader(call.Input), &actual); e != nil || !reflect.DeepEqual(actual, expected) {
			return errors.New("the identity negative input differs")
		}
		expectedError := "the authorization differs from the full grant"
		if name == "unknown-revocation" {
			expectedError = "the full grant revocation state is unavailable"
			if call.MonoNS >= claims.DeadlineNS {
				return errors.New("the unknown revocation call followed expiry")
			}
		}
		if call.Error != expectedError {
			return fmt.Errorf("the %s outcome differs", name)
		}
	}
	var records []lifecycle.Record
	if err = lifecycle.DecodeTransport(bytes.NewReader(r.JournalRecords), &records); err != nil {
		return err
	}
	var initial, replay lifecycle.Record
	if err = lifecycle.DecodeTransport(bytes.NewReader(r.Calls[10].Input), &initial); err != nil {
		return err
	}
	if err = lifecycle.DecodeTransport(bytes.NewReader(r.Calls[11].Input), &replay); err != nil {
		return err
	}
	expectedBinding := auth.Binding
	expectedBinding.CgroupID = 0
	expectedRecord := lifecycle.Record{Binding: expectedBinding, State: "preparing", Revision: 1, PreparationDeadlineNS: expectedBinding.DeadlineNS}
	if !reflect.DeepEqual(initial, expectedRecord) || len(records) != 1 || !reflect.DeepEqual(records[0], expectedRecord) || r.GenerationFloor != 1 || r.Calls[10].Error != "" || r.Calls[11].Error != lifecycle.ErrReplay.Error() {
		return errors.New("the durable generation readback differs")
	}
	expectedRecord.Binding.RunID += "-replay"
	if !reflect.DeepEqual(replay, expectedRecord) {
		return errors.New("the replay did not retain the reserved generation")
	}
	return nil
}

func verifyProofSignature(call enrollmentCall, public []byte) (requestproof.Claims, error) {
	claims, err := requestproof.Parse(call.Token)
	if err != nil {
		return claims, err
	}
	parts := strings.Split(call.Token, ".")
	signature, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || len(public) != ed25519.PublicKeySize || !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
		return claims, errors.New("the enrollment proof signature differs")
	}
	return claims, nil
}

func verifyEnrollment(request qualification.Request, result qualification.Result, r enrollmentReceipt) error {
	if len(r.AgentKey) != ed25519.PublicKeySize || r.PeerUID != 0 || r.SocketUID != 0 || r.SocketGID != r.PeerGID || r.SocketMode != 0660 || !r.SocketRemoved || r.ServerError != "" || r.PersistedReplayError != lifecycle.ErrReplay.Error() {
		return errors.New("the private socket custody or durable cleanup differs")
	}
	names := []string{"enrolled-proof", "proof-replay", "wrong-peer-uid", "wrong-peer-gid", "unenrolled-subject", "disabled-enrollment", "wrong-key", "body-substitution"}
	if len(r.Calls) != len(names) {
		return errors.New("the enrollment calls are incomplete")
	}
	baseline := nodeapi.Enrollment{AgentID: "qualification-agent", AgentKey: base64.RawURLEncoding.EncodeToString(r.AgentKey), PeerUID: r.PeerUID, PeerGID: r.PeerGID, Enabled: true, Runtimes: map[string]nodeapi.RuntimeArtifact{}}
	nonces := map[string]bool{}
	for index, name := range names {
		call := r.Calls[index]
		if call.Name != name || call.Method != "GET" || call.Path != "/v1/agents/qualification-agent/generation" || call.MonoNS < result.StartedMonoNS || call.MonoNS > result.FinishedMonoNS {
			return errors.New("the enrollment call binding or order differs")
		}
		claims, err := verifyProofSignature(call, r.AgentKey)
		if err != nil {
			return err
		}
		if claims.Subject != baseline.AgentID || claims.Method != call.Method || claims.Path != call.Path || claims.Audience != lifecycle.NodeAudience(request.Binding.NodeID) || claims.Epoch != request.Binding.BootID {
			return errors.New("the enrollment proof recipient differs")
		}
		expected := baseline
		switch name {
		case "wrong-peer-uid":
			expected.PeerUID++
		case "wrong-peer-gid":
			expected.PeerGID++
		case "unenrolled-subject":
			expected.AgentID += "-other"
		case "disabled-enrollment":
			expected.Enabled = false
		case "wrong-key":
			expected.AgentKey = call.Enrollment.AgentKey
			other, e := base64.RawURLEncoding.Strict().DecodeString(expected.AgentKey)
			if e != nil || len(other) != ed25519.PublicKeySize || bytes.Equal(other, r.AgentKey) {
				return errors.New("the substituted enrollment key differs")
			}
		}
		if !reflect.DeepEqual(expected, call.Enrollment) {
			return errors.New("the enrollment negative input differs")
		}
		if name == "body-substitution" {
			if string(call.Body) != "substituted-body" || claims.BodyDigest != requestproof.Digest(nil) {
				return errors.New("the substituted enrollment body differs")
			}
		} else if len(call.Body) != 0 || claims.BodyDigest != requestproof.Digest(nil) {
			return errors.New("the enrollment proof body differs")
		}
		if index == 0 {
			if call.Status != 200 {
				return errors.New("the enrolled proof did not reach the journal route")
			}
			var actual nodeapi.GenerationResponse
			if err = lifecycle.DecodeTransport(bytes.NewReader(call.Response), &actual); err != nil {
				return err
			}
			expected := nodeapi.GenerationResponse{Protocol: "agentgate.agent-generation.v1", AgentID: baseline.AgentID, NodeID: request.Binding.NodeID, BootID: request.Binding.BootID, Generation: 0}
			if actual != expected {
				return errors.New("the authenticated journal readback differs")
			}
		} else {
			code := "node_enrollment_denied"
			switch name {
			case "proof-replay":
				code = "node_proof_rejected"
				if call.Token != r.Calls[0].Token {
					return errors.New("the proof replay token differs")
				}
			case "wrong-key", "body-substitution":
				code = "node_proof_invalid"
			}
			var response struct {
				Error struct{ Code, Message string }
			}
			if err = json.Unmarshal(call.Response, &response); err != nil || call.Status != 401 || response.Error.Code != code || response.Error.Message != code {
				return fmt.Errorf("the %s enrollment denial differs", name)
			}
		}
		if index != 1 && nonces[claims.Nonce] {
			return errors.New("an unrelated enrollment case reused a nonce")
		}
		nonces[claims.Nonce] = true
	}
	return nil
}

func (a *serviceIdentity) Verify(request qualification.Request, result qualification.Result) ([]qualification.Coverage, error) {
	r, err := serviceResult(request, result)
	if err != nil {
		return nil, err
	}
	if err = verifyIdentity(request, r); err != nil {
		return nil, err
	}
	if err = verifyEnrollment(request, result, r.Enrollment); err != nil {
		return nil, err
	}
	if err = verifyServiceRuntimes(request, result, r.Enrollment); err != nil {
		return nil, err
	}
	receipt := digestBytes(result.Raw)
	// Complete identity admission still requires current qualification. No lifecycle, audit or process case follows from a
	// signature or journal probe.
	return []qualification.Coverage{
		{CapabilityID: "identity.job.v1", ContractVersion: qualification.ContractVersion, Cases: []string{"wrong-job-denied", "wrong-policy-denied", "wrong-node-denied", "wrong-boot-denied", "generation-replay-denied", "unknown-revocation-denied"}, ReceiptSHA256: receipt},
		{CapabilityID: "identity.local-enrollment.v1", ContractVersion: qualification.ContractVersion, Cases: []string{"enrolled-proof-accepted", "unenrolled-subject-denied", "wrong-peer-uid-denied", "proof-replay-denied", "body-substitution-denied", "key-role-reuse-denied"}, ReceiptSHA256: receipt},
	}, nil
}

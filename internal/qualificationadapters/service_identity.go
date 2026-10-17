// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodebackend"
	"alloyium.local/kernel-poc/internal/noderuntime"
	"alloyium.local/kernel-poc/internal/qualification"
)

// Identity qualification cannot assume its own future admission report. This
// provider deliberately leaves qualification unavailable. Only preceding actual
// negative checks can contribute partial coverage.
type serviceGrantTrust struct{ binding lifecycle.Binding }

func (s serviceGrantTrust) VerifyEnrollment(_ context.Context, b lifecycle.Binding) error {
	if b.AgentID != s.binding.AgentID || b.AgentKey != s.binding.AgentKey || b.NodeID != s.binding.NodeID || b.BootID != s.binding.BootID {
		return errors.New("the fixture enrollment differs")
	}
	return nil
}
func (serviceGrantTrust) Current(context.Context, lifecycle.Binding) (jobgrant.Snapshot, error) {
	return jobgrant.Snapshot{}, errors.New("qualification is unavailable until actual complete contracts pass")
}
func (serviceGrantTrust) State(context.Context, string) (jobgrant.RevocationState, error) {
	return jobgrant.RevocationState{Known: false}, nil
}
func (serviceGrantTrust) Now() (time.Time, uint64, error) {
	mono, err := (lifecycle.MonotonicClock{}).NowNS()
	return time.Now(), mono, err
}

func (a *serviceIdentity) runIdentity(ctx context.Context, request qualification.Request, path string, r *serviceReceipt) error {
	authority, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	defer clear(private)
	agent, agentPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	clear(agentPrivate)
	r.AuthorityKey, r.AgentKey = authority, agent
	node, nodePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	clear(nodePrivate)
	r.NodeKey = node
	nodes := map[string]ed25519.PublicKey{"qualification-node/one": node}
	authorities := map[string]ed25519.PublicKey{"qualification-authority/one": authority}
	for _, item := range []struct {
		name string
		key  ed25519.PublicKey
	}{{"separate-agent-key", agent}, {"node-role-reuse", node}, {"authority-role-reuse", authority}} {
		encoded := base64.RawURLEncoding.EncodeToString(item.key)
		outcome := noderuntime.VerifyAgentKeyRoles(encoded, nodes, authorities)
		r.KeyRoles = append(r.KeyRoles, serviceCall{Name: item.name, Input: serviceJSON(encoded), Error: serviceError(outcome), MonoNS: serviceMono()})
	}
	mono, err := (lifecycle.MonotonicClock{}).NowNS()
	if err != nil {
		return err
	}
	if request.Document.Lifecycle == nil || request.Document.Lifecycle.DurationSeconds == 0 {
		return errors.New("the service grant requires a bounded lifecycle")
	}
	duration := time.Duration(request.Document.Lifecycle.DurationSeconds) * time.Second
	if duration > 5*time.Second {
		duration = 5 * time.Second
	}
	now := time.Now().Unix()
	b := lifecycle.Binding{AgentID: "qualification-agent", AgentKey: base64.RawURLEncoding.EncodeToString(agent), JobDigest: digestJSON(request.Binding), GrantID: "qualification-grant", RunID: "qualification-run", NodeID: request.Binding.NodeID, BootID: request.Binding.BootID, PolicyDigest: request.Binding.PolicyDigest, SchemaDigest: request.Binding.SchemaDigest, CompilerDigest: nodebackend.CompilerDigest(request.Binding.ArtifactDigests["node"]), ArtifactDigests: request.Binding.ArtifactDigests, CgroupID: 1, Generation: 1, DeadlineNS: mono + uint64(duration)}
	claims := jobgrant.Claims{Binding: b, DocumentDigest: b.PolicyDigest, RequiredCapabilities: request.Document.RequiredCapabilities, QualificationDigest: digestJSON(request), AuditHeaderDigest: digestJSON(request.Contracts), IssuedAt: now, NotBefore: now, ExpiresAt: now + int64(duration/time.Second), IssuedMonoNS: mono, DeadlineNS: b.DeadlineNS}
	envelope, err := jobgrant.Sign("qualification-authority", "one", private, claims, request.Document)
	if err != nil {
		return err
	}
	r.Grant, r.SignedClaims = serviceJSON(envelope), serviceJSON(claims)
	grant, err := jobgrant.Encode(envelope)
	if err != nil {
		return err
	}
	document, err := request.Document.Canonical()
	if err != nil {
		return err
	}
	auth := lifecycle.Authorization{Binding: b, Grant: grant, Document: document, RequiredCapabilities: request.Document.RequiredCapabilities}
	r.Authorization = serviceJSON(auth)
	keys := map[string]ed25519.PublicKey{"qualification-authority/one": authority}
	_, err = jobgrant.VerifySigned(envelope, keys, request.Document)
	r.Calls = append(r.Calls, serviceCall{Name: "valid-signature", Error: serviceError(err), MonoNS: serviceMono()})
	if err != nil {
		return err
	}
	trust := serviceGrantTrust{binding: b}
	verifier, err := jobgrant.NewVerifier(jobgrant.Config{Authorities: keys, Enrollment: trust, Qualification: trust, Revocation: trust, Clock: trust, MaxLifetime: time.Minute})
	if err != nil {
		return err
	}
	for _, name := range []string{"wrong-job", "wrong-policy", "wrong-node", "wrong-boot", "wrong-agent", "wrong-agent-key", "wrong-generation", "wrong-artifact", "unknown-revocation"} {
		changed, err := changedServiceAuthorization(auth, name)
		if err != nil {
			return err
		}
		if name == "wrong-agent-key" {
			changed.Binding.AgentKey = base64.RawURLEncoding.EncodeToString(authority)
		}

		outcome := verifier.Verify(ctx, changed)
		r.Calls = append(r.Calls, serviceCall{Name: name, Input: serviceJSON(changed), Error: serviceError(outcome), MonoNS: serviceMono()})
	}
	journal, err := lifecycle.OpenJournal(path)
	if err != nil {
		return err
	}
	record := lifecycle.Record{Binding: b, State: "preparing", Revision: 1, PreparationDeadlineNS: b.DeadlineNS}
	record.Binding.CgroupID = 0
	err = journal.Save(ctx, record, 0)
	r.Calls = append(r.Calls, serviceCall{Name: "reserve-generation", Input: serviceJSON(record), Error: serviceError(err), MonoNS: serviceMono()})
	if closeErr := journal.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	journal, err = lifecycle.OpenJournal(path)
	if err != nil {
		return err
	}
	defer journal.Close()
	record.Binding.RunID += "-replay"
	err = journal.Save(ctx, record, 0)
	r.Calls = append(r.Calls, serviceCall{Name: "generation-replay-after-reopen", Input: serviceJSON(record), Error: serviceError(err), MonoNS: serviceMono()})
	if !errors.Is(err, lifecycle.ErrReplay) {
		return errors.New("the durable generation replay gate did not reject")
	}
	r.GenerationFloor, err = journal.GenerationFloor(ctx, b.AgentID, b.NodeID, b.BootID)
	if err != nil {
		return err
	}
	records, err := journal.Load(ctx)
	r.JournalRecords = serviceJSON(records)
	return err
}

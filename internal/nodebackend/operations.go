// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"time"
)

type GenerationStore interface {
	GenerationFloor(context.Context, string, string, string) (uint64, error)
}
type OperationsConfig struct {
	Backend          *Backend
	Manager          *lifecycle.Manager
	Generations      GenerationStore
	Target           func(context.Context) (policy.VerifiedTarget, error)
	PreparationLease time.Duration
}
type Operations struct{ config OperationsConfig }

func NewOperations(c OperationsConfig) (*Operations, error) {
	if c.Backend != nil && c.Backend.fixture != nil {
		return nil, errors.New("qualification fixture backends have no admission routes")
	}
	if c.Backend == nil || c.Manager == nil || c.Generations == nil || c.Target == nil || c.PreparationLease <= 0 || c.PreparationLease > 30*time.Second {
		return nil, errors.New("the node operations require guarded lifecycle and current target state")
	}
	return &Operations{config: c}, nil
}
func (o *Operations) Target(ctx context.Context) (policy.VerifiedTarget, error) {
	if !o.config.Manager.Ready() {
		return policy.VerifiedTarget{}, errors.New("the node lifecycle is unavailable")
	}
	return o.config.Target(ctx)
}
func (o *Operations) GenerationFloor(ctx context.Context, agent string) (uint64, error) {
	b := o.config.Backend
	return o.config.Generations.GenerationFloor(ctx, agent, b.config.Domain.NodeID, b.config.Domain.Proof.BootID)
}
func latest(record lifecycle.Record) (lifecycle.Evidence, error) {
	if len(record.Evidence) == 0 {
		return lifecycle.Evidence{}, errors.New("the durable phase evidence is absent")
	}
	return record.Evidence[len(record.Evidence)-1], nil
}
func (o *Operations) Prepare(ctx context.Context, request lifecycle.PrepareRequest) (out lifecycle.PrepareResponse, err error) {
	if err = request.Validate(); err != nil {
		return out, err
	}
	if err = o.config.Backend.verifyRuntime(ctx, request.Binding, request.Manifest); err != nil {
		return out, err
	}
	if err = jobartifacts.VerifyExecutable(request.Manifest.Executable, request.Manifest.ExecutableDigest); err != nil {
		return out, err
	}
	record, err := o.config.Manager.PrepareFor(ctx, request.Binding, o.config.PreparationLease)
	if err != nil {
		return out, err
	}
	defer func() {
		if err != nil {
			_, _ = o.config.Manager.Stop(context.WithoutCancel(ctx), record.Binding.RunID, "prepare-response-failed")
		}
	}()
	r, err := o.config.Backend.get(record.Binding.RunID)
	if err != nil {
		return out, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !reflect.DeepEqual(r.document.RequiredCapabilities, request.RequiredCapabilities) {
		return out, errors.New("the requested capabilities differ from the immutable document")
	}
	e, err := latest(record)
	if err != nil {
		return out, err
	}
	mono, err := o.config.Backend.config.Clock.NowNS()
	if err != nil {
		return out, err
	}
	out = lifecycle.PrepareResponse{PreparationKeyID: o.config.Backend.config.Signer.KeyID(), PreparedAtUnix: time.Now().Unix(), PreparedMonoNS: mono, Protocol: lifecycle.PreparedProtocol, Binding: copyValue(record.Binding), ManifestDigest: record.Binding.JobDigest, PreparationDeadlineNS: record.PreparationDeadlineNS, Evidence: e, AuditHeader: append([]byte{}, r.headerBytes...), AuditHeaderDigest: r.headerDigest}
	raw, err := lifecycle.PrepareSigningBytes(out)
	if err != nil {
		return out, err
	}
	signature, err := o.config.Backend.config.Signer.Sign(ctx, raw)
	if err != nil {
		return out, err
	}
	out.PreparationSignature = base64.RawURLEncoding.EncodeToString(signature)
	if _, err = lifecycle.VerifyPrepared(out, o.config.Backend.config.NodeKeys, request.Binding, time.Now().Unix(), time.Second); err != nil {
		return out, err
	}
	return out, nil
}
func (o *Operations) Run(ctx context.Context, request lifecycle.RunRequest) (out lifecycle.Terminal, err error) {
	if err = request.Validate(); err != nil {
		return out, err
	}
	id := request.Authorization.Binding.RunID
	record, ok := o.config.Manager.Record(id)
	if !ok || record.State != "quarantined" || !reflect.DeepEqual(record.Binding, request.Authorization.Binding) {
		return out, errors.New("the signed run has no exact prepared reservation")
	}
	reason := "run-failed"
	defer func() {
		if err != nil {
			_, stopErr := o.config.Manager.Stop(context.WithoutCancel(ctx), id, reason)
			err = errors.Join(err, stopErr)
		}
	}()
	p, err := o.config.Backend.Stage(ctx, request.Authorization, request.Manifest, request.Input)
	if err != nil {
		return out, err
	}
	if _, err = o.config.Manager.Place(ctx, id, p); err != nil {
		return out, err
	}
	if _, err = o.config.Manager.Install(ctx, id, request.Authorization); err != nil {
		return out, err
	}
	if _, err = o.config.Manager.Release(ctx, id); err != nil {
		return out, err
	}
	_, waitErr := o.config.Backend.Wait(ctx, request.Authorization.Binding)
	// An independent stop can persist the terminal and evict kernel buffers
	// before Wait returns. Manager.Stop serializes with that durable transition.
	r, _ := o.config.Backend.get(id)
	reason = stopReasonAfterWait(ctx.Err(), waitErr, r)
	stopped, err := o.config.Manager.Stop(context.WithoutCancel(ctx), id, reason)
	if err != nil {
		return out, err
	}
	e, err := latest(stopped)
	if err != nil {
		return out, err
	}
	out, err = o.config.Backend.Terminal(context.WithoutCancel(ctx), stopped.Binding, e.Digest)
	if err != nil {
		return out, err
	}
	if out.EvidenceVerdict != "VALID_COMPLETE" {
		return out, errors.New("the full terminal audit is incomplete")
	}
	return out, nil
}
func (o *Operations) Status(ctx context.Context, agent, id string) (lifecycle.JobStatus, error) {
	if err := ctx.Err(); err != nil {
		return lifecycle.JobStatus{}, err
	}
	record, ok := o.config.Manager.Record(id)
	if !ok || record.Binding.AgentID != agent {
		return lifecycle.JobStatus{}, errors.New("the node job status is unavailable")
	}
	out := lifecycle.JobStatus{Protocol: "agentgate.job.status.v1", Record: record}
	if record.State == "stopped" {
		e, err := latest(record)
		if err != nil {
			return out, err
		}
		terminal, err := o.config.Backend.Terminal(ctx, record.Binding, e.Digest)
		if err != nil {
			return out, err
		}
		out.Terminal = &terminal
	}
	return out, nil
}
func (o *Operations) Stop(ctx context.Context, request lifecycle.StopRequest) (lifecycle.StopResponse, error) {
	record, ok := o.config.Manager.Record(request.Binding.RunID)
	if !ok || !sameQuery(record.Binding, request.Binding) {
		return lifecycle.StopResponse{}, errors.New("the stop request binding differs")
	}
	record, err := o.config.Manager.Stop(ctx, request.Binding.RunID, request.Reason)
	if err != nil {
		return lifecycle.StopResponse{}, err
	}
	e, err := latest(record)
	if err != nil {
		return lifecycle.StopResponse{}, err
	}
	return lifecycle.StopResponse{Protocol: lifecycle.StoppedProtocol, Binding: record.Binding, Evidence: e}, nil
}

var _ nodeapi.NodeOperations = (*Operations)(nil)

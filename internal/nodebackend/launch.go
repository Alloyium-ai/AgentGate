// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/dnslease"
	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/execbroker"
	"alloyium.local/kernel-poc/internal/jobartifacts"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/nodedns"
	"context"
	"errors"
	"path/filepath"
	"reflect"
	"time"
)

func needsDNS(r *run) bool {
	if r.document.Network == nil {
		return false
	}
	for _, rule := range r.document.Network.Rules {
		if rule.Destination.Kind == "hostname" {
			return true
		}
	}
	return false
}
func (b *Backend) compile(ctx context.Context, r *run) (enforcement.Plan, error) {
	now, err := b.config.Clock.NowNS()
	if err != nil {
		return enforcement.Plan{}, err
	}
	if !needsDNS(r) {
		if needsCredentials(r.document) {
			return enforcement.CompileForTarget(r.document, r.binding.CgroupID, r.binding.Generation, now, r.deadline(), nil, r.qualification.Target, time.Now().Unix())
		}
		return enforcement.Compile(r.document, r.binding.CgroupID, r.binding.Generation, now, r.deadline(), nil)
	}
	if b.config.Resolver == nil {
		return enforcement.Plan{}, errors.New("the hostname policy requires a pinned node resolver")
	}
	binding := dnslease.Binding{JobID: r.binding.JobDigest, DomainID: r.binding.CgroupID, Generation: r.binding.Generation, DeadlineNS: r.deadline(), PolicySHA256: r.binding.PolicyDigest}
	r.dns, err = nodedns.New(nodedns.Config{Binding: binding, Network: *r.document.Network, Resolver: b.config.Resolver, Now: b.config.Clock.NowNS})
	if err != nil {
		return enforcement.Plan{}, err
	}
	r.dnsInitial, err = r.dns.ResolveAll(ctx)
	if err != nil {
		return enforcement.Plan{}, err
	}
	if needsCredentials(r.document) {
		return enforcement.CompileResolvedForTarget(r.document, binding, now, r.dnsInitial, b.config.Resolver.Evidence(), r.qualification.Target, time.Now().Unix())
	}
	return enforcement.CompileResolved(r.document, binding, now, r.dnsInitial, b.config.Resolver.Evidence())
}

// Stage starts only the measured helper. The helper remains stopped until the
// manager verifies authorization, placement, installation and watchdog custody.
func (b *Backend) Stage(ctx context.Context, a lifecycle.Authorization, m lifecycle.Manifest, input []byte) (p lifecycle.HeldProcess, err error) {
	if err = (lifecycle.RunRequest{Protocol: lifecycle.RunProtocol, Authorization: a, Manifest: m, Input: input}).Validate(); err != nil {
		return p, err
	}
	if err = b.verifyRuntime(ctx, a.Binding, m); err != nil {
		return p, err
	}
	if err = b.config.Verifier.Verify(ctx, a); err != nil {
		return p, err
	}
	r, err := b.get(a.Binding.RunID)
	if err != nil {
		return p, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.phase != "prepared" || !reflect.DeepEqual(a.Binding, r.binding) {
		return p, errors.New("the prepared run differs from the signed job")
	}
	if err = b.qualification(ctx, r); err != nil {
		return p, err
	}
	if err = r.collectors.healthy(); err != nil {
		return p, err
	}
	var grant jobgrant.Envelope
	if b.fixture != nil && b.fixture.Purpose() == lifecycle.QualificationVersionPurpose {
		grant, err = jobgrant.DecodeQualificationVersion(a.Grant)
	} else {
		grant, err = jobgrant.Decode(a.Grant)
	}
	if err != nil {
		return p, err
	}
	if grant.Claims.AuditHeaderDigest != r.headerDigest {
		return p, errors.New("the signed audit header differs")
	}
	if err = r.writer.AttachGrant(ctx, grant); err != nil {
		return p, err
	}
	if err = b.bindGrantExpiry(ctx, r, grant.Claims); err != nil {
		return p, err
	}
	if err = jobartifacts.VerifyExecutable(m.Executable, m.ExecutableDigest); err != nil {
		return p, err
	}
	measurement, measureErr := b.measureRuntime(ctx, a.Binding, m)
	if measureErr != nil {
		return p, measureErr
	}
	if err = r.control(ctx, "runtime_files_verified", nodecontrol.RuntimeFiles{Manifest: m, Measurement: measurement}); err != nil {
		return p, err
	}
	observer, readErr := b.observerReadback(r)
	if readErr != nil {
		return p, readErr
	}
	if err = r.control(ctx, "observer_binding_readback", observer); err != nil {
		return p, err
	}
	if r.streams, err = b.artifacts.Prepare(r.binding, m.InputDigest, input); err != nil {
		return p, err
	}
	if r.plan, err = b.compile(ctx, r); err != nil {
		return p, err
	}
	if err = r.plan.ValidateChildBootstrap(b.config.ArtifactDigests["held-helper"]); err != nil {
		return p, err
	}
	r.manifest = copyValue(m)
	owned := copyValue(a)
	r.authorization = &owned
	if err = b.prepareCredentials(ctx, r, a, m); err != nil {
		return p, err
	}
	r.phase = "staging"
	defer func() {
		if err != nil && r.child != nil {
			_ = r.child.Close()
		}
	}()
	if r.child, err = b.startChild(ctx, r, m); err != nil {
		return p, err
	}
	p = r.child.Held.Process()
	if err = r.retainChildFrames(ctx, b.config.ArtifactDigests["held-helper"]); err != nil {
		return p, err
	}
	r.phase = "held"
	if err = r.control(ctx, "held", p); err != nil {
		return p, err
	}
	return p, nil
}
func (b *Backend) Place(ctx context.Context, binding lifecycle.Binding, p lifecycle.HeldProcess) (lifecycle.Evidence, error) {
	r, err := b.get(binding.RunID)
	if err != nil {
		return lifecycle.Evidence{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.phase != "held" || !reflect.DeepEqual(r.binding, binding) {
		return lifecycle.Evidence{}, errors.New("the held run phase differs")
	}
	placement, err := b.domains.PlaceHeld(ctx, binding, p)
	if err != nil {
		return lifecycle.Evidence{}, err
	}
	r.phase = "placed"
	if err = r.control(ctx, "placed", placement); err != nil {
		return lifecycle.Evidence{}, err
	}
	return b.evidence(r, r.phase, &p, false)
}
func (b *Backend) Install(ctx context.Context, a lifecycle.Authorization) (lifecycle.Evidence, error) {
	if err := b.config.Verifier.Verify(ctx, a); err != nil {
		return lifecycle.Evidence{}, err
	}
	r, err := b.get(a.Binding.RunID)
	if err != nil {
		return lifecycle.Evidence{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.phase != "placed" || !reflect.DeepEqual(a.Binding, r.binding) || !reflect.DeepEqual(r.authorization, &a) {
		return lifecycle.Evidence{}, errors.New("the placed authorization differs")
	}
	p := r.child.Held.Process()
	verify := func() error { return b.VerifyHeld(ctx, r.binding, p) }
	if err = r.collectors.healthy(); err != nil {
		return lifecycle.Evidence{}, err
	}
	if err = r.group.Install(r.plan, verify); err != nil {
		return lifecycle.Evidence{}, err
	}
	if err = r.group.BindBootstrap(ctx, r.plan, r.child.Held, time.Duration(r.document.Runtime.Bootstrap.MaxHoldSeconds)*time.Second); err != nil {
		return lifecycle.Evidence{}, err
	}
	config, err := r.group.ExecBrokerConfig(r.plan, r.binding.BootID)
	if err != nil {
		return lifecycle.Evidence{}, err
	}
	r.brokerAudit = filepath.Join(b.config.AuditRoot, r.reservation.Name+".broker")
	r.brokerDiagnostic = r.brokerAudit + ".stderr"
	audit, err := privateLog(b.config.AuditRoot, filepath.Base(r.brokerAudit))
	if err != nil {
		return lifecycle.Evidence{}, err
	}
	defer audit.Close()
	diagnostic, err := privateLog(b.config.AuditRoot, filepath.Base(r.brokerDiagnostic))
	if err != nil {
		return lifecycle.Evidence{}, err
	}
	defer diagnostic.Close()
	if r.broker, err = execbroker.Start(ctx, b.config.Broker, b.config.ArtifactDigests["exec-broker"], r.child.Listener, audit, diagnostic, config); err != nil {
		return lifecycle.Evidence{}, err
	}
	if err = r.child.Listener.Close(); err != nil {
		return lifecycle.Evidence{}, err
	}
	r.child.Listener = nil
	readback, err := r.group.ReadInstalled(r.plan)
	if err != nil {
		return lifecycle.Evidence{}, err
	}
	if err = r.control(ctx, "installed_readback", readback); err != nil {
		return lifecycle.Evidence{}, err
	}
	r.phase = "installed"
	if err = r.control(ctx, "installed", struct{ Plan, Broker string }{r.plan.Digest(), digest(config)}); err != nil {
		return lifecycle.Evidence{}, err
	}
	return b.evidence(r, r.phase, &p, false)
}
func (b *Backend) Release(ctx context.Context, binding lifecycle.Binding) (lifecycle.Evidence, error) {
	r, err := b.get(binding.RunID)
	if err != nil {
		return lifecycle.Evidence{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.phase != "installed" || !reflect.DeepEqual(r.binding, binding) || r.authorization == nil || r.broker == nil {
		return lifecycle.Evidence{}, errors.New("the installed release custody differs")
	}
	if err = b.config.Verifier.Verify(ctx, *r.authorization); err != nil {
		return lifecycle.Evidence{}, err
	}
	if err = b.qualification(ctx, r); err != nil {
		return lifecycle.Evidence{}, err
	}
	if err = r.collectors.healthy(); err != nil {
		return lifecycle.Evidence{}, err
	}
	if _, err = r.group.VerifyInstalled(r.plan); err != nil {
		return lifecycle.Evidence{}, err
	}
	select {
	case <-r.broker.Done():
		return lifecycle.Evidence{}, errors.New("the exec broker stopped before release")
	default:
	}
	p := r.child.Held.Process()
	if err = r.control(ctx, "release_intent", p); err != nil {
		return lifecycle.Evidence{}, err
	}
	if r.dns != nil {
		publisher, e := r.group.DNSPublisher(r.plan, func(c context.Context, p enforcement.DNSPublication) error { return r.control(c, "dns_"+p.Phase, p) })
		if e != nil {
			return lifecycle.Evidence{}, e
		}
		if e = publisher.Activate(ctx, r.dnsInitial.Binding(), r.dnsInitial); e != nil {
			return lifecycle.Evidence{}, e
		}
		dnsCtx, cancel := context.WithCancel(context.Background())
		r.dnsCancel = cancel
		r.dnsDone = make(chan error, 1)
		go func() { r.dnsDone <- r.dns.Run(dnsCtx, publisher, r.dnsInitial) }()
	}
	if err = r.child.Held.Release(ctx); err != nil {
		return lifecycle.Evidence{}, err
	}
	r.phase = "released"
	return b.evidence(r, r.phase, &p, false)
}

// Wait monitors the helper, broker and loss detector. Every result requires the
// caller to stop the complete domain before it publishes a terminal response.
func (b *Backend) Wait(ctx context.Context, binding lifecycle.Binding) (int, error) {
	r, err := b.get(binding.RunID)
	if err != nil {
		return -1, err
	}
	r.mu.Lock()
	if r.phase != "released" || !reflect.DeepEqual(binding, r.binding) {
		r.mu.Unlock()
		return -1, errors.New("the released job binding differs")
	}
	child, broker, collect, dnsDone := r.child, r.broker, r.collectors, r.dnsDone
	deadline := r.deadline()
	r.mu.Unlock()
	now, err := b.config.Clock.NowNS()
	if err != nil {
		return -1, err
	}
	if now >= deadline {
		return -1, kernelExpired{}
	}
	cutoff := time.NewTimer(time.Duration(deadline - now))
	defer cutoff.Stop()
	done := make(chan error, 1)
	go func() { done <- child.Held.Wait(context.Background()) }()
	select {
	case err = <-done:
		return saveChildExit(r, err), err
	case <-ctx.Done():
		return -1, ctx.Err()
	case <-cutoff.C:
		return -1, kernelExpired{}
	case <-broker.Done():
		var reaped bool
		err, reaped = brokerExitResult(ctx, child.Held.Exited, done)
		if !reaped {
			return -1, err
		}
		return saveChildExit(r, err), err
	case err = <-collect.fault:
		return -1, err
	case err = <-dnsDone:
		r.mu.Lock()
		r.dnsConsumed = true
		r.dnsResult = err
		r.mu.Unlock()
		return -1, errors.Join(errors.New("the trusted DNS coordinator stopped"), err)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/domainstore"
	"alloyium.local/kernel-poc/internal/execbroker"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

func sameQuery(actual, query lifecycle.Binding) bool {
	if query.CgroupID == 0 {
		actual.CgroupID = 0
	}
	return reflect.DeepEqual(actual, query)
}
func (b *Backend) oldBoot(binding lifecycle.Binding) (lifecycle.Evidence, error) {
	if binding.Validate(binding.CgroupID == 0) != nil || binding.NodeID != b.config.Domain.NodeID || binding.BootID == b.config.Domain.Proof.BootID {
		return lifecycle.Evidence{}, errors.New("an authenticated old boot binding is required")
	}
	raw, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return lifecycle.Evidence{}, err
	}
	if strings.TrimSpace(string(raw)) != b.config.Domain.Proof.BootID {
		return lifecycle.Evidence{}, errors.New("the current boot readback differs")
	}
	e := lifecycle.Evidence{Binding: copyValue(binding), Phase: "stopped", Terminated: true, Empty: true, NoDomain: true, RightsRemoved: true, ReadbackDigest: digest(struct {
		Old     lifecycle.Binding
		Current domainstore.RootProof
	}{binding, b.config.Domain.Proof})}
	e.Digest = lifecycle.EvidenceDigest(e)
	return e, nil
}
func readBroker(path string, binding lifecycle.Binding, emit func(execbroker.Decision) error) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != 0 || st.Nlink != 1 || st.Mode&077 != 0 || st.Size > 4<<20 {
		return errors.New("the broker audit custody differs")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 4<<20))
	scanner.Buffer(make([]byte, 4096), 65536)
	var prior uint64
	count := 0
	for scanner.Scan() {
		var d execbroker.Decision
		if err = lifecycle.DecodeTransport(strings.NewReader(scanner.Text()), &d); err != nil {
			return err
		}
		if d.Protocol != "agentgate.exec-decision.v1" || d.Domain != binding.CgroupID || d.Generation != binding.Generation || d.NotificationID == 0 || d.MonotonicNS < prior || d.MonotonicNS >= binding.DeadlineNS && d.Continued {
			return errors.New("the exec broker audit binding differs")
		}
		prior = d.MonotonicNS
		count++
		if count > 4096 {
			return errors.New("the broker audit record bound is exceeded")
		}
		if err = emit(d); err != nil {
			return err
		}
	}
	return scanner.Err()
}
func terminalState(reason string, exit int) string {
	switch reason {
	case "grant-expired", "preparation-expired":
		return "expired"
	case "revoked":
		return "revoked"
	case "cancelled", "client-stop":
		return "cancelled"
	case "completed":
		if exit == 0 {
			return "completed"
		}
		return "failed"
	default:
		return "aborted"
	}
}

// Stop always attempts whole-domain termination before it removes a right. Audit
// failure prevents VALID_COMPLETE; it does not prevent verified rights cleanup.
func (b *Backend) Stop(ctx context.Context, binding lifecycle.Binding, reason string) (out lifecycle.Evidence, err error) {
	var trace *stopTrace
	if b.fixture != nil {
		trace = newStopTrace(b.config.Clock, os.Stderr, binding.RunID)
	}
	defer func() { trace.phase("stop-return", err) }()
	defer func() {
		if err != nil && b.fixture != nil {
			message := err.Error()
			if len(message) > 512 {
				message = message[:512]
			}
			fmt.Fprintln(os.Stderr, "qualification fixture stop: "+message)
		}
	}()
	if binding.BootID != b.config.Domain.Proof.BootID {
		e, oldErr := b.oldBoot(binding)
		if oldErr != nil {
			return e, oldErr
		}
		return b.persistRecovered(ctx, e, reason)
	}
	r, getErr := b.get(binding.RunID)
	if getErr != nil {
		return b.stopRecovered(ctx, binding, reason)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	trace.phase("run-lock", nil)
	if !sameQuery(r.binding, binding) {
		return out, errors.New("the stop binding differs")
	}
	if r.stopped != nil {
		if r.terminal == nil {
			return out, errors.New("the stopped run has no terminal record")
		}
		if err = b.persistTerminal(r, *r.terminal); err != nil {
			return *r.stopped, err
		}
		b.evict(r)
		return copyValue(*r.stopped), nil
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), b.config.Domain.StopTimeout)
	defer cancel()
	var safety []error
	var auditErrors []error
	stopped, stopErr := b.domains.StopReservation(cleanup, r.binding, reason)
	trace.phase("domain-stop", stopErr)
	if stopped.Reservation.Binding.RunID != "" {
		r.binding = stopped.Reservation.Binding
		r.reservation = stopped.Reservation
	}
	if r.child != nil {
		e := r.child.Close()
		trace.phase("child-close", e)
		if e != nil {
			safety = append(safety, e)
		}
	}
	if r.broker != nil {
		e := r.broker.Close()
		trace.phase("broker-close", e)
		if e != nil {
			safety = append(safety, e)
		}
	}
	trace.phase("process-close", errors.Join(safety...))
	if !stopped.Empty {
		return out, errors.Join(stopErr, errors.Join(safety...), errors.New("whole-domain termination is unconfirmed"))
	}
	if len(safety) != 0 {
		return out, errors.Join(safety...)
	}
	if r.writer != nil && len(stopped.Reservation.TerminationEvents) > 0 {
		proof := nodecontrol.DomainEmpty{Events: stopped.Reservation.TerminationEvents, ReadbackDigest: stopped.Reservation.TerminationReadback, ObservedMonoNS: stopped.Reservation.TerminationMonoNS}
		if e := r.control(cleanup, "domain_empty_readback", proof); e != nil {
			auditErrors = append(auditErrors, e)
		}
	}
	if r.dnsCancel != nil {
		r.dnsCancel()
		if r.dnsConsumed {
			auditErrors = append(auditErrors, nonCancellationErrors(r.dnsResult)...)
		} else {
			select {
			case e := <-r.dnsDone:
				auditErrors = append(auditErrors, nonCancellationErrors(e)...)
			case <-cleanup.Done():
				return out, cleanup.Err()
			}
		}
	}
	trace.phase("termination-evidence", nil)
	available := stopped.CountersAvailable
	var decisions, lost uint64
	if stopped.DomainEvidence != nil {
		decisions = stopped.DomainEvidence.Decisions
		lost = stopped.DomainEvidence.Lost
	}
	if r.collectors != nil {
		_, e := r.collectors.finish(cleanup, r.collectCancel)
		trace.phase("readers-finish", e)
		if e != nil {
			auditErrors = append(auditErrors, e)
			if cleanup.Err() != nil {
				return out, errors.Join(e, errors.New("the audit reader shutdown is unconfirmed; owned pins remain"))
			}
		}
	} else {
		available = false
	}
	if stopErr != nil {
		auditErrors = append(auditErrors, stopErr)
	}
	if r.writer != nil && r.brokerAudit != "" {
		if e := readBroker(r.brokerAudit, r.binding, func(d execbroker.Decision) error { return r.control(cleanup, "exec_decision", d) }); e != nil {
			auditErrors = append(auditErrors, e)
		}
	}
	trace.phase("broker-audit", nil)
	if r.group != nil {
		e := r.group.Close()
		trace.phase("resource-close", e)
		if e != nil {
			return out, e
		}
	}
	if r.observation != nil {
		e := r.observation.Close()
		trace.phase("observation-close", e)
		if e != nil {
			return out, e
		}
	}
	if r.binding.CgroupID != 0 {
		err = b.pins.cleanupPins(cleanup, r.binding)
		trace.phase("pin-cleanup", err)
		if err != nil {
			return out, err
		}
		if r.credentials != nil {
			e := lifecycle.Evidence{Binding: copyValue(r.binding), Phase: "stopped", Terminated: true, Empty: true, RightsRemoved: true, ReadbackDigest: stopped.ReadbackDigest}
			if e.ReadbackDigest == "" {
				e.ReadbackDigest = digest(stopped)
			}
			e.Digest = lifecycle.EvidenceDigest(e)
			if err = r.credentials.Close(cleanup, e); err != nil {
				return out, err
			}
			r.credentials = nil
		}
		err = b.domains.ReconcileEmpty(cleanup, r.binding)
		trace.phase("domain-remove", err)
		if err != nil {
			return out, err
		}
	} else if !stopped.NoDomain {
		return out, errors.New("the unallocated stop has no absence proof")
	}
	out = lifecycle.Evidence{Binding: copyValue(r.binding), Phase: "stopped", Terminated: true, Empty: true, NoDomain: stopped.NoDomain, RightsRemoved: true, CountersAvailable: available, Decisions: decisions, Lost: lost, ReadbackDigest: stopped.ReadbackDigest, EffectiveDeadlineNS: r.kernelDeadline}
	if out.ReadbackDigest == "" {
		out.ReadbackDigest = digest(stopped)
	}
	out.Digest = lifecycle.EvidenceDigest(out)
	r.stopped = &out
	r.phase = "stopped"
	var output, diagnostic []byte
	if r.streams.Directory != "" {
		output, diagnostic, err = b.artifacts.Outputs(r.binding)
		if err != nil {
			auditErrors = append(auditErrors, err)
		}
	}
	sum := sha256.Sum256(output)
	outputDigest := hex.EncodeToString(sum[:])
	state := terminalState(reason, r.exitCode)
	terminal := lifecycle.Terminal{Protocol: lifecycle.TerminalProtocol, Binding: copyValue(r.binding), State: state, ExitCode: r.exitCode, DomainEmpty: true, RightsRemoved: true, EvidenceDigest: out.Digest, Output: output, OutputDigest: outputDigest, EvidenceVerdict: "INCOMPLETE"}
	if r.writer != nil {
		if e := r.control(cleanup, "stopped", struct {
			Evidence         lifecycle.Evidence
			DiagnosticDigest string
			Errors           []string
		}{out, digest(diagnostic), errorStrings(auditErrors)}); e != nil {
			auditErrors = append(auditErrors, e)
		}
		if e := r.writer.FinishStream(cleanup, "node", jobaudit.FinalCounters{Sequence: r.controlCount, Available: true}); e != nil {
			auditErrors = append(auditErrors, e)
		}
		if len(auditErrors) == 0 && available && lost == 0 && r.authorization != nil {
			_, e := r.writer.Seal(cleanup, jobaudit.Terminal{State: state, ExitCode: r.exitCode, Empty: true, RightsRemoved: true, OutputDigest: outputDigest, CountersAvailable: true}, b.config.Signer)
			if e == nil {
				receipt, e := b.config.Authority.Countersign(cleanup, r.writer.Export())
				if e == nil {
					e = r.writer.AttachAuthority(cleanup, receipt)
				}
				if e == nil {
					verdict := jobaudit.VerifyOffline(r.writer.Export(), jobaudit.Trust{NodeKeys: b.config.NodeKeys, AuthorityKeys: b.config.AuthorityKeys, Registry: nodecontrol.Registry(b.config.Registry, r.binding), Document: r.document})
					terminal.EvidenceVerdict = verdict.State
				}
			}
		}
		_ = r.writer.Close()
	}
	trace.phase("audit-terminal", errors.Join(auditErrors...))
	if terminal.State == "completed" && terminal.EvidenceVerdict != "VALID_COMPLETE" {
		terminal.State = "aborted"
	}
	r.terminal = &terminal
	err = b.persistTerminal(r, terminal)
	trace.phase("terminal-persist", err)
	if err != nil {
		return out, err
	}
	b.evict(r)
	return out, nil
}
func errorStrings(in []error) []string {
	out := []string{}
	for _, err := range in {
		if err != nil {
			out = append(out, err.Error())
		}
	}
	return out
}
func (b *Backend) stopRecovered(ctx context.Context, binding lifecycle.Binding, reason string) (lifecycle.Evidence, error) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), b.config.Domain.StopTimeout)
	defer cancel()
	result, err := b.domains.StopReservation(cleanup, binding, reason)
	if !result.Empty {
		return lifecycle.Evidence{}, errors.Join(err, errors.New("the recovered domain termination is unconfirmed"))
	}
	actual := result.Reservation.Binding
	if actual.CgroupID != 0 && !result.NoDomain {
		if e := b.pins.cleanupPins(cleanup, actual); e != nil {
			return lifecycle.Evidence{}, e
		}
		if e := b.domains.ReconcileEmpty(cleanup, actual); e != nil {
			return lifecycle.Evidence{}, e
		}
	}
	e := lifecycle.Evidence{Binding: actual, Phase: "stopped", Terminated: true, Empty: true, NoDomain: result.NoDomain, RightsRemoved: true, CountersAvailable: result.CountersAvailable, ReadbackDigest: result.ReadbackDigest}
	if result.DomainEvidence != nil {
		e.Decisions = result.DomainEvidence.Decisions
		e.Lost = result.DomainEvidence.Lost
	}
	if e.ReadbackDigest == "" {
		return e, errors.New("the recovered termination readback is absent")
	}
	e.Digest = lifecycle.EvidenceDigest(e)
	return b.persistRecovered(cleanup, e, reason)
}
func (b *Backend) Recover(ctx context.Context, record lifecycle.Record) (lifecycle.Evidence, error) {
	// A replacement node never resumes an agent whose reader and held-process
	// custody died. The manager must execute its durable stop transition once.
	return lifecycle.Evidence{}, errors.New("the prior node process custody cannot resume")
}

func (b *Backend) persistRecovered(ctx context.Context, evidence lifecycle.Evidence, reason string) (lifecycle.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return evidence, err
	}
	name, err := domainstore.ReservationName(b.config.Domain.Proof.OwnedPrefix, evidence.Binding)
	if err != nil {
		return evidence, err
	}
	path := filepath.Join(b.config.AuditRoot, name+".terminal.json")
	prior, legacy, readErr := readStopRecord(path)
	if readErr == nil {
		if legacy {
			return evidence, errors.New("the legacy terminal lacks recoverable stop evidence")
		}
		if !reflect.DeepEqual(prior.Evidence.Binding, evidence.Binding) {
			return evidence, errors.New("the recovered terminal binding differs")
		}
		if _, err = b.Terminal(ctx, evidence.Binding, prior.Evidence.Digest); err != nil {
			return evidence, err
		}
		return copyValue(prior.Evidence), nil
	}
	if !errors.Is(readErr, os.ErrNotExist) {
		return evidence, readErr
	}
	var output []byte
	if b.artifacts != nil {
		// The domain is empty. Preserve bounded owned output even though the
		// lost reader prevents a complete audit or a recovered exit status.
		output, _, _ = b.artifacts.Outputs(evidence.Binding)
	}
	sum := sha256.Sum256(output)
	state := terminalState(reason, -1)
	if state == "failed" {
		state = "aborted"
	}
	terminal := lifecycle.Terminal{Protocol: lifecycle.TerminalProtocol, Binding: copyValue(evidence.Binding), State: state, ExitCode: -1, DomainEmpty: true, RightsRemoved: true, EvidenceDigest: evidence.Digest, Output: output, OutputDigest: hex.EncodeToString(sum[:]), EvidenceVerdict: "INCOMPLETE"}
	r := &run{binding: copyValue(evidence.Binding), reservation: domainstore.Reservation{Name: name}, stopped: &evidence}
	return evidence, b.persistTerminal(r, terminal)
}

var _ lifecycle.Backend = (*Backend)(nil)
var _ domainstore.BarrierVerifier = (*Backend)(nil)

func nonCancellationErrors(err error) []error {
	if err == nil || err == context.Canceled {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var out []error
		for _, child := range joined.Unwrap() {
			out = append(out, nonCancellationErrors(child)...)
		}
		return out
	}
	return []error{err}
}

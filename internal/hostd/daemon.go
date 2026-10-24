// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// Version is reported in enrollment and every heartbeat.
const Version = "agentgate-hostd/0.1"

// Timing bounds of the daemon.
const (
	minPollInterval     = 2 * time.Second
	maxPollInterval     = 5 * time.Minute
	capabilityRefresh   = 10 * time.Minute
	ledgerRetention     = 7 * 24 * time.Hour
	requestTimeout      = 30 * time.Second
	maxJobsPerPoll      = 4
	stopWaitMargin      = 180 * time.Second
	defaultHeartbeat    = 10 * time.Second
	maxLauncherStopWait = 30
)

// Daemon is one running agentgate-hostd.
type Daemon struct {
	Config   Config
	StateDir string
	Identity Identity
	Keys     Keys
	Service  Service
	Runtime  Runtime
	Ledger   *Ledger
	Outbox   *Outbox
	Sequence *Sequence
	Now      func() time.Time
	Random   io.Reader
	Log      *log.Logger
	// Broker runs each launch's credential broker. Open sets a DockerBroker
	// when the configuration has a broker section; tests replace it.
	Broker BrokerRuntime

	jobKey ed25519.PublicKey

	signMu sync.Mutex

	sealMu  sync.Mutex
	sealKey *secretseal.HostKey
	// secretMu serializes secret-put, secret-delete and the secret checks of
	// a launch, so a launch never binds a value being replaced or removed.
	secretMu sync.Mutex

	mu           sync.Mutex
	active       map[string]*activeLaunch
	caps         []string
	capsAt       time.Time
	lastContact  time.Time
	pollInterval time.Duration
	degraded     string
	workers      sync.WaitGroup
}

type activeLaunch struct {
	jobID, launchID string
	heartbeat       time.Duration
	started         time.Time
	cancel          context.CancelFunc
	done            chan struct{}
	stopSent        bool
	// secrets are the refs the launch's broker uses.
	secrets []string
}

// Open loads a daemon from an enrolled state directory.
func Open(stateDir string, service Service, runtime Runtime, logger *log.Logger) (*Daemon, error) {
	if err := checkPrivateDir(stateDir); err != nil {
		return nil, err
	}
	cfg, err := loadConfig(stateDir)
	if err != nil {
		return nil, err
	}
	id, err := loadIdentity(stateDir)
	if err != nil {
		return nil, fmt.Errorf("hostd: not enrolled (run agentgate-hostd install): %w", err)
	}
	keys, err := loadOrCreateKeys(stateDir, rand.Reader)
	if err != nil {
		return nil, err
	}
	if hostproto.KeyID(keys.Signing.Public().(ed25519.PublicKey)) != id.HostKeyID {
		return nil, errors.New("hostd: the host key differs from the enrolled key")
	}
	origin, err := ServiceOrigin(cfg.ServiceURL, cfg.AllowLoopbackHTTP)
	if err != nil || origin != id.ServiceURL {
		return nil, errors.New("hostd: the configured service differs from the enrolled service")
	}
	return newDaemon(cfg, stateDir, id, keys, service, runtime, time.Now, rand.Reader, logger)
}

func newDaemon(cfg Config, stateDir string, id Identity, keys Keys, service Service, runtime Runtime,
	now func() time.Time, random io.Reader, logger *log.Logger) (*Daemon, error) {
	ledger, err := openLedger(stateDir, now)
	if err != nil {
		return nil, err
	}
	outbox, err := openOutbox(stateDir)
	if err != nil {
		return nil, err
	}
	jobKey, err := id.jobKey()
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	interval := time.Duration(id.PollSeconds) * time.Second
	d := &Daemon{Config: cfg, StateDir: stateDir, Identity: id, Keys: keys, Service: service, Runtime: runtime,
		Ledger: ledger, Outbox: outbox, Sequence: newSequence(stateDir), Now: now, Random: random, Log: logger,
		jobKey: jobKey, active: map[string]*activeLaunch{}, pollInterval: clampInterval(interval)}
	if cfg.Broker != nil {
		d.Broker = &DockerBroker{}
	}
	return d, nil
}

func clampInterval(d time.Duration) time.Duration {
	if d <= 0 {
		return hostproto.DefaultPollInterval
	}
	if d < minPollInterval {
		return minPollInterval
	}
	if d > maxPollInterval {
		return maxPollInterval
	}
	return d
}

// logf writes one bounded, single-line message. Callers never pass secrets.
func (d *Daemon) logf(format string, args ...any) {
	message := strings.ToValidUTF8(fmt.Sprintf(format, args...), "?")
	message = strings.ReplaceAll(message, "\n", " ")
	if len(message) > 2000 {
		message = message[:2000]
	}
	d.Log.Print(message)
}

// header reserves the next sequence: persisted before the request is sent.
func (d *Daemon) header() (hostproto.Header, error) {
	seq, err := d.Sequence.Next()
	if err != nil {
		return hostproto.Header{}, err
	}
	nonce, err := newNonce(d.Random)
	if err != nil {
		return hostproto.Header{}, err
	}
	return hostproto.Header{HostID: d.Identity.TargetID, Nonce: nonce, TimestampMS: d.Now().UnixMilli(), Sequence: seq}, nil
}

func (d *Daemon) noteRejection(err error) {
	var status *StatusError
	if errors.As(err, &status) && status.LastAccepted > 0 {
		// Resynchronise forward only; a lower value is never used again.
		if advanceErr := d.Sequence.AdvancePast(status.LastAccepted); advanceErr != nil {
			d.logf("sequence resynchronisation failed: %v", advanceErr)
		}
	}
}

func (d *Daemon) contact() {
	d.mu.Lock()
	d.lastContact = d.Now()
	d.mu.Unlock()
}

// capabilities maps the runtime's report to protocol capabilities.
func (d *Daemon) capabilities(ctx context.Context) []string {
	d.mu.Lock()
	if d.caps != nil && d.Now().Sub(d.capsAt) < capabilityRefresh {
		out := append([]string(nil), d.caps...)
		d.mu.Unlock()
		return out
	}
	d.mu.Unlock()
	info, err := d.Runtime.Info(ctx)
	caps := []string{hostproto.CapabilityDocker, hostproto.CapabilityPOCPolicyV2}
	if err != nil {
		d.logf("capability detection failed: %v", err)
	} else {
		caps = mapCapabilities(info, d.Config.Runtime)
		// Brokered secrets need the broker image and network, the secret
		// store, and a Docker host: the appliance guest has no broker yet.
		if d.Config.Runtime != RuntimeAppliance && info.Runtime != RuntimeAppliance && d.brokerAvailable(ctx) {
			caps = append(caps, hostproto.CapabilityBrokeredSecrets)
			sort.Strings(caps)
		}
	}
	d.mu.Lock()
	d.caps, d.capsAt = caps, d.Now()
	d.mu.Unlock()
	return append([]string(nil), caps...)
}

func mapCapabilities(info RuntimeInfo, configured string) []string {
	caps := []string{hostproto.CapabilityDocker, hostproto.CapabilityPOCPolicyV2}
	runtime := info.Runtime
	if configured == RuntimeAppliance {
		runtime = RuntimeAppliance
	}
	if runtime == RuntimeAppliance {
		caps = append(caps, hostproto.CapabilityAppliance)
	}
	for _, name := range info.Capabilities {
		switch name {
		case "live-mounts":
			if runtime != RuntimeAppliance {
				caps = append(caps, hostproto.CapabilityLiveMounts)
			}
		case "snapshots":
			caps = append(caps, hostproto.CapabilitySnapshots)
		case "kernel-bpf-lsm":
			if info.Preflight.OK {
				caps = append(caps, hostproto.CapabilityBPFLSM)
			}
		}
	}
	sort.Strings(caps)
	return caps
}

func (d *Daemon) hasCapability(ctx context.Context, name string) bool {
	for _, item := range d.capabilities(ctx) {
		if item == name {
			return true
		}
	}
	return false
}

func (d *Daemon) runningLaunches() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]string, 0, len(d.active))
	for id := range d.active {
		out = append(out, id)
	}
	sort.Strings(out)
	if len(out) > hostproto.MaxRunningLaunches {
		out = out[:hostproto.MaxRunningLaunches]
	}
	return out
}

// PollOnce sends one signed poll with the heartbeat and handles its jobs.
func (d *Daemon) PollOnce(ctx context.Context) error {
	// Signed requests are serialized: sequences leave in the order reserved.
	d.signMu.Lock()
	header, err := d.header()
	if err != nil {
		d.signMu.Unlock()
		return err
	}
	request := hostproto.PollRequest{Header: header, MaxJobs: maxJobsPerPoll, Heartbeat: hostproto.Heartbeat{
		Capabilities: d.capabilities(ctx), RunningLaunches: d.runningLaunches(), AgentVersion: Version, SealKey: d.sealKeyRecord()}}
	env, err := hostproto.Seal(hostproto.DomainPoll, d.Keys.Signing, request)
	if err != nil {
		d.signMu.Unlock()
		return err
	}
	callCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	response, err := d.Service.Poll(callCtx, env)
	d.signMu.Unlock()
	cancel()
	if err != nil {
		d.noteRejection(err)
		return err
	}
	d.contact()
	if response.PollIntervalSeconds > 0 {
		d.mu.Lock()
		d.pollInterval = clampInterval(time.Duration(response.PollIntervalSeconds) * time.Second)
		d.mu.Unlock()
	}
	skew := d.Now().Sub(time.UnixMilli(response.ServerTimeMS))
	if response.ServerTimeMS > 0 && (skew > hostproto.MaxClockSkew || skew < -hostproto.MaxClockSkew) {
		d.logf("clock skew with the service is %s; jobs will fail their time checks until the clock is fixed", skew)
	}
	if len(response.Jobs) > 16 {
		return errors.New("hostd: the service sent more jobs than the protocol allows")
	}
	for _, job := range response.Jobs {
		d.HandleEnvelope(ctx, job)
	}
	return nil
}

// HandleEnvelope verifies one job and runs it at most once.
func (d *Daemon) HandleEnvelope(ctx context.Context, env hostproto.Envelope) {
	var job hostproto.Job
	if err := hostproto.Open(env, hostproto.DomainJob, d.jobKey, &job); err != nil {
		// An unverifiable job names nothing this host can trust, not even its id.
		d.logf("dropped an unverifiable job: %v", err)
		return
	}
	if !jobIDPattern.MatchString(job.ID) {
		d.logf("dropped a job with an invalid id")
		return
	}
	entry, fresh, err := d.Ledger.Begin(LedgerEntry{JobID: job.ID, Type: job.Type, LaunchID: job.LaunchID,
		SpecDigest: job.SpecDigest, PolicyDigest: job.PolicyDigest, DeadlineMS: job.DeadlineMS})
	if err != nil {
		d.logf("job %s: ledger refused it: %v", job.ID, err)
		return
	}
	if !fresh {
		d.repeat(entry)
		return
	}
	payload, err := job.Check(d.Identity.TargetID, d.Now())
	if err != nil {
		d.finish(job.ID, hostproto.ResultRejected, "invalid_job", err.Error(), nil, "")
		return
	}
	d.dispatch(ctx, job, payload)
}

// repeat answers a job id seen before with its recorded result. A job still
// running is never started again.
func (d *Daemon) repeat(entry LedgerEntry) {
	if entry.State != JobDone || entry.Result == nil {
		d.logf("job %s repeated while %s; not run again", entry.JobID, entry.State)
		return
	}
	if d.Outbox.Known(entry.JobID) && !d.Outbox.Completed(entry.JobID) {
		return // the recorded result is still queued for upload
	}
	result := *entry.Result
	if _, err := d.Outbox.Append(entry.JobID, hostproto.Event{TimeMS: d.Now().UnixMilli(), Kind: hostproto.EventResult, Result: &result}, false); err != nil {
		d.logf("job %s: could not queue its recorded result: %v", entry.JobID, err)
	}
}

func boundedMessage(text string) string {
	text = strings.ToValidUTF8(text, "?")
	if len(text) > hostproto.MaxEventMessage {
		text = text[:hostproto.MaxEventMessage]
		for !utf8.ValidString(text) {
			text = text[:len(text)-1]
		}
	}
	return text
}

// progress queues one human-readable step.
func (d *Daemon) progress(jobID, message string) {
	if _, err := d.Outbox.Append(jobID, hostproto.Event{TimeMS: d.Now().UnixMilli(), Kind: hostproto.EventProgress, Message: boundedMessage(message)}, false); err != nil {
		d.logf("job %s: progress not queued: %v", jobID, err)
	}
}

// finish records the result durably, then queues it for upload.
func (d *Daemon) finish(jobID, status, reason, message string, receipt *hostproto.Receipt, missing string) {
	result := hostproto.JobResult{Status: status, Reason: reasonCode(reason), Receipt: receipt}
	if receipt == nil && missing != "" {
		result.EvidenceMissing = reasonCode(missing)
	}
	d.finishResult(jobID, result, message)
}

// finishResult records a complete result durably, then queues it.
func (d *Daemon) finishResult(jobID string, result hostproto.JobResult, message string) {
	if message != "" {
		d.progress(jobID, message)
	}
	if _, err := d.Ledger.Update(jobID, JobDone, &result); err != nil {
		d.logf("job %s: ledger update failed: %v", jobID, err)
	}
	if _, err := d.Outbox.Append(jobID, hostproto.Event{TimeMS: d.Now().UnixMilli(), Kind: hostproto.EventResult, Result: &result}, false); err != nil {
		d.logf("job %s: result not queued: %v", jobID, err)
	}
}

// reasonCode turns any text into the protocol's short reason form.
func reasonCode(value string) string {
	var out strings.Builder
	for _, r := range strings.ToLower(value) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '.', r == ':', r == '-':
			out.WriteRune(r)
		case r == ' ' || r == '/':
			out.WriteRune('_')
		}
		if out.Len() >= 64 {
			break
		}
	}
	if out.Len() == 0 {
		return "unspecified"
	}
	return out.String()
}

func (d *Daemon) dispatch(ctx context.Context, job hostproto.Job, payload any) {
	if _, err := d.Ledger.Update(job.ID, JobRunning, nil); err != nil {
		d.logf("job %s: not started, ledger update failed: %v", job.ID, err)
		return
	}
	switch p := payload.(type) {
	case hostproto.LaunchPayload:
		d.startLaunch(ctx, job, p)
	case hostproto.StopPayload:
		d.background(func() { d.stopJob(ctx, job, p) })
	case hostproto.CollectPayload:
		d.background(func() { d.collectJob(ctx, job) })
	case hostproto.ProvisionPayload:
		d.background(func() { d.provisionJob(ctx, job, p) })
	case hostproto.ApplyProfilePayload:
		d.background(func() { d.applyProfileJob(ctx, job, p) })
	case hostproto.SnapshotMountPayload:
		d.background(func() { d.snapshotJob(ctx, job, p) })
	case hostproto.SecretPutPayload:
		d.background(func() { d.secretPutJob(job, p) })
	case hostproto.SecretDeletePayload:
		d.background(func() { d.secretDeleteJob(job, p) })
	default:
		d.finish(job.ID, hostproto.ResultRejected, "unsupported_job", "this host does not run job type "+job.Type, nil, "")
	}
}

func (d *Daemon) background(work func()) {
	d.workers.Add(1)
	go func() {
		defer d.workers.Done()
		work()
	}()
}

// Wait blocks until every background job has finished.
func (d *Daemon) Wait() { d.workers.Wait() }

// FlushOutbox uploads queued events in order until each batch is acknowledged.
func (d *Daemon) FlushOutbox(ctx context.Context) error {
	var failures []error
	for _, jobID := range d.Outbox.Pending() {
		for attempts := 0; attempts < 64; attempts++ {
			events, err := d.Outbox.Batch(jobID)
			if err != nil || len(events) == 0 {
				if err != nil {
					failures = append(failures, err)
				}
				break
			}
			d.signMu.Lock()
			header, err := d.header()
			if err != nil {
				d.signMu.Unlock()
				return err
			}
			env, err := hostproto.Seal(hostproto.DomainEvents, d.Keys.Signing, hostproto.EventsRequest{Header: header, JobID: jobID, Events: events})
			if err != nil {
				d.signMu.Unlock()
				failures = append(failures, err)
				break
			}
			callCtx, cancel := context.WithTimeout(ctx, requestTimeout)
			response, err := d.Service.Events(callCtx, jobID, env)
			d.signMu.Unlock()
			cancel()
			if err != nil {
				d.noteRejection(err)
				failures = append(failures, err)
				break
			}
			d.contact()
			if err = d.Outbox.Ack(jobID, response.AcceptedThrough, response.Completed); err != nil {
				failures = append(failures, err)
				break
			}
			if response.AcceptedThrough < events[len(events)-1].Seq {
				break // the service holds fewer than were sent; retry on the next round
			}
		}
	}
	return errors.Join(failures...)
}

// EnforceGrace stops every launch whose service has been unreachable longer
// than its grace: three missed heartbeats, the same bound the service uses
// to declare the host lost. Failure to reach the service never extends a launch.
func (d *Daemon) EnforceGrace(ctx context.Context) {
	d.mu.Lock()
	var stops []*activeLaunch
	now := d.Now()
	for _, launch := range d.active {
		grace := time.Duration(hostproto.MissedHeartbeatsLimit) * launch.heartbeat
		last := d.lastContact
		if launch.started.After(last) {
			last = launch.started
		}
		if !launch.stopSent && now.Sub(last) > grace {
			launch.stopSent = true
			stops = append(stops, launch)
		}
	}
	d.mu.Unlock()
	for _, launch := range stops {
		d.logf("launch %s: service unreachable beyond its grace; stopping it", launch.launchID)
		if _, err := d.Runtime.Stop(ctx, launch.launchID, 0, "service_unreachable"); err != nil {
			d.logf("launch %s: stop request failed, cancelling its runtime: %v", launch.launchID, err)
			launch.cancel()
		}
	}
}

// Run is the daemon's main loop: recover, then poll, upload and enforce.
func (d *Daemon) Run(ctx context.Context) error {
	d.Recover(ctx)
	for {
		if err := d.FlushOutbox(ctx); err != nil {
			d.logf("event upload pending: %v", err)
		}
		if err := d.PollOnce(ctx); err != nil {
			d.logf("poll failed: %v", err)
		}
		d.EnforceGrace(ctx)
		if d.degradedReason() != "" {
			d.retryReconcile(ctx)
		}
		if err := d.Ledger.Prune(ledgerRetention, func(id string) bool { return d.Outbox.Known(id) && !d.Outbox.Completed(id) }); err != nil {
			d.logf("ledger prune: %v", err)
		}
		select {
		case <-ctx.Done():
			d.shutdown()
			return ctx.Err()
		case <-time.After(d.nextInterval()):
		}
	}
}

func (d *Daemon) nextInterval() time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	interval := d.pollInterval
	for _, launch := range d.active {
		// A running launch is backed by a heartbeat at least this often.
		if launch.heartbeat < interval {
			interval = launch.heartbeat
		}
	}
	return clampInterval(interval)
}

// shutdown cancels every launch runtime; each tears down and writes its
// receipt, which the next start reports.
func (d *Daemon) shutdown() {
	d.mu.Lock()
	for _, launch := range d.active {
		launch.cancel()
	}
	d.mu.Unlock()
	d.workers.Wait()
}

func (d *Daemon) degradedReason() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.degraded
}

func (d *Daemon) setDegraded(reason string) {
	d.mu.Lock()
	d.degraded = reason
	d.mu.Unlock()
}

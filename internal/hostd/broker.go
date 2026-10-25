// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/broker"
	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/pocpolicy"
)

// Paths inside the broker container and timing of its lifecycle.
const (
	brokerContainerConfig = "/etc/agentgate/broker.json"
	brokerContainerStats  = "/var/lib/agentgate/broker"
	brokerStatsName       = "stats.json"
	brokerSecretMount     = "/run/agentgate/secrets"
	brokerStopGrace       = 5 * time.Second
	brokersDirName        = "brokers"
	brokerStateName       = "state.json"
	brokerEvidenceName    = "evidence.json"
	brokerConfigName      = "broker.json"
)

// brokerStartWait bounds how long a launch waits for its broker to report
// running before it fails closed (docs/BROKER.md: 10 seconds).
var brokerStartWait = 10 * time.Second

// BrokerSecretFile is one store file bound read-only into the broker.
type BrokerSecretFile struct {
	Ref           string `json:"ref"`
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
}

// BrokerLaunch is one launch's broker as this host sets it up: its own
// internal /29 network (gateway .1, broker .2, target .3), its configuration
// (root-owned 0600, no secret in it), the store files it reads at start, and
// a stats directory owned by the broker's unprivileged identity.
type BrokerLaunch struct {
	LaunchID      string
	TargetID      string
	Network       string
	Container     string
	Subnet        netip.Prefix
	Gateway       netip.Addr
	Address       netip.Addr
	TargetAddress netip.Addr
	Port          int
	Dir           string
	ConfigPath    string
	Config        []byte
	ConfigSHA256  string
	StatsDir      string
	Secrets       []BrokerSecretFile
	Deadline      time.Time
	Image         string
	RunAs         broker.Identity
	Egress        string
}

// StatsPath is the stats file as the host reads it.
func (b *BrokerLaunch) StatsPath() string { return filepath.Join(b.StatsDir, brokerStatsName) }

// BrokerRuntime runs one launch's broker. DockerBroker is the host's
// implementation (the hardened recipe in docs/BROKER.md); tests run the
// broker in process. Start returns once the broker process is started; the
// daemon then waits for its stats to say it is serving.
type BrokerRuntime interface {
	// Check reports whether this host has what a broker needs.
	Check(ctx context.Context, cfg BrokerConfig) error
	// Start creates the launch network and starts the broker on it.
	Start(ctx context.Context, b *BrokerLaunch) error
	// Stop asks the broker to stop (SIGTERM), waiting at most grace before
	// it is killed, so it writes its final stats.
	Stop(ctx context.Context, b *BrokerLaunch, grace time.Duration) error
	// Remove deletes the container and the network and verifies both are gone.
	Remove(ctx context.Context, b *BrokerLaunch) error
}

// launcherBroker is the broker part of the launcher job: where the target
// joins and what the agent receives. It never names a path or a value.
type launcherBroker struct {
	Network       string            `json:"network"`
	Subnet        string            `json:"subnet"`
	Address       string            `json:"address"`
	Port          int               `json:"port"`
	TargetAddress string            `json:"target_address"`
	Env           map[string]string `json:"env"`
}

func brokerNetworkName(launchID string) string { return "agentgate-" + launchID + "-broker" }

// brokerEndpoint derives the launch network from the signed policy's broker
// endpoint: the /29 holding it, which must sit inside this host's pool with
// the broker at .2 and the target at .3.
func brokerEndpoint(endpoint *pocpolicy.Broker, pool netip.Prefix) (netip.Prefix, netip.Addr, netip.Addr, netip.Addr, error) {
	addr, err := netip.ParseAddr(endpoint.Address)
	if err != nil || !addr.Is4() {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, netip.Addr{}, errors.New("the policy's broker endpoint is not an IPv4 address")
	}
	subnet := netip.PrefixFrom(addr, 29).Masked()
	base := subnet.Addr().As4()
	at := func(i byte) netip.Addr { return netip.AddrFrom4([4]byte{base[0], base[1], base[2], base[3] + i}) }
	if addr != at(2) || !pool.IsValid() || !pool.Contains(subnet.Addr()) || !pool.Contains(at(7)) || subnet.Addr() == pool.Addr() {
		return netip.Prefix{}, netip.Addr{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("the policy's broker endpoint %s is not the .2 of a /29 inside this host's broker pool %s", addr, pool)
	}
	return subnet, at(1), addr, at(3), nil
}

// planBroker builds the broker configuration for a verified launch exactly as
// the broker validates it, and the base URLs the agent receives. Secrets are
// referenced by their path inside the broker container; values never appear.
// It works from the job's copy of each secret's settings and is a pre-check
// only: newBrokerLaunch refuses settings that differ from the policy sealed
// with the stored value and builds the configuration the broker runs from
// that stored policy.
func planBroker(job hostproto.Job, p hostproto.LaunchPayload, doc pocpolicy.Document, targetID string, cfg *BrokerConfig, now time.Time) (*launcherBroker, []byte, error) {
	if doc.Broker == nil {
		return nil, nil, errors.New("a launch with secrets needs the broker endpoint in its signed policy")
	}
	subnet, _, addr, target, err := brokerEndpoint(doc.Broker, cfg.pool())
	if err != nil {
		return nil, nil, err
	}
	secrets := make([]broker.LaunchSecret, 0, len(p.Secrets))
	for _, s := range p.Secrets {
		if len(s.Rules) == 0 {
			return nil, nil, fmt.Errorf("secret %s has no broker rules; deny by default", s.Ref)
		}
		rules := make([]broker.Rule, 0, len(s.Rules))
		for _, r := range s.Rules {
			rules = append(rules, broker.Rule{Methods: r.Methods, Path: r.Path, Match: r.Match})
		}
		secrets = append(secrets, broker.LaunchSecret{Ref: s.Ref, Env: s.Env, Upstreams: s.Upstreams, Header: s.Header, Scheme: s.Scheme,
			Username: s.Username, Rules: rules, SecretFile: brokerSecretMount + "/" + s.Ref, Extra: s.ExtraHeaders, Forward: s.ForwardHeaders})
	}
	raw, _, env, err := broker.BuildLaunchConfig(broker.LaunchInput{LaunchID: job.LaunchID, TargetID: targetID, Deadline: time.UnixMilli(p.ExpiresAtMS),
		Listen:    broker.Listen{Network: "tcp", Address: addr.String(), Port: doc.Broker.Port, Subnet: subnet.String()},
		StatsPath: brokerContainerStats + "/" + brokerStatsName, RunAs: broker.Identity{UID: cfg.UID, GID: cfg.GID}, Secrets: secrets}, now)
	if err != nil {
		return nil, nil, err
	}
	return &launcherBroker{Network: brokerNetworkName(job.LaunchID), Subnet: subnet.String(), Address: addr.String(), Port: doc.Broker.Port,
		TargetAddress: target.String(), Env: env}, raw, nil
}

// brokerState is the durable record of one broker, so a restarted host
// agent can stop and remove what a crash left behind.
type brokerState struct {
	LaunchID      string             `json:"launch_id"`
	TargetID      string             `json:"target_id"`
	Network       string             `json:"network"`
	Container     string             `json:"container"`
	Subnet        string             `json:"subnet"`
	Address       string             `json:"address"`
	TargetAddress string             `json:"target_address"`
	Port          int                `json:"port"`
	ConfigSHA256  string             `json:"config_sha256"`
	Secrets       []BrokerSecretFile `json:"secrets"`
	Image         string             `json:"image"`
	Egress        string             `json:"egress_network"`
	UID           int                `json:"uid"`
	GID           int                `json:"gid"`
	DeadlineMS    int64              `json:"deadline_ms"`
	StartedAtMS   int64              `json:"started_at_ms"`
	Stopped       bool               `json:"stopped"`
}

// brokerOutcome is what the host keeps after a broker stopped: the verified
// evidence for the receipt and any cleanup failure.
type brokerOutcome struct {
	Evidence      *hostproto.BrokerEvidence `json:"evidence"`
	Counts        map[string]uint64         `json:"counts"`
	CleanupErrors []string                  `json:"cleanup_errors"`
}

func (d *Daemon) brokersDir() string { return filepath.Join(d.StateDir, brokersDirName) }

func (d *Daemon) brokerDir(launchID string) string { return filepath.Join(d.brokersDir(), launchID) }

// newBrokerLaunch binds the planned broker to this host: the store files of
// exactly the secrets the service relayed for these ids, and its directories.
// It refuses, failing the launch closed, any secret whose settings in the job
// do not produce exactly the policy digest stored with its value, and builds
// the broker configuration from the stored policies (the job supplies only
// the refs, the agent's variable names and the endpoint).
func (d *Daemon) newBrokerLaunch(job hostproto.Job, p hostproto.LaunchPayload, plan *launcherBroker, config []byte) (*BrokerLaunch, error) {
	cfg := d.Config.Broker
	store, err := d.secretStore()
	if err != nil {
		return nil, errors.New("the secret store is unavailable")
	}
	bindings, err := d.loadBindings()
	if err != nil {
		return nil, err
	}
	b := &BrokerLaunch{LaunchID: job.LaunchID, TargetID: d.Identity.TargetID, Network: plan.Network, Container: plan.Network, Port: plan.Port,
		Deadline: time.UnixMilli(p.ExpiresAtMS), Image: cfg.Image,
		RunAs: broker.Identity{UID: cfg.UID, GID: cfg.GID}, Egress: cfg.EgressNetwork, Dir: d.brokerDir(job.LaunchID)}
	b.Subnet = netip.MustParsePrefix(plan.Subnet)
	b.Address, b.TargetAddress = netip.MustParseAddr(plan.Address), netip.MustParseAddr(plan.TargetAddress)
	base := b.Subnet.Addr().As4()
	b.Gateway = netip.AddrFrom4([4]byte{base[0], base[1], base[2], base[3] + 1})
	b.ConfigPath, b.StatsDir = filepath.Join(b.Dir, brokerConfigName), filepath.Join(b.Dir, "stats")
	secrets := make([]broker.LaunchSecret, 0, len(p.Secrets))
	for _, s := range p.Secrets {
		path, stored, err := d.boundSecret(store, bindings, s.Ref, s.SecretID)
		if err != nil {
			return nil, err
		}
		requested, err := s.Policy()
		if err != nil || s.PolicyDigest != stored.Digest() || requested.Digest() != stored.Digest() {
			return nil, fmt.Errorf("secret %s: the launch's broker settings differ from the policy sealed with the stored value (policy %s); refusing the launch", s.Ref, stored.Digest())
		}
		rules := make([]broker.Rule, 0, len(stored.Rules))
		for _, r := range stored.Rules {
			rules = append(rules, broker.Rule{Methods: r.Methods, Path: r.Path, Match: r.Match})
		}
		secrets = append(secrets, broker.LaunchSecret{Ref: s.Ref, Env: s.Env, Upstreams: stored.UpstreamNames(), Header: stored.Header, Scheme: stored.Scheme,
			Username: stored.Username, Rules: rules, SecretFile: brokerSecretMount + "/" + s.Ref, Extra: stored.ExtraHeaderMap(), Forward: stored.ForwardHeaders})
		b.Secrets = append(b.Secrets, BrokerSecretFile{Ref: s.Ref, HostPath: path, ContainerPath: brokerSecretMount + "/" + s.Ref})
	}
	raw, _, env, err := broker.BuildLaunchConfig(broker.LaunchInput{LaunchID: job.LaunchID, TargetID: d.Identity.TargetID, Deadline: time.UnixMilli(p.ExpiresAtMS),
		Listen:    broker.Listen{Network: "tcp", Address: plan.Address, Port: plan.Port, Subnet: plan.Subnet},
		StatsPath: brokerContainerStats + "/" + brokerStatsName, RunAs: broker.Identity{UID: cfg.UID, GID: cfg.GID}, Secrets: secrets}, d.Now())
	if err != nil {
		return nil, fmt.Errorf("the broker refuses the stored secret policy: %w", err)
	}
	for name, url := range env {
		if plan.Env[name] != url {
			return nil, errors.New("the broker routes built from the stored policies differ from the launch's")
		}
	}
	if len(env) != len(plan.Env) {
		return nil, errors.New("the broker routes built from the stored policies differ from the launch's")
	}
	_ = config // the job-derived configuration was a pre-check only
	b.Config, b.ConfigSHA256 = raw, broker.ConfigDigest(raw)
	return b, nil
}

func (b *BrokerLaunch) state(started time.Time, stopped bool) brokerState {
	return brokerState{LaunchID: b.LaunchID, TargetID: b.TargetID, Network: b.Network, Container: b.Container, Subnet: b.Subnet.String(),
		Address: b.Address.String(), TargetAddress: b.TargetAddress.String(), Port: b.Port, ConfigSHA256: b.ConfigSHA256, Secrets: b.Secrets,
		Image: b.Image, Egress: b.Egress, UID: b.RunAs.UID, GID: b.RunAs.GID, DeadlineMS: b.Deadline.UnixMilli(), StartedAtMS: started.UnixMilli(), Stopped: stopped}
}

func brokerFromState(dir string, s brokerState) (*BrokerLaunch, error) {
	subnet, err1 := netip.ParsePrefix(s.Subnet)
	addr, err2 := netip.ParseAddr(s.Address)
	target, err3 := netip.ParseAddr(s.TargetAddress)
	if err1 != nil || err2 != nil || err3 != nil || !jobIDPattern.MatchString(s.LaunchID) || s.Network != brokerNetworkName(s.LaunchID) || s.Container != s.Network {
		return nil, errors.New("hostd: a broker state record is damaged")
	}
	base := subnet.Addr().As4()
	return &BrokerLaunch{LaunchID: s.LaunchID, TargetID: s.TargetID, Network: s.Network, Container: s.Container, Subnet: subnet, Address: addr,
		TargetAddress: target, Gateway: netip.AddrFrom4([4]byte{base[0], base[1], base[2], base[3] + 1}), Port: s.Port, Dir: dir,
		ConfigPath: filepath.Join(dir, brokerConfigName), ConfigSHA256: s.ConfigSHA256, StatsDir: filepath.Join(dir, "stats"),
		Secrets: s.Secrets, Image: s.Image, Egress: s.Egress, RunAs: broker.Identity{UID: s.UID, GID: s.GID}, Deadline: time.UnixMilli(s.DeadlineMS)}, nil
}

func (d *Daemon) saveBrokerState(b *BrokerLaunch, started time.Time, stopped bool) error {
	raw, err := json.Marshal(b.state(started, stopped))
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(b.Dir, brokerStateName), raw, 0o600)
}

// startBroker prepares the broker's files, starts it, and waits until its
// stats say it is serving this exact configuration. Any failure removes what
// was created and fails the launch closed.
func (d *Daemon) startBroker(ctx context.Context, b *BrokerLaunch) (string, error) {
	if d.Broker == nil || d.Config.Broker == nil {
		return "broker_unavailable", errors.New("this host has no credential broker configured")
	}
	if err := ensurePrivateDir(d.brokersDir()); err != nil {
		return "broker_state_unavailable", err
	}
	// One broker per launch id, ever: an existing directory means this launch
	// already had a broker on this host.
	if err := os.Mkdir(b.Dir, 0o700); err != nil {
		return "broker_state_unavailable", fmt.Errorf("the broker directory for this launch exists or cannot be made: %w", err)
	}
	if err := checkPrivateDir(b.Dir); err != nil {
		return "broker_state_unavailable", err
	}
	if err := os.Mkdir(b.StatsDir, 0o700); err != nil {
		return "broker_state_unavailable", err
	}
	// The broker writes its stats as its unprivileged identity.
	if err := os.Chown(b.StatsDir, b.RunAs.UID, b.RunAs.GID); err != nil {
		return "broker_state_unavailable", err
	}
	if err := createFileExclusive(b.ConfigPath, b.Config); err != nil {
		return "broker_state_unavailable", err
	}
	started := d.Now()
	if err := d.saveBrokerState(b, started, false); err != nil {
		return "broker_state_unavailable", err
	}
	fail := func(code string, err error) (string, error) {
		outcome := d.teardownBroker(b, started)
		if len(outcome.CleanupErrors) > 0 {
			err = fmt.Errorf("%w; cleanup: %s", err, strings.Join(outcome.CleanupErrors, "; "))
		}
		return code, err
	}
	if err := d.Broker.Start(ctx, b); err != nil {
		return fail("broker_start_failed", err)
	}
	if err := d.waitBroker(ctx, b); err != nil {
		return fail("broker_not_running", err)
	}
	return "", nil
}

// readBrokerStats reads and verifies the broker's stats document: strict
// parse, this launch, this target, this exact configuration and endpoint.
func readBrokerStats(b *BrokerLaunch) (*broker.StatsDocument, error) {
	raw, err := readStatsFile(b.StatsPath())
	if err != nil {
		return nil, err
	}
	doc, err := broker.ParseStats(raw)
	if err != nil {
		return nil, err
	}
	if doc.LaunchID != b.LaunchID || doc.TargetID != b.TargetID || doc.ConfigSHA256 != b.ConfigSHA256 ||
		doc.Listen != "tcp:"+net.JoinHostPort(b.Address.String(), strconv.Itoa(b.Port)) {
		return nil, errors.New("the broker stats belong to another launch, configuration or endpoint")
	}
	return doc, nil
}

// readStatsFile reads a regular file without following a link. The broker
// writes it as its own user, so ownership is not checked; the content is
// parsed strictly and bound to the configuration.
func readStatsFile(path string) ([]byte, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > broker.MaxStatsBytes {
		return nil, errors.New("the broker stats file is not a bounded regular file")
	}
	return io.ReadAll(io.LimitReader(file, broker.MaxStatsBytes+1))
}

func (d *Daemon) waitBroker(ctx context.Context, b *BrokerLaunch) error {
	deadline := time.Now().Add(brokerStartWait)
	var last error = errors.New("the broker wrote no stats")
	for time.Now().Before(deadline) {
		doc, err := readBrokerStats(b)
		switch {
		case err == nil && doc.State == "running":
			return nil
		case err == nil && doc.State == "stopped":
			return errors.New("the broker stopped before serving")
		case err != nil && !errors.Is(err, os.ErrNotExist):
			last = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("the broker did not report running within %s: %v", brokerStartWait, last)
}

// teardownBroker stops the broker, collects and verifies its final stats,
// removes the container and the network, and records the outcome. It runs on
// its own bounded context: a cancelled launch still cleans up.
func (d *Daemon) teardownBroker(b *BrokerLaunch, started time.Time) brokerOutcome {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	outcome := brokerOutcome{Counts: map[string]uint64{}, CleanupErrors: []string{}}
	if err := d.Broker.Stop(ctx, b, brokerStopGrace); err != nil {
		outcome.CleanupErrors = append(outcome.CleanupErrors, "stop: "+boundedMessage(err.Error()))
	}
	outcome.Evidence = &hostproto.BrokerEvidence{Version: hostproto.BrokerEvidenceVersion, Missing: "broker_stats"}
	if doc, err := readBrokerStats(b); err == nil {
		evidence, counts := brokerEvidenceFrom(doc)
		if _, checkErr := evidence.Check(); checkErr == nil {
			outcome.Evidence, outcome.Counts = evidence, counts
		} else {
			outcome.Evidence.Missing = "broker_stats_invalid"
		}
	}
	if err := d.Broker.Remove(ctx, b); err != nil {
		outcome.CleanupErrors = append(outcome.CleanupErrors, "remove: "+boundedMessage(err.Error()))
	}
	// The configuration holds no secret; remove it with the stats directory.
	_ = os.Remove(b.ConfigPath)
	_ = os.RemoveAll(b.StatsDir)
	raw, err := json.Marshal(outcome)
	if err == nil {
		err = writeFileAtomic(filepath.Join(b.Dir, brokerEvidenceName), raw, 0o600)
	}
	if err != nil {
		d.logf("launch %s: broker evidence not saved: %v", b.LaunchID, err)
	}
	if err := d.saveBrokerState(b, started, true); err != nil {
		d.logf("launch %s: broker state not saved: %v", b.LaunchID, err)
	}
	return outcome
}

// brokerEvidenceFrom folds a verified stats document into the receipt's
// bounded evidence: counts and fixed codes, no denial records or paths.
func brokerEvidenceFrom(doc *broker.StatsDocument) (*hostproto.BrokerEvidence, map[string]uint64) {
	h := doc.Hardening
	e := &hostproto.BrokerEvidence{Version: hostproto.BrokerEvidenceVersion, ConfigSHA256: doc.ConfigSHA256, Listen: doc.Listen, State: doc.State,
		StopReason: doc.StopReason, Complete: doc.Complete, StartedAt: doc.StartedAt, UpdatedAt: doc.UpdatedAt,
		Hardening: &hostproto.BrokerHardening{UID: h.UID, GID: h.GID, NotDumpable: h.NotDumpable, CoreLimitZero: h.CoreLimitZero,
			NoNewPrivs: h.NoNewPrivs, NoCapabilities: h.NoCapabilities, MemoryLocked: h.MemoryLocked},
		Connections: hostproto.BrokerConnections{Accepted: doc.Connections.Accepted, Rejected: doc.Connections.Rejected},
		Requests:    hostproto.BrokerRequests{Total: doc.Requests.Total, Denied: doc.Requests.Denied, Forwarded: doc.Requests.Forwarded},
		Denied:      map[string]uint64{}, Routes: map[string]hostproto.BrokerRouteEvidence{}, DenialsRecorded: len(doc.Denials), DenialsTruncated: doc.DenialsTruncated}
	for code, n := range doc.Denied {
		e.Denied[code] = n
	}
	for name, r := range doc.Routes {
		route := hostproto.BrokerRouteEvidence{Upstream: r.Upstream, Requests: r.Requests, Forwarded: r.Forwarded, Status: map[string]uint64{},
			Errors: map[string]uint64{}, BytesIn: r.BytesIn, BytesOut: r.BytesOut, Redactions: r.Redactions}
		for k, v := range r.Status {
			route.Status[k] = v
		}
		for k, v := range r.Errors {
			route.Errors[k] = v
		}
		e.Routes[name] = route
	}
	return e, broker.BrokerCounts(doc)
}

// brokerOutcomeFor reads the recorded outcome of a launch's broker; ok is
// false for a launch that had none.
func (d *Daemon) brokerOutcomeFor(launchID string) (brokerOutcome, bool) {
	var out brokerOutcome
	if !jobIDPattern.MatchString(launchID) {
		return out, false
	}
	dir := d.brokerDir(launchID)
	if _, err := os.Lstat(dir); err != nil {
		return out, false
	}
	raw, err := readPrivateFile(filepath.Join(dir, brokerEvidenceName), 1<<20)
	if err == nil && json.Unmarshal(raw, &out) == nil && out.Evidence != nil && out.Counts != nil {
		return out, true
	}
	// The broker existed but its outcome is unreadable: report it missing
	// and never as a clean teardown.
	return brokerOutcome{Evidence: &hostproto.BrokerEvidence{Version: hostproto.BrokerEvidenceVersion, Missing: "broker_evidence_unreadable"},
		Counts: map[string]uint64{}, CleanupErrors: []string{"broker outcome unreadable"}}, true
}

// recoverBrokers stops and removes every broker a crash left running and
// records its outcome, so the launch's receipt still reports it.
func (d *Daemon) recoverBrokers() {
	entries, err := os.ReadDir(d.brokersDir())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			d.logf("broker recovery: %v", err)
		}
		return
	}
	for _, entry := range entries {
		dir := filepath.Join(d.brokersDir(), entry.Name())
		if !entry.IsDir() || !jobIDPattern.MatchString(entry.Name()) {
			continue
		}
		raw, err := readPrivateFile(filepath.Join(dir, brokerStateName), 64<<10)
		if err != nil {
			d.logf("broker recovery %s: %v", entry.Name(), err)
			continue
		}
		var s brokerState
		if json.Unmarshal(raw, &s) != nil || s.LaunchID != entry.Name() || s.Stopped {
			continue
		}
		b, err := brokerFromState(dir, s)
		if err != nil {
			d.logf("broker recovery %s: %v", entry.Name(), err)
			continue
		}
		if d.Broker == nil {
			d.logf("broker recovery %s: no broker runtime to stop it with", entry.Name())
			continue
		}
		outcome := d.teardownBroker(b, time.UnixMilli(s.StartedAtMS))
		d.logf("launch %s: stopped and removed the broker a restart left behind (cleanup errors: %d)", s.LaunchID, len(outcome.CleanupErrors))
	}
}

// brokerAvailable decides the brokered-secrets capability.
func (d *Daemon) brokerAvailable(ctx context.Context) bool {
	if d.Config.Broker == nil || d.Broker == nil {
		return false
	}
	if err := d.Broker.Check(ctx, *d.Config.Broker); err != nil {
		d.logf("brokered secrets unavailable: %v", err)
		return false
	}
	if _, err := d.secretStore(); err != nil {
		d.logf("brokered secrets unavailable: the secret store: %v", err)
		return false
	}
	return true
}

// DockerBroker runs a launch's broker with the Docker CLI, following the
// hardened recipe in docs/BROKER.md. It never mounts the Docker socket, the
// whole secret store or anything of the target into the broker.
type DockerBroker struct {
	// Docker is the CLI path (default /usr/bin/docker).
	Docker string
	// Exec runs one command; tests record it. Default: os/exec with a clean
	// environment and bounded output.
	Exec func(ctx context.Context, argv []string) (stdout []byte, err error)
	// Interfaces lists host addresses; a broker network may not overlap them.
	Interfaces func() ([]net.Addr, error)
}

func (r *DockerBroker) run(ctx context.Context, args ...string) ([]byte, error) {
	docker := r.Docker
	if docker == "" {
		docker = "/usr/bin/docker"
	}
	argv := append([]string{docker}, args...)
	if r.Exec != nil {
		return r.Exec(ctx, argv)
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = cleanEnv
	var stdout bytes.Buffer
	stderr := &tailBuffer{limit: maxStderrTail}
	cmd.Stdout = &limitWriter{w: &stdout, left: 4 << 20}
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("docker %s: %v: %s", args[0], err, strings.TrimSpace(strings.ToValidUTF8(string(stderr.buf), "?")))
	}
	return stdout.Bytes(), nil
}

// Check requires the pinned broker image and the egress network.
func (r *DockerBroker) Check(ctx context.Context, cfg BrokerConfig) error {
	if _, err := r.run(ctx, "image", "inspect", "--format", "{{.Id}}", cfg.Image); err != nil {
		return fmt.Errorf("the broker image is not present: %w", err)
	}
	if _, err := r.run(ctx, "network", "inspect", "--format", "{{.Name}}", cfg.EgressNetwork); err != nil {
		return fmt.Errorf("the broker egress network is absent: %w", err)
	}
	return nil
}

// overlap refuses a broker subnet that overlaps any Docker network or any
// address on the host.
func (r *DockerBroker) overlap(ctx context.Context, subnet netip.Prefix) error {
	out, err := r.run(ctx, "network", "ls", "--quiet", "--no-trunc")
	if err != nil {
		return err
	}
	ids := strings.Fields(string(out))
	if len(ids) > 0 {
		out, err = r.run(ctx, append([]string{"network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}"}, ids...)...)
		if err != nil {
			return err
		}
		for _, field := range strings.Fields(string(out)) {
			if p, err := netip.ParsePrefix(field); err == nil && p.Overlaps(subnet) {
				return fmt.Errorf("the broker network %s overlaps the Docker network %s", subnet, p)
			}
		}
	}
	list := r.Interfaces
	if list == nil {
		list = net.InterfaceAddrs
	}
	addrs, err := list()
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(n.IP); ok {
				bits, _ := n.Mask.Size()
				if netip.PrefixFrom(ip.Unmap(), bits).Masked().Overlaps(subnet) {
					return fmt.Errorf("the broker network %s overlaps a host address", subnet)
				}
			}
		}
	}
	return nil
}

// Start creates the internal launch network, creates the broker container
// with the hardened recipe, gives it its own egress network and starts it.
func (r *DockerBroker) Start(ctx context.Context, b *BrokerLaunch) error {
	if err := r.overlap(ctx, b.Subnet); err != nil {
		return err
	}
	label := "agentgate.launch=" + b.LaunchID
	if _, err := r.run(ctx, "network", "create", "--internal", "--driver", "bridge", "--subnet", b.Subnet.String(), "--gateway", b.Gateway.String(),
		"--label", label, "--label", "agentgate.role=broker-network", b.Network); err != nil {
		return err
	}
	args := []string{"create", "--name", b.Container, "--network", b.Network, "--ip", b.Address.String(),
		"--read-only", "--cap-drop", "ALL", "--cap-add", "SETUID", "--cap-add", "SETGID", "--security-opt", "no-new-privileges",
		"--ulimit", "core=0", "--memory", "256m", "--pids-limit", "64", "--cpus", "1", "--restart", "no", "--pull", "never",
		"--label", label, "--label", "agentgate.role=broker",
		"--mount", "type=bind,source=" + b.ConfigPath + ",target=" + brokerContainerConfig + ",readonly"}
	for _, s := range b.Secrets {
		args = append(args, "--mount", "type=bind,source="+s.HostPath+",target="+s.ContainerPath+",readonly")
	}
	args = append(args, "--mount", "type=bind,source="+b.StatsDir+",target="+brokerContainerStats,
		b.Image, "run", "--config-sha256", b.ConfigSHA256, brokerContainerConfig)
	if _, err := r.run(ctx, args...); err != nil {
		return err
	}
	if _, err := r.run(ctx, "network", "connect", b.Egress, b.Container); err != nil {
		return err
	}
	_, err := r.run(ctx, "start", b.Container)
	return err
}

// Stop sends SIGTERM and waits at most grace before Docker kills it.
func (r *DockerBroker) Stop(ctx context.Context, b *BrokerLaunch, grace time.Duration) error {
	_, err := r.run(ctx, "stop", "--time", strconv.Itoa(int(grace/time.Second)), b.Container)
	if err != nil && absent(err) {
		return nil
	}
	return err
}

func absent(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "no such") || strings.Contains(text, "not found")
}

// Remove deletes the container and the network, then proves both are gone.
func (r *DockerBroker) Remove(ctx context.Context, b *BrokerLaunch) error {
	var failures []string
	if _, err := r.run(ctx, "rm", "--force", "--volumes", b.Container); err != nil && !absent(err) {
		failures = append(failures, err.Error())
	}
	if _, err := r.run(ctx, "network", "rm", b.Network); err != nil && !absent(err) {
		failures = append(failures, err.Error())
	}
	if _, err := r.run(ctx, "container", "inspect", "--format", "{{.Id}}", b.Container); err == nil || !absent(err) {
		failures = append(failures, "the broker container remains")
	}
	if _, err := r.run(ctx, "network", "inspect", "--format", "{{.Id}}", b.Network); err == nil || !absent(err) {
		failures = append(failures, "the broker network remains")
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

// stopLeftoverBroker stops the broker of a launch whose supervisor is no
// longer running but did not record the broker as stopped.
func (d *Daemon) stopLeftoverBroker(launchID string) {
	d.mu.Lock()
	_, running := d.active[launchID]
	d.mu.Unlock()
	if running || d.Broker == nil || !jobIDPattern.MatchString(launchID) {
		return
	}
	dir := d.brokerDir(launchID)
	raw, err := readPrivateFile(filepath.Join(dir, brokerStateName), 64<<10)
	if err != nil {
		return
	}
	var s brokerState
	if json.Unmarshal(raw, &s) != nil || s.Stopped || s.LaunchID != launchID {
		return
	}
	if b, err := brokerFromState(dir, s); err == nil {
		d.teardownBroker(b, time.UnixMilli(s.StartedAtMS))
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Owned fixed diagnostic only. This program never authorizes normal admission.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/buildinfo"
	"alloyium.local/kernel-poc/internal/dockerplacement"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/pocpolicy"
	"alloyium.local/kernel-poc/internal/policy"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type event struct {
	Sequence, Generation, Domain, Cgroup, MonoNS               uint64
	PID, UID, Hook, Allowed, RuleIndex, Family, Protocol, Port uint32
	Address                                                    [16]byte
	Version, LeaseRevision                                     uint32
}
type counters struct{ Decisions, Lost uint64 }

// networkAttachments is the complete network guard. gateway.py NETWORK_LINKS
// must equal its length; a test binds the two.
var networkAttachments = []struct {
	name string
	kind ebpf.AttachType
}{
	{"net_connect4", ebpf.AttachCGroupInet4Connect}, {"net_connect6", ebpf.AttachCGroupInet6Connect},
	{"net_sendmsg4", ebpf.AttachCGroupUDP4Sendmsg}, {"net_sendmsg6", ebpf.AttachCGroupUDP6Sendmsg},
	{"net_egress", ebpf.AttachCGroupInetEgress}, {"net_ingress", ebpf.AttachCGroupInetIngress},
}

// maxNetworkEvents bounds the network events kept in one receipt.
const maxNetworkEvents = 10000

type receipt struct {
	Scope          string                       `json:"scope"`
	SourceRevision string                       `json:"source_revision"`
	BootID         string                       `json:"boot_id"`
	PolicyDigest   string                       `json:"policy_digest"`
	ObjectSHA256   string                       `json:"object_sha256"`
	Target         dockerplacement.Measurement  `json:"target"`
	Domain         uint64                       `json:"domain"`
	DomainPath     string                       `json:"domain_path"`
	PinDir         string                       `json:"pin_dir"`
	RuleIDs        []string                     `json:"rule_ids"`
	MapDecisions   map[string]netrules.Decision `json:"map_decisions"`
	PublicHostname string                       `json:"public_hostname"`
	PublicAddress  string                       `json:"public_address"`
	StartedMonoNS  uint64                       `json:"started_mono_ns"`
	DeadlineMonoNS uint64                       `json:"deadline_mono_ns"`
	FinishedMonoNS uint64                       `json:"finished_mono_ns"`
	Events         []event                      `json:"events"`
	Counters       counters                     `json:"counters"`
	Host           *hostEvidence                `json:"host,omitempty"`
	// A launch document also records its mode and lifetime, and aggregates its
	// network stream instead of keeping every event.
	Mode            string         `json:"mode,omitempty"`
	LifetimeSeconds int            `json:"lifetime_seconds,omitempty"`
	Network         *networkStream `json:"network,omitempty"`
	// Stop is "signal" for a normal stop. Any other value marks the receipt incomplete.
	Stop            string `json:"stop"`
	CollectionError string `json:"collection_error,omitempty"`
	Complete        bool   `json:"complete"`
}

func run() (err error) {
	if (len(os.Args) != 10 && len(os.Args) != 12) || os.Geteuid() != 0 {
		return errors.New("usage: pilot-network-guard TARGET POLICY OBJECT HOST ADDRESS READY RECEIPT SOURCE ROOT_DOMAIN_PATH [FILESYSTEM_OBJECT PROCESS_OBJECT]")
	}
	targetPath, policyPath, objectPath, hostname, address, readyPath, receiptPath, source := os.Args[1], os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], os.Args[7], os.Args[8]
	cgroup := os.Args[9]
	if buildinfo.SourceRevision != source || source == "" {
		return errors.New("diagnostic source revision differs")
	}
	if err = kernel.Preflight(); err != nil {
		return err
	}
	raw, err := os.ReadFile(targetPath)
	if err != nil {
		return err
	}
	var target dockerplacement.Target
	if err = json.Unmarshal(raw, &target); err != nil {
		return err
	}
	if err = target.Validate(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	handles, err := dockerplacement.Open(ctx, target)
	if err != nil {
		return err
	}
	measured := handles.Measurement
	// Close the measured namespace handles on every path, including a refusal.
	if err = handles.Close(); err != nil {
		return err
	}
	if measured.ImageSourceRevision != source {
		return errors.New("target image source differs")
	}
	raw, err = os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	simpleMode := hostname == "--network-policy"
	var simple pocpolicy.Document
	var digest string
	var duration int
	hostObjects := len(os.Args) == 12
	var addr netip.Addr
	var ruleID string
	var publicPort uint16
	var document policy.Document
	launch := false
	if simpleMode {
		simple, err = pocpolicy.Parse(raw)
		if err != nil {
			return err
		}
		digest = simple.Digest()
		duration = simple.DurationSeconds
		launch = simple.IsLaunch()
		// A host-control policy without its objects, or objects without that
		// policy, would silently run with less or more than the operator wrote.
		if simple.HasHostControls() != hostObjects {
			return errors.New("filesystem and process objects must accompany exactly the policies that declare them")
		}
	} else {
		if hostObjects {
			return errors.New("host controls require the simple network policy format")
		}
		document, err = policy.Parse(raw, "json")
		if err != nil {
			return err
		}
		if document.Network == nil || document.Network.Pilot == nil {
			return errors.New("signed pilot network absent")
		}
		digest, err = document.Digest()
		if err != nil {
			return err
		}
		addr, err = netip.ParseAddr(address)
		if err != nil || !addr.IsGlobalUnicast() {
			return errors.New("public lease address differs")
		}
		for _, rule := range document.Network.Rules {
			if rule.Destination.Kind == "hostname" && rule.Destination.Value == hostname && rule.Effect == "allow" {
				if ruleID != "" || rule.Protocol != "tcp" || rule.PortFrom < 1 || rule.PortFrom != rule.PortTo {
					return errors.New("duplicate hostname rule")
				}
				ruleID = rule.ID
				publicPort = uint16(rule.PortFrom)
			}
		}
		if ruleID == "" {
			return errors.New("the public hostname is not signed")
		}

		duration = document.Lifecycle.DurationSeconds
	}
	if !ownedDiagnosticDomain(cgroup) {
		return errors.New("the diagnostic domain is not owned and root-level")
	}
	var stat syscall.Stat_t
	if err = syscall.Stat(cgroup, &stat); err != nil {
		return err
	}
	if stat.Ino == 0 {
		return errors.New("target cgroup has no inode")
	}
	now, err := kernel.MonotonicNS()
	if err != nil {
		return err
	}
	deadline := now + uint64(time.Duration(duration)*time.Second)

	var compiled netrules.Compiled
	var decisions map[string]netrules.Decision
	if simpleMode {
		compiled, err = simple.Compile(now, deadline)
		if err != nil {
			return err
		}
		decisions = map[string]netrules.Decision{}
	} else {
		lease := netrules.Lease{RuleID: ruleID, Hostname: hostname, Address: addr, Chain: []string{hostname}, ExpiresNS: deadline}
		compiled, err = netrules.Compile(*document.Network, 1, now, deadline, []netrules.Lease{lease})
		if err != nil {
			return err
		}
		decisions, err = pilotProbeDecisions(compiled.Policy, *document.Network.Pilot, addr, publicPort, now)
		if err != nil {
			return err
		}

	}
	object, err := os.ReadFile(objectPath)
	if err != nil {
		return err
	}
	objectDigest := sha256.Sum256(object)
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return err
	}
	if launch {
		// A long launch drains continuously; a larger ring absorbs bursts.
		ring := spec.Maps["net_events"]
		if ring == nil || ring.Type != ebpf.RingBuf {
			return errors.New("network object lacks ring buffer net_events")
		}
		ring.MaxEntries = launchNetworkRingBytes
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	defer collection.Close()
	for _, name := range []string{"net_policies", "net_events", "net_stats"} {
		if collection.Maps[name] == nil {
			return fmt.Errorf("mandatory BPF map absent: %s", name)
		}
	}
	if err = collection.Maps["net_policies"].Update(stat.Ino, compiled.Policy, ebpf.UpdateAny); err != nil {
		return err
	}
	links := []link.Link{}
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	for _, a := range networkAttachments {
		program := collection.Programs[a.name]
		if program == nil {
			return fmt.Errorf("mandatory BPF program absent: %s", a.name)
		}
		l, attachErr := link.AttachCgroup(link.CgroupOptions{Path: cgroup, Attach: a.kind, Program: program})
		if attachErr != nil {
			return fmt.Errorf("attach %s: %w", a.name, attachErr)
		}
		links = append(links, l)
	}
	reader, err := ringbuf.NewReader(collection.Maps["net_events"])
	if err != nil {
		return err
	}
	defer reader.Close()
	var network *networkTracker
	networkStop := make(chan struct{})
	networkDone := make(chan struct{})
	stopNetwork := sync.OnceFunc(func() { close(networkStop); <-networkDone })
	if launch {
		network = newNetworkTracker(stat.Ino, now)
		go func() {
			defer close(networkDone)
			drainNetwork(func(deadline time.Time) ([]byte, error) {
				reader.SetDeadline(deadline)
				record, readErr := reader.Read()
				return record.RawSample, readErr
			}, network, networkStop, func() uint64 { value, _ := kernel.MonotonicNS(); return value })
		}()
	} else {
		close(networkDone)
	}
	// The reader closes only after the drain goroutine has returned.
	defer stopNetwork()
	pins, err := pinGuard(cgroup, collection, links)
	if err != nil {
		return err
	}
	var host *hostGuard
	defer func() {
		empty, checkErr := domainIsEmpty(cgroup)
		if checkErr != nil {
			err = errors.Join(err, checkErr)
		} else if !empty {
			err = errors.Join(err, errors.New("diagnostic domain still populated; kernel pins retained"))
		} else {
			err = errors.Join(err, pins.release(), host.release())
		}
	}()
	if hostObjects {
		// The network links above must already be live: the filesystem plan lets
		// socket I/O through only after the kernel reports them on this cgroup.
		// No socket LSM guard is attached. Policies install before any hook attaches.
		if host, err = attachHost(simple, cgroup, stat.Ino, deadline, os.Args[10], os.Args[11]); err != nil {
			return err
		}
		defer host.close()
		if err = host.pin(); err != nil {
			return err
		}
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	out := receipt{Scope: "fixed-diagnostic-only; no normal admission", SourceRevision: source, BootID: strings.TrimSpace(string(boot)), PolicyDigest: digest, ObjectSHA256: hex.EncodeToString(objectDigest[:]), Target: measured, Domain: stat.Ino, DomainPath: cgroup, PinDir: pins.dir, RuleIDs: compiled.RuleIDs, MapDecisions: decisions, PublicHostname: hostname, PublicAddress: address, StartedMonoNS: now, DeadlineMonoNS: deadline, Events: []event{}}
	if launch {
		out.Mode, out.LifetimeSeconds = simple.Mode, simple.DurationSeconds
	}
	if err = os.WriteFile(readyPath, []byte("guard-attached\n"), 0600); err != nil {
		return err
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	// The signed execution cutoff stays unchanged. This extra bound (five
	// seconds for an SSH command, longer for a launch's graceful stop) bounds
	// diagnostic collection and is not a workload execution grant.
	limit := time.NewTimer(time.Duration(duration)*time.Second + cleanupBound(launch))
	defer limit.Stop()
	stopReason := "signal"
	select {
	case <-stop:
	case <-limit.C:
		// Keep the evidence: the receipt is still written, marked incomplete.
		stopReason = "cleanup_bound_exceeded"
	}
	signal.Stop(stop)
	out.Stop = stopReason
	out.FinishedMonoNS, _ = kernel.MonotonicNS()
	var collectErr error
	if launch {
		stopNetwork()
		countErr := collection.Maps["net_stats"].Lookup(uint32(0), &out.Counters)
		var stream networkStream
		out.Events, stream = network.finish(out.Counters, countErr)
		out.Network = &stream
		if countErr != nil {
			collectErr = countErr
		}
	} else {
		reader.SetDeadline(time.Now().Add(200 * time.Millisecond))
		out.Events, collectErr = collectNetworkEvents(func() ([]byte, error) {
			record, readErr := reader.Read()
			return record.RawSample, readErr
		}, maxNetworkEvents)
		if countErr := collection.Maps["net_stats"].Lookup(uint32(0), &out.Counters); countErr != nil {
			collectErr = errors.Join(collectErr, countErr)
		}
	}
	if launch {
		out.Scope = "experimental-launch-poc-only; no normal admission"
		out.Complete = out.Network.Complete
	} else if simpleMode {
		out.Scope = "experimental-network-poc-only; no normal admission"
		if hostObjects {
			out.Scope = "experimental-network-and-host-poc-only; no normal admission"
		}
		out.Complete = out.Counters.Lost == 0 && out.Counters.Decisions == uint64(len(out.Events))
		if len(out.Events) > 0 {
			out.Complete = completeGuardEvents(out.Events, out.Counters, out.Domain, out.StartedMonoNS, out.FinishedMonoNS)
		}
	} else {
		out.Complete = completePilotBoundary(out, *document.Network.Pilot, addr, publicPort)
	}
	if host != nil {
		evidence := host.finish()
		out.Host = &evidence
		out.Complete = out.Complete && evidence.Complete
	}
	if collectErr != nil {
		out.Complete = false
		out.CollectionError = collectErr.Error()
	}
	if stopReason != "signal" {
		out.Complete = false
	}
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(receiptPath, append(encoded, '\n'), 0600); err != nil {
		return err
	}
	if stopReason != "signal" {
		return errors.Join(collectErr, errors.New("diagnostic guard stop exceeded its cleanup bound"))
	}
	if collectErr != nil {
		return collectErr
	}
	if !out.Complete {
		return errors.New("network or host event loss, count mismatch, or malformed record")
	}
	return nil
}

// collectNetworkEvents reads until the reader's deadline. It returns every
// event read before an error, so the receipt is still written, marked incomplete.
func collectNetworkEvents(read func() ([]byte, error), limit int) ([]event, error) {
	events := []event{}
	for {
		raw, err := read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return events, nil
		}
		if err != nil {
			return events, err
		}
		if len(raw) != binary.Size(event{}) {
			return events, errors.New("network event ABI differs")
		}
		if len(events) >= limit {
			return events, errors.New("network event bound exceeded")
		}
		var e event
		if err = binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
			return events, err
		}
		events = append(events, e)
	}
}

// cleanupBound is the guard's collection bound after the policy window.
func cleanupBound(launch bool) time.Duration {
	if launch {
		return launchCleanupBound
	}
	return legacyCleanupBound
}

func main() {
	operation := run
	if len(os.Args) > 1 && (os.Args[1] == "policy" || os.Args[1] == "policy-digest") {
		operation = func() error { return policyCommand(os.Args[1:]) }
	}
	if len(os.Args) > 1 && os.Args[1] == "network-info" {
		operation = func() error { return networkPolicyCommand(os.Args[1:]) }
	}
	if command, ok := verifyCommands(os.Args[1:]); ok {
		operation = command
	}
	if err := operation(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

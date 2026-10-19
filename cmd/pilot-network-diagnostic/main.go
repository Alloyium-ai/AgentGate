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
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/buildinfo"
	"alloyium.local/kernel-poc/internal/dockerplacement"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
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
	Complete       bool                         `json:"complete"`
}

func run() (err error) {
	if len(os.Args) != 10 || os.Geteuid() != 0 {
		return errors.New("usage: pilot-network-guard TARGET POLICY OBJECT HOST ADDRESS READY RECEIPT SOURCE ROOT_DOMAIN_PATH")
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
	if measured.ImageSourceRevision != source {
		return errors.New("target image source differs")
	}
	if err = handles.Close(); err != nil {
		return err
	}
	raw, err = os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	document, err := policy.Parse(raw, "json")
	if err != nil {
		return err
	}
	if document.Network == nil || document.Network.Pilot == nil {
		return errors.New("signed pilot network absent")
	}
	digest, err := document.Digest()
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(address)
	if err != nil || !addr.IsGlobalUnicast() {
		return errors.New("public lease address differs")
	}
	var ruleID string
	var publicPort uint16
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
	deadline := now + uint64(time.Duration(document.Lifecycle.DurationSeconds)*time.Second)
	lease := netrules.Lease{RuleID: ruleID, Hostname: hostname, Address: addr, Chain: []string{hostname}, ExpiresNS: deadline}
	compiled, err := netrules.Compile(*document.Network, 1, now, deadline, []netrules.Lease{lease})
	if err != nil {
		return err
	}
	decisions, err := pilotProbeDecisions(compiled.Policy, *document.Network.Pilot, addr, publicPort, now)
	if err != nil {
		return err
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
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return err
	}
	defer collection.Close()
	if err = collection.Maps["net_policies"].Update(stat.Ino, compiled.Policy, ebpf.UpdateAny); err != nil {
		return err
	}
	attachments := []struct {
		name string
		kind ebpf.AttachType
	}{
		{"net_connect4", ebpf.AttachCGroupInet4Connect}, {"net_connect6", ebpf.AttachCGroupInet6Connect},
		{"net_sendmsg4", ebpf.AttachCGroupUDP4Sendmsg}, {"net_sendmsg6", ebpf.AttachCGroupUDP6Sendmsg},
		{"net_egress", ebpf.AttachCGroupInetEgress}, {"net_ingress", ebpf.AttachCGroupInetIngress},
	}
	links := []link.Link{}
	defer func() {
		for _, l := range links {
			_ = l.Close()
		}
	}()
	for _, a := range attachments {
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
	pins, err := pinGuard(cgroup, collection, links)
	if err != nil {
		return err
	}
	defer func() {
		empty, checkErr := domainIsEmpty(cgroup)
		if checkErr != nil {
			err = errors.Join(err, checkErr)
		} else if !empty {
			err = errors.Join(err, errors.New("diagnostic domain still populated; kernel pins retained"))
		} else {
			err = errors.Join(err, pins.release())
		}
	}()
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	out := receipt{Scope: "fixed-diagnostic-only; no normal admission", SourceRevision: source, BootID: strings.TrimSpace(string(boot)), PolicyDigest: digest, ObjectSHA256: hex.EncodeToString(objectDigest[:]), Target: measured, Domain: stat.Ino, DomainPath: cgroup, PinDir: pins.dir, RuleIDs: compiled.RuleIDs, MapDecisions: decisions, PublicHostname: hostname, PublicAddress: address, StartedMonoNS: now, DeadlineMonoNS: deadline, Events: []event{}}
	if err = os.WriteFile(readyPath, []byte("guard-attached\n"), 0600); err != nil {
		return err
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	// The signed execution cutoff stays unchanged. This extra five seconds
	// bounds diagnostic collection and is not a workload execution grant.
	limit := time.NewTimer(time.Duration(document.Lifecycle.DurationSeconds)*time.Second + 5*time.Second)
	defer limit.Stop()
	select {
	case <-stop:
	case <-limit.C:
		return errors.New("diagnostic guard stop exceeded its cleanup bound")
	}
	signal.Stop(stop)
	out.FinishedMonoNS, _ = kernel.MonotonicNS()
	reader.SetDeadline(time.Now().Add(200 * time.Millisecond))
	for {
		record, readErr := reader.Read()
		if errors.Is(readErr, os.ErrDeadlineExceeded) {
			break
		}
		if readErr != nil {
			return readErr
		}
		if len(record.RawSample) != binary.Size(event{}) {
			return errors.New("network event ABI differs")
		}
		var e event
		if err = binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &e); err != nil {
			return err
		}
		out.Events = append(out.Events, e)
		if len(out.Events) > 10000 {
			return errors.New("network event bound exceeded")
		}
	}
	if err = collection.Maps["net_stats"].Lookup(uint32(0), &out.Counters); err != nil {
		return err
	}
	out.Complete = completePilotBoundary(out, *document.Network.Pilot, addr, publicPort)
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(receiptPath, append(encoded, '\n'), 0600); err != nil {
		return err
	}
	if !out.Complete {
		return errors.New("network event loss or count mismatch")
	}
	return nil
}

func main() {
	operation := run
	if len(os.Args) > 1 && (os.Args[1] == "policy" || os.Args[1] == "policy-digest") {
		operation = func() error { return policyCommand(os.Args[1:]) }
	}
	if err := operation(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

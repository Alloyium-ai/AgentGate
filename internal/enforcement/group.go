// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package enforcement joins private components. Lifecycle admission remains separate.
package enforcement

import (
	"alloyium.local/kernel-poc/internal/anonrules"
	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/processrules"
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

type Artifacts struct{ Files, Peers, Sockets, Custody, Process, Anonymous string }
type Group struct {
	Files, Peers, Sockets, Custody, Process *kernel.Runtime
	Anonymous                               *kernel.Runtime
	mu                                      sync.Mutex
	generation                              uint64
	closed                                  bool
	dns                                     *dnsState
}

var peerHooks = []kernel.CgroupProgram{{Name: "net_connect4", Attach: ebpf.AttachCGroupInet4Connect}, {Name: "net_connect6", Attach: ebpf.AttachCGroupInet6Connect}, {Name: "net_sendmsg4", Attach: ebpf.AttachCGroupUDP4Sendmsg}, {Name: "net_sendmsg6", Attach: ebpf.AttachCGroupUDP6Sendmsg}, {Name: "net_egress", Attach: ebpf.AttachCGroupInetEgress}, {Name: "net_ingress", Attach: ebpf.AttachCGroupInetIngress}}
var socketHooks = []string{"operation_create", "operation_post_create", "operation_bind", "operation_listen", "operation_accept", "operation_send", "operation_receive", "operation_local_name", "operation_peer_name", "operation_shutdown", "operation_set_option", "operation_get_option", "operation_file_permission"}

type custodyBinding struct{ Generation, ExpiresNS uint64 }

func initialize(marker, policyName string, zero any) func(*kernel.Runtime) error {
	return func(r *kernel.Runtime) error {
		m := r.Collection.Maps[policyName]
		if m == nil {
			return fmt.Errorf("mandatory policy map absent: %s", policyName)
		}
		if marker != "" {
			owned := r.Collection.Maps[marker]
			if owned == nil {
				return fmt.Errorf("mandatory managed marker absent: %s", marker)
			}
			if err := owned.Update(r.ID, uint32(1), ebpf.UpdateNoExist); err != nil {
				return err
			}
		}
		return m.Update(r.ID, zero, ebpf.UpdateNoExist)
	}
}

// New attaches every deny-initialized component before an agent enters the domain.
// The caller must verify artifact hashes and retain the protected domain reservation.
func New(domain string, id uint64, artifacts Artifacts) (out *Group, err error) {
	if id == 0 {
		return nil, errors.New("an owned nonzero domain is required")
	}
	g := &Group{}
	defer func() {
		if err != nil {
			_ = g.Close()
		}
	}()
	if g.Files, err = kernel.AttachOwnedProfile(artifacts.Files, domain, "files", id, fsrules.AccessProfile()); err != nil {
		return nil, err
	}
	if artifacts.Anonymous != "" {
		profile, e := anonrules.Profile(g.Files)
		if e != nil {
			return nil, e
		}
		if g.Anonymous, err = kernel.AttachOwnedProfile(artifacts.Anonymous, domain, "anonymous", id, profile); err != nil {
			return nil, err
		}
	}
	if g.Process, err = kernel.AttachOwnedProfile(artifacts.Process, domain, "process", id, processrules.Profile()); err != nil {
		return nil, err
	}
	if g.Peers, err = kernel.AttachOwnedProfile(artifacts.Peers, domain, "peers", id, kernel.Profile{Initialize: initialize("", "net_policies", netrules.Policy{}), CgroupPrograms: append([]kernel.CgroupProgram{}, peerHooks...), EventsMap: "net_events", CountersMap: "net_stats"}); err != nil {
		return nil, err
	}
	if g.Custody, err = kernel.AttachOwnedProfile(artifacts.Custody, domain, "custody", id, kernel.Profile{Initialize: initialize("cust_managed", "cust_bindings", custodyBinding{}), LSMPrograms: []string{"custody_sendmsg", "custody_recvmsg"}, EventsMap: "cust_events", CountersMap: "cust_stats"}); err != nil {
		return nil, err
	}
	if g.Sockets, err = kernel.AttachOwnedProfile(artifacts.Sockets, domain, "sockets", id, kernel.Profile{Initialize: initialize("sock_managed", "sock_policies", netrules.SocketPlan{}), LSMPrograms: append([]string{}, socketHooks...), CgroupPrograms: []kernel.CgroupProgram{{Name: "operation_ingress", Attach: ebpf.AttachCGroupInetIngress}, {Name: "operation_egress", Attach: ebpf.AttachCGroupInetEgress}}, MapReplacements: map[string]*ebpf.Map{"net_policies": g.Peers.Collection.Maps["net_policies"]}, EventsMap: "sock_events", CountersMap: "sock_stats"}); err != nil {
		return nil, err
	}
	return g, nil
}
func (g *Group) components() []*kernel.Runtime {
	out := g.counterComponents()
	if g.Anonymous != nil {
		out = append(out, g.Anonymous)
	}
	return out
}

// The anonymous guard shares the file stream and counters. Count those once.
func (g *Group) counterComponents() []*kernel.Runtime {
	return []*kernel.Runtime{g.Files, g.Peers, g.Custody, g.Sockets, g.Process}
}
func (g *Group) Counters() (kernel.Counters, error) {
	var sum kernel.Counters
	for _, r := range g.counterComponents() {
		if r == nil {
			return sum, errors.New("a mandatory component is absent")
		}
		v, err := r.Counters()
		if err != nil {
			return sum, err
		}
		sum.Decisions += v.Decisions
		sum.Lost += v.Lost
	}
	return sum, nil
}
func (g *Group) StopRetain() error {
	for _, r := range g.components() {
		if r != nil && r.Domain != "" {
			return r.StopWorkload()
		}
	}
	return nil
}
func (g *Group) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	if err := g.StopRetain(); err != nil {
		return err
	}
	for _, r := range g.components() {
		if r != nil {
			if err := r.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"encoding/json"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/execbroker"
	"alloyium.local/kernel-poc/internal/syscallrules"

	"golang.org/x/sys/unix"
)

func listenerFixture() listenerReceipt {
	return listenerReceipt{Data: []byte("AGQSN001" + strings.Repeat("a", 64)), Control: append(unix.UnixRights(7), unix.UnixCredentials(&unix.Ucred{Pid: 42, Uid: 65534, Gid: 65534})...)}
}

func TestListenerCustodyRejectsChangedSenderBindingAndExtraDescriptors(t *testing.T) {
	r := listenerFixture()
	if fd, _, err := listenerCustody(r, 42, strings.Repeat("a", 64)); err != nil || fd != 7 {
		t.Fatal("the fixed credential frame differs", fd, err)
	}
	for name, change := range map[string]func(*listenerReceipt){
		"changed binding": func(r *listenerReceipt) { r.Data[8] = 'b' },
		"changed peer": func(r *listenerReceipt) {
			r.Control = append(unix.UnixRights(7), unix.UnixCredentials(&unix.Ucred{Pid: 43, Uid: 65534, Gid: 65534})...)
		},
		"wrong uid": func(r *listenerReceipt) {
			r.Control = append(unix.UnixRights(7), unix.UnixCredentials(&unix.Ucred{Pid: 42, Uid: 0, Gid: 65534})...)
		},
		"extra descriptor": func(r *listenerReceipt) { r.Control = append(r.Control, unix.UnixRights(8)...) },
		"duplicate credentials": func(r *listenerReceipt) {
			r.Control = append(r.Control, unix.UnixCredentials(&unix.Ucred{Pid: 42, Uid: 65534, Gid: 65534})...)
		},
		"truncated controls": func(r *listenerReceipt) { r.Flags = unix.MSG_CTRUNC },
	} {
		t.Run(name, func(t *testing.T) {
			r := listenerFixture()
			change(&r)
			if _, _, err := listenerCustody(r, 42, strings.Repeat("a", 64)); err == nil {
				t.Fatal("changed listener custody passed")
			}
		})
	}
}

func TestBrokerRawDecoderRejectsSummaryAndDuplicateClaims(t *testing.T) {
	for _, raw := range []string{`{"passed":true}`, `{"Continued":true,"continued":false}`, "{}\n\n{}\n"} {
		if _, err := brokerDecisions([]byte(raw)); err == nil {
			t.Fatal("a summary or ambiguous broker record passed")
		}
	}
}

func TestBrokerClosureRequiresActualExitFlagsIdentityAndEmptyControls(t *testing.T) {
	r := candidateReceipt{DomainID: 5, Generation: 1, EmptyReadback: "populated 0\nfrozen 0\n", Broker: brokerReceipt{StoppedMonoNS: 150}}
	closure := execbroker.ListenerClosure{Protocol: "agentgate.listener-closure.v1", Domain: 5, Generation: 1, DomainInode: 5, PollFlags: unix.POLLHUP, MonotonicNS: 120, Events: []byte(r.EmptyReadback), Empty: true}
	closure.Readbacks = []execbroker.ListenerPopulation{{MonotonicNS: 121, Events: []byte(r.EmptyReadback), Empty: true}}
	calls := []syscallrules.Event{{Type: syscallrules.TaskExit, ExitCode: 0, MonoNS: 110}}
	encode := func(c execbroker.ListenerClosure) { r.Broker.Diagnostic, _ = json.Marshal(c) }
	encode(closure)
	if err := verifyBrokerClosure(r, calls); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*execbroker.ListenerClosure){
		"invalid descriptor":   func(c *execbroker.ListenerClosure) { c.PollFlags = unix.POLLNVAL },
		"foreign inode":        func(c *execbroker.ListenerClosure) { c.DomainInode++ },
		"live population":      func(c *execbroker.ListenerClosure) { c.Events = []byte("populated 1\nfrozen 0\n") },
		"early final readback": func(c *execbroker.ListenerClosure) { c.Readbacks[0].MonotonicNS = 100 },
		"failed readback":      func(c *execbroker.ListenerClosure) { c.ReadbackError = "failed" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := closure
			changed.Readbacks = append([]execbroker.ListenerPopulation{}, closure.Readbacks...)
			change(&changed)
			encode(changed)
			if verifyBrokerClosure(r, calls) == nil {
				t.Fatal("a changed broker closure passed")
			}
		})
	}
	encode(closure)
	if verifyBrokerClosure(r, nil) == nil {
		t.Fatal("a missing actual workload exit passed")
	}
}

func TestBrokerClosurePreservesEarlyPopulationAndRequiresLaterEmptyWitness(t *testing.T) {
	r := candidateReceipt{DomainID: 5, Generation: 1, EmptyReadback: "populated 0\nfrozen 0\n", Broker: brokerReceipt{StoppedMonoNS: 150}}
	first := []byte("populated 1\nfrozen 0\n")
	c := execbroker.ListenerClosure{Protocol: "agentgate.listener-closure.v1", Domain: 5, Generation: 1, DomainInode: 5, PollFlags: unix.POLLHUP, MonotonicNS: 120, Events: first, Empty: false, Readbacks: []execbroker.ListenerPopulation{{MonotonicNS: 121, Events: first, Empty: false}, {MonotonicNS: 140, Events: []byte(r.EmptyReadback), Empty: true}}}
	calls := []syscallrules.Event{{Type: syscallrules.Result, MonoNS: 119}, {Type: syscallrules.TaskExit, MonoNS: 130, ExitCode: 0}}
	encode := func() { r.Broker.Diagnostic, _ = json.Marshal(c) }
	encode()
	if err := verifyBrokerClosure(r, calls); err != nil {
		t.Fatal(err)
	}
	c.Readbacks = c.Readbacks[:1]
	encode()
	if verifyBrokerClosure(r, calls) == nil {
		t.Fatal("the original live population passed without a later empty witness")
	}
}

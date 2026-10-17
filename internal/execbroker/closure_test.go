// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package execbroker

import (
	"encoding/json"
	"golang.org/x/sys/unix"
	"strings"
	"testing"
)

func TestListenerClosurePreservesExactFlagsAndReadback(t *testing.T) {
	e := ListenerClosure{Protocol: "agentgate.listener-closure.v1", Domain: 12, Generation: 3, MonotonicNS: 99, PollFlags: unix.POLLHUP | unix.POLLERR, DomainInode: 12, Events: []byte("populated 0\nfrozen 0\n"), Empty: true}
	var decoded ListenerClosure
	if err := json.Unmarshal([]byte(e.Error()), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.PollFlags != e.PollFlags || decoded.MonotonicNS != 99 || string(decoded.Events) != string(e.Events) || !decoded.Empty {
		t.Fatal("closure observation changed")
	}
}
func TestListenerClosureRejectsInvalidPopulation(t *testing.T) {
	for _, raw := range []string{"", "frozen 0\n", "populated 0\npopulated 0\n", "populated 2\n", "populated 0\nunknown 1\n", strings.Repeat(" ", 4097)} {
		if _, err := emptyClosureEvents([]byte(raw)); err == nil {
			t.Fatalf("invalid events accepted: %q", raw[:min(len(raw), 60)])
		}
	}
	for _, value := range []struct {
		raw   string
		empty bool
	}{{"populated 0\nfrozen 0\n", true}, {"populated 1\nfrozen 1\n", false}} {
		empty, err := emptyClosureEvents([]byte(value.raw))
		if err != nil || empty != value.empty {
			t.Fatal("population observation differs", err)
		}
	}
}

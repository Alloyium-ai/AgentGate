// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/processrules"
)

// The gateway and start-guard check pins against gateway.py's counts. Those
// counts must equal what this guard actually attaches and pins.
func TestGatewayLinkCountsMatchTheAttachedPrograms(t *testing.T) {
	raw, err := os.ReadFile("../../poc/ssh-diagnostic/gateway.py")
	if err != nil {
		t.Fatal(err)
	}
	count := func(name string) int {
		match := regexp.MustCompile(`(?m)^` + name + ` = (\d+)$`).FindSubmatch(raw)
		if match == nil {
			t.Fatalf("gateway.py lacks %s", name)
		}
		value, _ := strconv.Atoi(string(match[1]))
		return value
	}
	if got, want := count("NETWORK_LINKS"), len(networkAttachments); got != want {
		t.Fatalf("gateway.py NETWORK_LINKS=%d but the guard attaches %d", got, want)
	}
	host := len(fsrules.AccessProfile().LSMPrograms) + len(processrules.Programs())
	if got := count("HOST_LINKS"); got != host {
		t.Fatalf("gateway.py HOST_LINKS=%d but the guard attaches %d host hooks", got, host)
	}
}

func rawEvent(t *testing.T, sequence uint64) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := binary.Write(&out, binary.LittleEndian, event{Sequence: sequence}); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func fakeRing(records [][]byte, final error) func() ([]byte, error) {
	return func() ([]byte, error) {
		if len(records) == 0 {
			return nil, final
		}
		next := records[0]
		records = records[1:]
		return next, nil
	}
}

func TestNetworkCollectionKeepsEvidenceReadBeforeAnError(t *testing.T) {
	events, err := collectNetworkEvents(fakeRing([][]byte{rawEvent(t, 1), rawEvent(t, 2)}, os.ErrDeadlineExceeded), 10)
	if err != nil || len(events) != 2 || events[1].Sequence != 2 {
		t.Fatalf("idle ring: %v %+v", err, events)
	}
	events, err = collectNetworkEvents(fakeRing([][]byte{rawEvent(t, 1), {1, 2, 3}}, os.ErrDeadlineExceeded), 10)
	if err == nil || len(events) != 1 {
		t.Fatalf("malformed record: %v %d", err, len(events))
	}
	failure := errors.New("ring closed")
	events, err = collectNetworkEvents(fakeRing([][]byte{rawEvent(t, 1)}, failure), 10)
	if !errors.Is(err, failure) || len(events) != 1 {
		t.Fatalf("read failure: %v %d", err, len(events))
	}
	events, err = collectNetworkEvents(fakeRing([][]byte{rawEvent(t, 1), rawEvent(t, 2), rawEvent(t, 3)}, os.ErrDeadlineExceeded), 2)
	if err == nil || len(events) != 2 {
		t.Fatalf("bound: %v %d", err, len(events))
	}
}

func TestHostGuardCloseIsIdempotentAndJoinsReaders(t *testing.T) {
	host := &hostGuard{stopping: make(chan struct{})}
	finished := make(chan struct{})
	host.done.Add(1)
	go func() {
		defer host.done.Done()
		<-host.stopping
		close(finished)
	}()
	host.close()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("close returned before its reader stopped")
	}
	host.close()
	host.stop()
	var absent *hostGuard
	absent.close()
	if absent.release() != nil {
		t.Fatal("an absent host guard reported pins")
	}
}

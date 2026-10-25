// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"testing"

	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/processrules"
)

func fsTracker() *ringTracker {
	return newEvidence("fs_access.bpf.o", sha256.Sum256(nil), "plan", []string{"fs_open"}, binary.Size(fsEvent{}),
		func(raw []byte) (string, bool, denial, error) {
			var e fsEvent
			if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
				return "", false, denial{}, err
			}
			name := fsOperationName(e.Operation)
			return name, e.Allowed == 1, denial{Sequence: e.Sequence, PID: e.PID, Operation: name, Rule: e.Rule, Reason: e.Reason, Path: cString(e.Path[:])}, nil
		})
}

func rawFS(t *testing.T, e fsEvent) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := binary.Write(&out, binary.LittleEndian, e); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestEventLayoutsMatchTheKernelStructures(t *testing.T) {
	// struct event in bpf/fs_access.bpf.c: four u64, six u32, char path[160].
	if binary.Size(fsEvent{}) != 4*8+6*4+160 || binary.Size(fsEvent{}) != 216 {
		t.Fatalf("filesystem event is %d bytes", binary.Size(fsEvent{}))
	}
	// struct process_event in bpf/process_guard.bpf.c is asserted at 80 bytes.
	if binary.Size(processrules.Event{}) != 80 {
		t.Fatalf("process event is %d bytes", binary.Size(processrules.Event{}))
	}
}

func TestTrackerCountsOperationsAndKeepsDenials(t *testing.T) {
	tracker := fsTracker()
	var path [160]byte
	copy(path[:], "/etc/shadow")
	tracker.consume(rawFS(t, fsEvent{Sequence: 1, Operation: 0, Allowed: 1}))
	tracker.consume(rawFS(t, fsEvent{Sequence: 2, Operation: 0, Allowed: 0, Reason: 0, Rule: 0, PID: 7, Path: path}))
	tracker.consume(rawFS(t, fsEvent{Sequence: 3, Operation: 4, Allowed: 0, Reason: 7}))
	if tracker.Observed != 3 || tracker.failure != nil {
		t.Fatalf("observed %d failure %v", tracker.Observed, tracker.failure)
	}
	if got := tracker.Operations["read"]; got.Allowed != 1 || got.Denied != 1 {
		t.Fatalf("read counts differ: %+v", got)
	}
	if got := tracker.Operations["delete"]; got.Denied != 1 {
		t.Fatalf("delete counts differ: %+v", got)
	}
	if len(tracker.Denials) != 2 || tracker.Denials[0].Path != "/etc/shadow" || tracker.Denials[0].PID != 7 || tracker.Denials[1].Reason != 7 {
		t.Fatalf("denials differ: %+v", tracker.Denials)
	}
}

func TestTrackerBoundsDenialsButCountsEverything(t *testing.T) {
	tracker := fsTracker()
	for i := 0; i < maxDenials+50; i++ {
		tracker.consume(rawFS(t, fsEvent{Sequence: uint64(i + 1), Operation: 1, Allowed: 0}))
	}
	if tracker.Observed != uint64(maxDenials+50) || len(tracker.Denials) != maxDenials || !tracker.DenialsTruncated {
		t.Fatalf("bounded denials differ: %d %d %v", tracker.Observed, len(tracker.Denials), tracker.DenialsTruncated)
	}
	if tracker.Operations["write"].Denied != uint64(maxDenials+50) {
		t.Fatal("truncated denials were not counted")
	}
}

func TestTrackerRejectsMalformedRecordsAndHashesTheStream(t *testing.T) {
	tracker := fsTracker()
	tracker.consume([]byte{1, 2, 3})
	if tracker.failure == nil || tracker.Observed != 0 {
		t.Fatal("a short record was accepted")
	}
	a, b := fsTracker(), fsTracker()
	first, second := rawFS(t, fsEvent{Sequence: 1, Allowed: 1}), rawFS(t, fsEvent{Sequence: 2, Allowed: 1})
	a.consume(first)
	a.consume(second)
	b.consume(second)
	b.consume(first)
	if bytes.Equal(a.raw.Sum(nil), b.raw.Sum(nil)) {
		t.Fatal("the raw stream digest ignores event order")
	}
}

func TestFSOperationNamesCoverEveryHookOperation(t *testing.T) {
	for index, want := range map[uint32]string{0: "read", 1: "write", 2: "create", 3: "mkdir", 4: "delete", 5: "rename", 6: "hardlink", 7: "symlink", 8: "metadata", 11: "execute"} {
		if got := fsOperationName(index); got != want {
			t.Errorf("operation %d: got %s want %s", index, got, want)
		}
	}
	if fsOperationName(99) != "internal-99" {
		t.Fatal("an unknown operation was not labeled")
	}
}

func TestStdioGrantArgumentsAreExact(t *testing.T) {
	pipes, err := parseStdioPipes([]string{"11:read", "12:write", "13:write"})
	if err != nil || len(pipes) != 3 || pipes[0] != (fsrules.StdioPipe{Inode: 11, Rights: fsrules.StdioRead}) || pipes[2].Rights != fsrules.StdioWrite {
		t.Fatalf("pipes %+v: %v", pipes, err)
	}
	for _, args := range [][]string{{}, {"11"}, {"11:rw"}, {"011:read"}, {"-1:read"}, {"x:read"}, {"11:read", "11:write"},
		{"1:read", "2:write", "3:write", "4:write"}, {"0:write"}, {"11:read:extra"}} {
		if _, err := parseStdioPipes(args); err == nil {
			t.Fatalf("%v was accepted", args)
		}
	}
	if hostPinDir("/sys/fs/cgroup/ag-mvp-demo-domain") != "/sys/fs/bpf/ag-mvp-host-ag-mvp-demo-domain" {
		t.Fatal("the stdio grant would open another guard's pins")
	}
	open := t.TempDir()
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if checkPinDir(open) == nil || checkPinDir(open+"/absent") == nil {
		t.Fatal("a pin directory others can read, or an absent one, was accepted")
	}
	if stdioGrantCommand([]string{"stdio-grant", "/sys/fs/cgroup/../etc", "11:read"}) == nil {
		t.Fatal("a foreign domain was accepted")
	}
}

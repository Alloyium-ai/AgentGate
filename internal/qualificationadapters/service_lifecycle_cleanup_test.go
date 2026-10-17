// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func lifecycleStatFixture(pid int, ticks uint64) []byte {
	return []byte(fmt.Sprintf("%d (fixed worker) Z %s%d\n", pid, strings.Repeat("0 ", 18), ticks))
}

func TestLifecycleAfterRetainsTheActualMissingProcessErrno(t *testing.T) {
	command := exec.Command("/bin/true")
	if err := command.Run(); err != nil {
		t.Fatal(err)
	}
	pid := command.Process.Pid
	after := serviceLifecycleAfter([]processSnapshot{{PID: pid, StartTimeTicks: 1}})
	if len(after) != 1 || after[0].Errno != int(unix.ENOENT) || after[0].Error == "" {
		t.Fatal(after)
	}
	if !serviceLifecycleActorsTerminated([]processSnapshot{{PID: pid, StartTimeTicks: 1}}, after) {
		t.Fatal("an actual missing process lost its raw ENOENT outcome")
	}
}

func TestLifecycleStatParserRetainsZombieStartTimes(t *testing.T) {
	if ticks, err := serviceLifecycleStatTicks(lifecycleStatFixture(123, 456), 123); err != nil || ticks != 456 {
		t.Fatal(ticks, err)
	}
	if _, err := serviceLifecycleStatTicks(lifecycleStatFixture(124, 456), 123); err == nil {
		t.Fatal("a different PID supplied its start time")
	}
	raw, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	if ticks, err := serviceLifecycleStatTicks(raw, os.Getpid()); err != nil || ticks == 0 {
		t.Fatal(ticks, err)
	}
}

func TestLifecycleImageUsesTheImmutableDigest(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, input := range []string{digest, "registry.example/fixed-worker@" + digest} {
		actual, err := serviceLifecycleImageDigest(input)
		if err != nil || actual != digest {
			t.Fatal(actual, err)
		}
	}
	for _, input := range []string{"latest", "registry.example/fixed-worker:latest", "@" + digest, digest + "@extra", "registry.example/fixed worker@" + digest} {
		if _, err := serviceLifecycleImageDigest(input); err == nil {
			t.Fatal("the mutable or malformed image reached the manifest")
		}
	}
}

func TestLifecycleCleanupRequiresActualActorTermination(t *testing.T) {
	actors := []processSnapshot{{PID: 123, StartTimeTicks: 456}}
	cases := []struct {
		name  string
		after []serviceLifecycleAfterProcess
		want  bool
	}{
		{"missing", nil, false},
		{"alive", []serviceLifecycleAfterProcess{{PID: 123, StartTicks: 456, Status: "State:\tS (sleeping)\n"}}, false},
		{"unavailable", []serviceLifecycleAfterProcess{{PID: 123, Error: "permission denied", Errno: int(unix.EPERM)}}, false},
		{"absent", []serviceLifecycleAfterProcess{{PID: 123, Error: "no such process", Errno: int(unix.ENOENT)}}, true},
		{"reaped", []serviceLifecycleAfterProcess{{PID: 123, StartTicks: 456, Stat: lifecycleStatFixture(123, 456), Status: "State:\tZ (zombie)\n"}}, true},
		{"reused", []serviceLifecycleAfterProcess{{PID: 123, StartTicks: 999, Stat: lifecycleStatFixture(123, 999), Status: "State:\tS (sleeping)\n"}}, true},
		{"wrong-pid", []serviceLifecycleAfterProcess{{PID: 124, Error: "absent", Errno: int(unix.ENOENT)}}, false},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			if got := serviceLifecycleActorsTerminated(actors, item.after); got != item.want {
				t.Fatalf("got%v want%v", got, item.want)
			}
		})
	}
}

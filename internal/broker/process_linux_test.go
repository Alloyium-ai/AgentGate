//go:build linux

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func mkfifo(path string) error { return unix.Mkfifo(path, 0o600) }

func dupFD(f *os.File) (int, error) { return unix.Dup(int(f.Fd())) }

// TestDropPrivilegesInSubprocess runs the hardening and privilege drop in a
// child process (it cannot be undone in the test process) and checks the
// result from outside.
func TestDropPrivilegesInSubprocess(t *testing.T) {
	if os.Getenv("AGENTGATE_BROKER_DROP_HELPER") == "1" {
		dropHelper()
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("privilege drop needs root; not exercised as an unprivileged user")
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "root-only")
	if err := os.WriteFile(secret, []byte(testSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDropPrivilegesInSubprocess$", "-test.v=false")
	cmd.Env = append(os.Environ(), "AGENTGATE_BROKER_DROP_HELPER=1", "AGENTGATE_BROKER_DROP_FILE="+secret)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper: %v", err)
	}
	var got struct {
		Hardening        Hardening
		Drop             string
		UID, EUID, GID   int
		RootFileReadable bool
		RegainedRoot     bool
	}
	line := out
	if i := indexJSON(out); i >= 0 {
		line = out[i:]
	}
	if err := json.Unmarshal(firstLine(line), &got); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got.Drop != "" || got.UID != 65534 || got.EUID != 65534 || got.GID != 65534 || got.RootFileReadable || got.RegainedRoot {
		t.Fatalf("%+v", got)
	}
	h := got.Hardening
	if !h.NotDumpable || !h.CoreLimitZero {
		t.Fatalf("hardening %+v", h)
	}
}

func indexJSON(b []byte) int {
	for i, c := range b {
		if c == '{' {
			return i
		}
	}
	return -1
}

func firstLine(b []byte) []byte {
	for i, c := range b {
		if c == '\n' {
			return b[:i]
		}
	}
	return b
}

func dropHelper() {
	h := HardenProcess()
	result := map[string]any{"Hardening": h}
	if err := DropPrivileges(&Identity{UID: 65534, GID: 65534}); err != nil {
		result["Drop"] = err.Error()
	} else {
		result["Drop"] = ""
	}
	result["UID"], result["EUID"], result["GID"] = os.Getuid(), os.Geteuid(), os.Getgid()
	_, err := os.ReadFile(os.Getenv("AGENTGATE_BROKER_DROP_FILE"))
	result["RootFileReadable"] = err == nil
	result["RegainedRoot"] = syscall.Setuid(0) == nil
	raw, _ := json.Marshal(result)
	os.Stdout.Write(append(raw, '\n'))
	os.Exit(0)
}

func TestDropPrivilegesRefusesRootWithoutIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		// Not root: the identity must already match.
		if err := DropPrivileges(&Identity{UID: os.Geteuid() + 1, GID: os.Getegid()}); err == nil {
			t.Fatal("mismatched identity accepted")
		}
		return
	}
	if err := DropPrivileges(nil); err == nil {
		t.Fatal("broker would serve as root")
	}
}

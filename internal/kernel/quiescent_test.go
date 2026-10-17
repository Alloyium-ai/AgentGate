// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package kernel

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestQuiescenceChecksEveryProcessThreadAndChildDomain(t *testing.T) {
	cmd := exec.Command("sh", "-c", "kill -STOP $$; exit 0")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(2 * time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for stoppedSingleThread(cmd.Process.Pid) != nil {
		if time.Now().After(deadline) {
			t.Fatal("the fixture did not stop")
		}
		<-tick.C
	}
	domain := t.TempDir()
	var st syscall.Stat_t
	if err := syscall.Stat(domain, &st); err != nil {
		t.Fatal(err)
	}
	r := &Runtime{Domain: domain, ID: st.Ino}
	path := filepath.Join(domain, "cgroup.procs")
	write := func(raw string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(strconv.Itoa(cmd.Process.Pid) + "\n")
	checks := 0
	verify := func() error { checks++; return nil }
	if err := r.VerifyQuiescent(verify); err != nil || checks < 2 {
		t.Fatalf("the measured single held process failed: %v", err)
	}
	write("")
	if r.VerifyQuiescent(verify) == nil {
		t.Fatal("an empty domain substituted for the placed helper")
	}
	write(strconv.Itoa(cmd.Process.Pid) + "\n" + strconv.Itoa(os.Getpid()) + "\n")
	if r.VerifyQuiescent(verify) == nil {
		t.Fatal("an extra process entered the installation window")
	}
	write(strconv.Itoa(os.Getpid()) + "\n")
	if r.VerifyQuiescent(verify) == nil {
		t.Fatal("a live process entered the installation window")
	}
	write(strconv.Itoa(cmd.Process.Pid) + "\n")
	if err := os.Mkdir(filepath.Join(domain, "descendant"), 0700); err != nil {
		t.Fatal(err)
	}
	if r.VerifyQuiescent(verify) == nil {
		t.Fatal("an unverified descendant domain was accepted")
	}
	os.Remove(filepath.Join(domain, "descendant"))
	r.ID++
	if r.VerifyQuiescent(verify) == nil {
		t.Fatal("a changed domain inode was accepted")
	}
	r.ID--
	if r.VerifyQuiescent(nil) == nil || r.VerifyQuiescent(func() error { return errors.New("changed helper") }) == nil {
		t.Fatal("the measured helper verifier was optional")
	}
}

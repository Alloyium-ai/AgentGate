// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package workload

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

var execProbe = flag.Bool("workload-exec-probe", false, "run the owned privilege probe")
var execWitness = flag.Bool("workload-exec-witness", false, "run the owned set-user-ID witness")

// Each helper runs in its own process. Its UID changes never reach the test runner.
func TestWorkloadExecProbe(t *testing.T) {
	if !*execProbe && !*execWitness {
		return
	}
	flags, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if *execWitness {
		if os.Getuid() != 65534 || os.Geteuid() != 0 || flags != 0 {
			t.Fatalf("set-user-ID witness unavailable: uid=%d euid=%d nnp=%d", os.Getuid(), os.Geteuid(), flags)
		}
		return
	}
	if os.Getuid() != 65534 || os.Geteuid() != 65534 || os.Getgid() != 65534 || flags != 1 {
		t.Fatalf("exec lost the privilege boundary: uid=%d euid=%d gid=%d nnp=%d", os.Getuid(), os.Geteuid(), os.Getgid(), flags)
	}
	if err = syscall.Setuid(0); !errors.Is(err, syscall.EPERM) {
		t.Fatalf("exec restored UID0: %v", err)
	}
}
func TestWorkloadExecHelper(t *testing.T) {
	if os.Getenv("AGENTGATE_CHILD_EXEC_HELPER") != "1" {
		return
	}
	runtime.GOMAXPROCS(8)
	for i := 0; i < 32; i++ {
		go func() {
			for {
				runtime.Gosched()
			}
		}()
	}
	job := Job{Executable: os.Getenv("AGENTGATE_CHILD_EXEC_FILE"), Arguments: []string{"-test.run=^TestWorkloadExecProbe$", "-workload-exec-probe"}, Workspace: os.Getenv("AGENTGATE_CHILD_EXEC_WORKSPACE")}
	err := execChild(job, func(job Job) error {
		tid := unix.Gettid()
		if err := restrictChild(job); err != nil {
			return err
		}
		for i := 0; i < 1024; i++ {
			runtime.Gosched()
			if unix.Gettid() != tid {
				return errors.New("security setup moved to another OS thread")
			}
		}
		runtime.GC()
		if unix.Gettid() != tid {
			return errors.New("security setup moved after garbage collection")
		}
		return nil
	})
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
func TestLockedExecRetainsNoNewPrivilegesUnderScheduling(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("the privilege boundary fixture requires an owned root test container")
	}
	flags, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags != 0 {
		t.Skip("the fixture must start before no-new-privileges to prove the exec boundary")
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	// t.TempDir's parent also needs traversal for the dropped UID in the owned fixture.
	if err = os.Chmod(filepath.Dir(root), 0755); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(root, "privilege-probe")
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(target, source); err != nil {
		target.Close()
		t.Fatal(err)
	}
	target.Close()
	if err = os.Chmod(probe, 0755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	witness := exec.Command(probe, "-test.run=^TestWorkloadExecProbe$", "-workload-exec-witness")
	witness.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	if output, err := witness.CombinedOutput(); err != nil {
		t.Fatalf("the owned set-user-ID witness failed: %v %s", err, output)
	}
	for attempt := 0; attempt < 8; attempt++ {
		command := exec.Command(executable, "-test.run=^TestWorkloadExecHelper$")
		command.Env = append(os.Environ(), "AGENTGATE_CHILD_EXEC_HELPER=1", "AGENTGATE_CHILD_EXEC_FILE="+probe, "AGENTGATE_CHILD_EXEC_WORKSPACE="+root)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("scheduled exec attempt%d failed: %v %s", attempt, err, output)
		}
	}
	data, _ := json.Marshal(map[string]any{"attempts": 8, "setuid_witness": true, "exec_uid": 65534, "no_new_privs": 1})
	t.Log(string(data))
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"alloyium.local/kernel-poc/internal/kernel"
)

type crashState struct {
	Domain string `json:"domain"`
	Root   string `json:"root"`
	Boot   string `json:"boot"`
}

func crash(args []string) error {
	if len(args) != 2 {
		return errors.New("crash requires BPF object and fresh output directory")
	}
	if err := kernel.Preflight(); err != nil {
		return err
	}
	root, err := filepath.Abs(args[1])
	if err != nil {
		return err
	}
	if err = fixture(root); err != nil {
		return err
	}
	r, err := kernel.New(args[0], "/sys/fs/cgroup/alloyium-poc-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err != nil {
		return err
	}
	// Errors clean up; os.Exit deliberately bypasses this defer after release.
	defer r.Close()
	now, err := kernel.MonotonicNS()
	if err != nil {
		return err
	}
	p := kernel.Policy{Generation: 1, ExpiresNS: now + uint64(2*time.Second), AllowedIP: 0x0100007f, AllowedPort: 0xa146}
	copy(p.Workspace[:], root+"/workspace/")
	if err = r.Install(p); err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	state, _ := json.Marshal(crashState{r.Domain, root, string(boot)})
	if err = os.WriteFile(filepath.Join(root, "crash.json"), state, 0600); err != nil {
		return err
	}
	rd, wr, err := os.Pipe()
	if err != nil {
		return err
	}
	defer rd.Close()
	defer wr.Close()
	output, err := os.OpenFile(filepath.Join(root, "worker.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer output.Close()
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, "worker", "expiry", root, "18081", "18082")
	cmd.ExtraFiles = []*os.File{rd}
	cmd.Stdout = output
	cmd.Stderr = output
	if err = cmd.Start(); err != nil {
		return err
	}
	if err = r.Move(cmd.Process.Pid); err != nil {
		return err
	}
	if _, err = wr.Write([]byte{1}); err != nil {
		return err
	}
	fmt.Println("CRASH_FIXTURE_RELEASED: expected exit 86; kernel attachments stay pinned")
	os.Exit(86)
	return nil
}

func recoverRun(args []string) error {
	if len(args) != 1 {
		return errors.New("recover requires the crash output directory")
	}
	body, err := os.ReadFile(filepath.Join(args[0], "crash.json"))
	if err != nil {
		return err
	}
	var state crashState
	if err = json.Unmarshal(body, &state); err != nil {
		return err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	if state.Boot != string(boot) {
		return errors.New("recovery belongs to another VM boot")
	}
	r, err := kernel.Recover(state.Domain)
	if err != nil {
		return err
	}
	defer r.Close()
	events, err := r.Drain()
	if err != nil {
		return err
	}
	stats, err := r.Counters()
	if err != nil {
		return err
	}
	if len(events) != 4 || stats.Decisions != 4 || stats.Lost != 0 {
		return fmt.Errorf("expiry evidence differs: events=%d stats=%+v", len(events), stats)
	}
	for _, e := range events {
		if e.Allowed != 0 || e.Cgroup != r.ID {
			return errors.New("kernel expiry or domain binding differs")
		}
	}
	output, err := os.ReadFile(filepath.Join(state.Root, "worker.jsonl"))
	if err != nil {
		return err
	}
	fmt.Print(string(output))
	for path, want := range map[string]string{"workspace/result": "initial\n", "outside/canary": "unchanged\n"} {
		value, err := os.ReadFile(filepath.Join(state.Root, path))
		if err != nil {
			return err
		}
		if string(value) != want {
			return errors.New("expiry effect check failed")
		}
	}
	if err = r.Close(); err != nil {
		return err
	}
	fmt.Println("DAEMON_INDEPENDENT_EXPIRY_PASS decisions=4; CLEANUP_PASS; audit=INCOMPLETE (no terminal seal)")
	return nil
}

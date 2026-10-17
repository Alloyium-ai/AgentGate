// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"alloyium.local/kernel-poc/internal/audit"
	"alloyium.local/kernel-poc/internal/grant"
	"alloyium.local/kernel-poc/internal/kernel"
)

type service struct {
	listener net.Listener
	count    atomic.Uint64
}

func listen(port int) (*service, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return nil, err
	}
	s := &service{listener: l}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			s.count.Add(1)
			c.Close()
		}
	}()
	return s, nil
}

func fixture(root string) error {
	if err := os.Mkdir(root, 0755); err != nil {
		return err
	}
	for _, dir := range []string{"workspace", "outside"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0777); err != nil {
			return err
		}
		if err := os.Chmod(filepath.Join(root, dir), 0777); err != nil {
			return err
		}
	}
	for path, data := range map[string]string{"workspace/result": "initial\n", "outside/canary": "unchanged\n"} {
		name := filepath.Join(root, path)
		if err := os.WriteFile(name, []byte(data), 0666); err != nil {
			return err
		}
		if err := os.Chmod(name, 0666); err != nil {
			return err
		}
	}
	return nil
}

func launch(r *kernel.Runtime, root, mode string) (string, error) {
	return launchPorts(r, root, mode, 18081, 18082)
}
func launchPorts(r *kernel.Runtime, root, mode string, allow, deny int) (string, error) {
	rd, wr, err := os.Pipe()
	if err != nil {
		return "", err
	}
	defer rd.Close()
	defer wr.Close()
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	cmd := exec.Command(exe, "worker", mode, root, strconv.Itoa(allow), strconv.Itoa(deny))
	cmd.ExtraFiles = []*os.File{rd}
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err = cmd.Start(); err != nil {
		return "", err
	}
	defer cmd.Process.Kill()
	if err = r.Move(cmd.Process.Pid); err != nil {
		return "", err
	}
	if _, err = wr.Write([]byte{1}); err != nil {
		return "", err
	}
	err = cmd.Wait()
	return output.String(), err
}

func probe(args []string, signed bool, mode string) error {
	want := 2
	if signed {
		want = 3
	}
	if len(args) != want {
		return errors.New("probe requires BPF object, fresh output directory, and keys directory for demo")
	}
	if err := kernel.Preflight(); err != nil {
		return err
	}
	root, err := filepath.Abs(args[1])
	if err != nil {
		return err
	}
	if strings.HasPrefix(root, "/tmp") || len(root)+32 >= kernel.PathSize {
		return errors.New("invalid fixture path")
	}
	if err = fixture(root); err != nil {
		return err
	}
	allow, err := listen(18081)
	if err != nil {
		return err
	}
	defer allow.listener.Close()
	deny, err := listen(18082)
	if err != nil {
		return err
	}
	defer deny.listener.Close()
	r, err := kernel.New(args[0], "/sys/fs/cgroup/alloyium-poc-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err != nil {
		return err
	}
	defer r.Close()
	now, err := kernel.MonotonicNS()
	if err != nil {
		return err
	}
	p := kernel.Policy{Generation: 1, ExpiresNS: now + uint64(30*time.Second), AllowedIP: binary.LittleEndian.Uint32(net.ParseIP("127.0.0.1").To4())}
	// user_port is a network-order 16-bit value stored in a 32-bit field.
	p.AllowedPort = uint32(18081>>8 | (18081&255)<<8)
	copy(p.Workspace[:], root+"/workspace/")
	expectedEvents := 8
	expectedGeneration := uint64(1)
	expectedConnections := uint64(2)
	expectedWorkspace := "allowed\n"
	if mode == "quarantine" {
		p = kernel.Policy{}
		expectedEvents = 4
		expectedGeneration = 0
		expectedConnections = 0
		expectedWorkspace = "initial\n"
	}
	if mode == "flood" {
		expectedConnections = 0
		expectedWorkspace = "initial\n"
	}
	var keys grant.Keys
	var claims grant.Claims
	var token string
	if signed {
		keys, err = grant.Load(args[2])
		if err != nil {
			return err
		}
		claims, token, err = admit(keys, root, r.ID, p.ExpiresNS, args[2])
		if err != nil {
			return err
		}
	}
	if err = r.Install(p); err != nil {
		return err
	}
	output, runErr := launch(r, root, mode)
	fmt.Print(output)
	events, err := r.Drain()
	if err != nil {
		return err
	}
	stats, err := r.Counters()
	if err != nil {
		return err
	}
	report := map[string]any{"cgroup_id": strconv.FormatUint(r.ID, 10), "events": events, "counters": stats, "allowed_server": allow.count.Load(), "denied_server": deny.count.Load()}
	body, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(root, "probe.json"), body, 0600); err != nil {
		return err
	}
	if runErr != nil {
		return fmt.Errorf("worker: %w", runErr)
	}
	canary, err := os.ReadFile(filepath.Join(root, "outside/canary"))
	if err != nil {
		return err
	}
	workspace, err := os.ReadFile(filepath.Join(root, "workspace/result"))
	if err != nil {
		return err
	}
	if string(canary) != "unchanged\n" || string(workspace) != expectedWorkspace || deny.count.Load() != 0 || allow.count.Load() != expectedConnections {
		return errors.New("independent effect check failed")
	}
	if mode == "flood" {
		if stats.Lost == 0 || stats.Decisions != 10000 || stats.Decisions != uint64(len(events))+stats.Lost {
			return errors.New("ring saturation differs from declared loss")
		}
	} else if stats.Lost != 0 || stats.Decisions != uint64(len(events)) || len(events) != expectedEvents {
		return fmt.Errorf("audit counts differ: %+v, events=%d", stats, len(events))
	}
	for _, e := range events {
		if e.Cgroup != r.ID || e.Generation != expectedGeneration {
			return errors.New("kernel binding differs from launcher binding")
		}
	}
	if signed {
		object, err := os.ReadFile(args[0])
		if err != nil {
			return err
		}
		if err = audit.Save(root, token, claims, events, stats, keys, grant.Digest(object), "completed"); err != nil {
			return err
		}
		verdict, err := audit.Verify(root, keys.Trust)
		if mode == "flood" {
			if verdict != audit.Incomplete {
				return errors.New("loss verifier accepted incomplete observations")
			}
		} else if err != nil {
			return err
		}
		fmt.Println(verdict)
	}
	label := "G1_SMALL_PROBE_PASS"
	if mode == "quarantine" {
		label = "QUARANTINE_PASS"
	}
	if mode == "flood" {
		label = "KERNEL_LOSS_PASS"
		fmt.Printf("kernel_decisions=%d kernel_lost=%d\n", stats.Decisions, stats.Lost)
	}
	fmt.Printf("%s events=%d allowed_server=%d denied_server=%d cgroup=%d\n", label, len(events), allow.count.Load(), deny.count.Load(), r.ID)
	if err = r.Close(); err != nil {
		return err
	}
	fmt.Println("CLEANUP_PASS")
	return nil
}

func admit(keys grant.Keys, root string, domain, deadline uint64, state string) (grant.Claims, string, error) {
	var c grant.Claims
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return c, "", err
	}
	node, err := os.Hostname()
	if err != nil {
		return c, "", err
	}
	nonce, err := grant.Nonce()
	if err != nil {
		return c, "", err
	}
	now := time.Now().Unix()
	c = grant.Claims{Issuer: grant.Issuer, Audience: grant.Audience, Deployment: "disposable-dev-poc", Node: node, Boot: strings.TrimSpace(string(boot)), Run: filepath.Base(root), Domain: strconv.FormatUint(domain, 10), Agent: "synthetic-worker-1", AgentKey: keys.Trust.Agent, JobDigest: grant.Digest([]byte("deterministic-existing-file-and-ipv4-tcp-fixture-v1")), Generation: "1", Workspace: root + "/workspace/", Endpoint: "127.0.0.1:18081", DeadlineNS: strconv.FormatUint(deadline, 10), Issued: now, Expires: now + 30, Nonce: nonce}
	token, err := grant.Sign(c, keys.Authority)
	if err != nil {
		return c, "", err
	}
	pub, err := grant.Public(keys.Trust.Authority)
	if err != nil {
		return c, "", err
	}
	if _, err = grant.Verify(token, pub, c, now); err != nil {
		return c, "", err
	}
	if err = grant.Consume(filepath.Join(state, "admissions"), c, token); err != nil {
		return c, "", err
	}
	return c, token, nil
}

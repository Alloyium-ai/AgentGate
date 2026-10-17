// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/audit"
	"alloyium.local/kernel-poc/internal/controlclient"
	"alloyium.local/kernel-poc/internal/grant"
	"alloyium.local/kernel-poc/internal/kernel"
)

type controllerAdmission struct {
	ID        string `json:"id"`
	RequestID string `json:"request_id"`
	RunID     string `json:"run_id"`
	AgentID   string `json:"agent_id"`
	VersionID string `json:"version_id"`
	Digest    string `json:"policy_digest"`
	Token     string `json:"grant"`
	State     string `json:"state"`
}
type controllerEvidence struct {
	Grant    string          `json:"grant"`
	Events   string          `json:"events"`
	Terminal json.RawMessage `json:"terminal"`
}

func controlled(args []string) error {
	if len(args) != 3 {
		return errors.New("controlled requires BPF object, fresh output directory and private controller configuration")
	}
	if err := kernel.Preflight(); err != nil {
		return err
	}
	var cfg controlclient.Config
	data, err := os.ReadFile(args[2])
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	client, err := controlclient.New(cfg)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(args[1])
	if err != nil {
		return err
	}
	if len(root)+32 >= kernel.PathSize {
		return errors.New("fixture path too long")
	}
	if err = fixture(root); err != nil {
		return err
	}
	a, err := listen(18081)
	if err != nil {
		return err
	}
	defer a.listener.Close()
	b, err := listen(18082)
	if err != nil {
		return err
	}
	defer b.listener.Close()
	r, err := kernel.New(args[0], "/sys/fs/cgroup/alloyium-poc-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err != nil {
		return err
	}
	defer r.Close()
	now, err := kernel.MonotonicNS()
	if err != nil {
		return err
	}
	deadline := now + uint64(30*time.Second)
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	// The deployed kernel exposes the standard boot identity below /proc/sys/kernel/random.
	if err != nil {
		return err
	}
	node, err := os.Hostname()
	if err != nil {
		return err
	}
	runID := filepath.Base(root)
	input := map[string]string{"request_id": cfg.RequestID, "run_id": runID, "node": node, "boot": strings.TrimSpace(string(boot)), "cgroup": strconv.FormatUint(r.ID, 10), "workspace": root + "/workspace/", "deadline_ns": strconv.FormatUint(deadline, 10), "reason": "Admit the exact human-approved synthetic fixture"}
	var admitted controllerAdmission
	key, _ := grant.Nonce()
	if err = client.Call("admissions", "POST", key, input, &admitted); err != nil {
		return err
	}
	released := false
	defer func() {
		if !released {
			key, _ := grant.Nonce()
			client.Call("admissions/"+admitted.ID+"/release", "POST", key, map[string]string{"state": "released", "reason": "Dispose a failed synthetic admission"}, nil)
		}
	}()
	claims, err := verifyAdmission(admitted, cfg, node, strings.TrimSpace(string(boot)), runID, r.ID, root, deadline)
	if err != nil {
		return err
	}
	if err = grant.Consume(filepath.Join(filepath.Dir(args[2]), "admissions"), claims, admitted.Token); err != nil {
		return err
	}
	endpoint, portText, err := net.SplitHostPort(claims.Endpoint)
	if err != nil || endpoint != "127.0.0.1" {
		return errors.New("controller endpoint exceeds the fixture ceiling")
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		return err
	}
	denyPort := 18082
	allow, deny := a, b
	if port == 18082 {
		denyPort = 18081
		allow, deny = b, a
	}
	p := kernel.Policy{Generation: 1, ExpiresNS: deadline, AllowedIP: 0x0100007f, AllowedPort: uint32(port>>8 | (port&255)<<8)}
	if !claims.ReadOnly {
		copy(p.Workspace[:], root+"/workspace/")
	}
	if err = r.Install(p); err != nil {
		return err
	}
	object, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	key, _ = grant.Nonce()
	var confirmed controllerAdmission
	if err = client.Call("admissions/"+admitted.ID+"/activate", "POST", key, map[string]string{"version_id": admitted.VersionID, "policy_digest": admitted.Digest, "bpf_digest": grant.Digest(object), "reason": "Confirm the installed immutable kernel policy before release"}, &confirmed); err != nil {
		return err
	}
	if confirmed.ID != admitted.ID || confirmed.RunID != admitted.RunID || confirmed.VersionID != admitted.VersionID || confirmed.Digest != admitted.Digest || confirmed.State != "admitted" {
		return errors.New("the installation confirmation differs from this admission")
	}
	mode := "bootstrap"
	if claims.ReadOnly {
		mode = "read-only"
	}
	output, runErr := launchPorts(r, root, mode, port, denyPort)
	fmt.Print(output)
	events, err := r.Drain()
	if err != nil {
		return err
	}
	stats, err := r.Counters()
	if err != nil {
		return err
	}
	if runErr != nil {
		return runErr
	}
	if stats.Lost != 0 || stats.Decisions != 8 || len(events) != 8 || allow.count.Load() != 2 || deny.count.Load() != 0 {
		return errors.New("controlled fixture effects or audit counts differ")
	}
	for _, e := range events {
		if e.Cgroup != r.ID || e.Generation != 1 {
			return errors.New("controlled fixture generation differs")
		}
	}
	canary, err := os.ReadFile(filepath.Join(root, "outside/canary"))
	if err != nil {
		return err
	}
	workspace, err := os.ReadFile(filepath.Join(root, "workspace/result"))
	if err != nil {
		return err
	}
	want := "allowed\n"
	if claims.ReadOnly {
		want = "initial\n"
	}
	if string(canary) != "unchanged\n" || string(workspace) != want {
		return errors.New("controlled filesystem observations differ")
	}
	keys := grant.Keys{Node: client.Key, Trust: grant.Trust{Authority: cfg.Authority, Node: controlclient.EncodeKey(client.Key.Public().(ed25519.PublicKey)), Agent: cfg.AgentKey}}
	if err = audit.Save(root, admitted.Token, claims, events, stats, keys, grant.Digest(object), "completed"); err != nil {
		return err
	}
	stream, err := os.ReadFile(filepath.Join(root, "events.jsonl"))
	if err != nil {
		return err
	}
	terminal, err := os.ReadFile(filepath.Join(root, "terminal.json"))
	if err != nil {
		return err
	}
	evidence := controllerEvidence{admitted.Token, string(stream), terminal}
	payload := map[string]any{"admission_id": admitted.ID, "evidence": evidence, "reason": "Retain the signed synthetic kernel decision evidence"}
	var seal audit.Seal
	key, _ = grant.Nonce()
	if err = client.Call("evidence/receipt", "POST", key, payload, &seal); err != nil {
		return err
	}
	terminal, err = json.Marshal(seal)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(root, "terminal.json"), terminal, 0600); err != nil {
		return err
	}
	evidence.Terminal = terminal
	payload["evidence"] = evidence
	verdict, err := audit.Verify(root, keys.Trust)
	if err != nil || verdict != audit.Complete {
		return fmt.Errorf("controller receipt verification failed: %s %v", verdict, err)
	}
	if err = r.Close(); err != nil {
		return err
	}
	key, _ = grant.Nonce()
	if err = client.Call("evidence", "POST", key, payload, nil); err != nil {
		return err
	}
	key, _ = grant.Nonce()
	if err = client.Call("admissions/"+admitted.ID+"/release", "POST", key, map[string]string{"state": "released", "reason": "The synthetic domain is empty and its enforcement objects are removed"}, nil); err != nil {
		return err
	}
	released = true
	fmt.Printf("CONTROL_PLANE_KERNEL_PASS run=%s policy=%s digest=%s verifier=%s\n", runID, admitted.VersionID, admitted.Digest, verdict)
	return nil
}
func verifyAdmission(a controllerAdmission, cfg controlclient.Config, node, boot, run string, id uint64, root string, deadline uint64) (grant.Claims, error) {
	var c grant.Claims
	parts := strings.Split(a.Token, ".")
	if len(parts) != 3 {
		return c, errors.New("invalid controller grant")
	}
	data, err := controlclient.Decode(parts[1])
	if err != nil {
		return c, err
	}
	if err = json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	if a.RequestID != cfg.RequestID || a.RunID != run || a.AgentID != cfg.Agent || a.State != "issued" || c.Node != node || c.Boot != boot || c.Domain != strconv.FormatUint(id, 10) || c.Run != run || c.Agent != cfg.Agent || c.AgentKey != cfg.AgentKey || c.Workspace != root+"/workspace/" || c.DeadlineNS != strconv.FormatUint(deadline, 10) || c.PolicyVersion != a.VersionID || c.PolicyDigest != a.Digest || c.Nonce != a.ID {
		return c, errors.New("controller grant differs from the trusted launch enrollment")
	}
	key, err := grant.Public(cfg.Authority)
	if err != nil {
		return c, err
	}
	return grant.Verify(a.Token, key, c, time.Now().Unix())
}

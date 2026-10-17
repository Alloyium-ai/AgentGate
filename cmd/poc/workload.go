// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"alloyium.local/kernel-poc/internal/audit"
	"alloyium.local/kernel-poc/internal/controlclient"
	"alloyium.local/kernel-poc/internal/grant"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/workload"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var safeWorkloadRun = regexp.MustCompile("^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,99}$")

func privateDeclaration(name string, dst any) error {
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return errors.New("a private regular controller declaration is required")
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	if len(data) > 32768 {
		return errors.New("controller declaration exceeds the limit")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(dst); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("one controller declaration is required")
	}
	return nil
}
func readJob(name string) (workload.Job, error) {
	file, err := os.Open(name)
	if err != nil {
		return workload.Job{}, err
	}
	defer file.Close()
	job, err := workload.Read(file)
	if err == nil {
		err = job.CheckFiles()
	}
	return job, err
}

type customerRun struct {
	runtime            *kernel.Runtime
	job                workload.Job
	cfg                controlclient.Config
	client             *controlclient.Client
	admission          controllerAdmission
	claims             grant.Claims
	output, configPath string
	object             []byte
	deadline           uint64
}

var errDenyAllUnqualified = errors.New("customer workload execution is unavailable until a deny-all profile and explicit runtime permissions qualify")

func runWorkload(args []string) error { return errDenyAllUnqualified }

func prepareCustomerRun(args []string) (*customerRun, error) {
	if len(args) != 4 {
		return nil, errors.New("run requires a BPF object, fresh evidence directory, private controller configuration and workload JSON")
	}
	if err := kernel.Preflight(); err != nil {
		return nil, err
	}
	run := &customerRun{configPath: args[2]}
	var err error
	if run.job, err = readJob(args[3]); err != nil {
		return nil, err
	}
	if err = privateDeclaration(args[2], &run.cfg); err != nil {
		return nil, err
	}
	if run.client, err = controlclient.New(run.cfg); err != nil {
		return nil, err
	}
	if run.output, err = filepath.Abs(args[1]); err != nil {
		return nil, err
	}
	if filepath.Clean(run.output) != run.output || strings.HasPrefix(run.output, "/tmp/") || run.output == "/tmp" {
		return nil, errors.New("a clean private evidence path is required")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(run.output))
	if err != nil || parent != filepath.Dir(run.output) {
		return nil, errors.New("an unlinked evidence parent directory is required")
	}
	if !safeWorkloadRun.MatchString(filepath.Base(run.output)) {
		return nil, errors.New("a short workload run name is required")
	}
	if run.object, err = os.ReadFile(args[0]); err != nil {
		return nil, err
	}
	if err = os.Mkdir(run.output, 0700); err != nil {
		return nil, err
	}
	run.runtime, err = kernel.New(args[0], "/sys/fs/cgroup/alloyium-poc-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	if err != nil {
		return nil, err
	}
	return run, nil
}
func (r *customerRun) admit() error {
	now, err := kernel.MonotonicNS()
	if err != nil {
		return err
	}
	r.deadline = now + uint64(20*time.Second)
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return err
	}
	node, err := os.Hostname()
	if err != nil {
		return err
	}
	run := filepath.Base(r.output)
	input := map[string]string{"request_id": r.cfg.RequestID, "run_id": run, "node": node, "boot": strings.TrimSpace(string(boot)), "cgroup": strconv.FormatUint(r.runtime.ID, 10), "workspace": r.job.Workspace + "/", "deadline_ns": strconv.FormatUint(r.deadline, 10), "job_digest": r.job.Digest(), "reason": "Admit the exact declared customer workload and approved policy"}
	key, err := grant.Nonce()
	if err != nil {
		return err
	}
	if err = r.client.Call("admissions", "POST", key, input, &r.admission); err != nil {
		return err
	}
	r.claims, err = verifyWorkloadAdmission(r.admission, r.cfg, r.job, node, strings.TrimSpace(string(boot)), run, r.runtime.ID, r.deadline)
	if err != nil {
		return err
	}
	return grant.Consume(filepath.Join(filepath.Dir(r.configPath), "admissions"), r.claims, r.admission.Token)
}
func (r *customerRun) activate() error {
	policy, err := workloadPolicy(r.claims)
	if err != nil {
		return err
	}
	if err = r.runtime.Install(policy); err != nil {
		return err
	}
	var confirmed controllerAdmission
	key, err := grant.Nonce()
	if err != nil {
		return err
	}
	if err = r.client.Call("admissions/"+r.admission.ID+"/activate", "POST", key, map[string]string{"version_id": r.admission.VersionID, "policy_digest": r.admission.Digest, "bpf_digest": grant.Digest(r.object), "reason": "Confirm the installed customer policy before releasing the workload"}, &confirmed); err != nil {
		return err
	}
	if confirmed.ID != r.admission.ID || confirmed.RunID != r.admission.RunID || confirmed.VersionID != r.admission.VersionID || confirmed.Digest != r.admission.Digest || confirmed.State != "admitted" {
		return errors.New("customer activation differs from the exact admission")
	}
	return nil
}
func (r *customerRun) execute() error {
	launchErr := launchWorkload(r.runtime, r.job, r.deadline)
	outcome := "completed"
	empty, err := r.runtime.Empty()
	if err != nil {
		return err
	}
	if launchErr != nil || !empty {
		outcome = "aborted"
	}
	if err = r.runtime.StopWorkload(); err != nil {
		return err
	}
	events, err := r.runtime.Drain()
	if err != nil {
		return err
	}
	counts, err := r.runtime.Counters()
	if err != nil {
		return err
	}
	for _, event := range events {
		if event.Cgroup != r.runtime.ID || event.Generation != 1 {
			return errors.New("customer audit event differs from the admitted domain")
		}
	}
	verdict, err := retainWorkloadEvidence(r.client, r.cfg, r.admission, r.claims, r.output, events, counts, r.object, outcome)
	if err != nil {
		return err
	}
	if err = r.release(); err != nil {
		return err
	}
	fmt.Printf("CUSTOMER_WORKLOAD_RETAINED run=%s verifier=%s decisions=%d lost=%d outcome=%s\n", filepath.Base(r.output), verdict, counts.Decisions, counts.Lost, outcome)
	if launchErr != nil {
		return errors.New("the customer workload failed; retained evidence records its incomplete lifecycle")
	}
	if verdict != audit.Complete {
		return errors.New("the customer workload evidence is incomplete")
	}
	return nil
}
func (r *customerRun) release() error {
	if err := r.runtime.Close(); err != nil {
		return err
	}
	if r.admission.ID == "" {
		return nil
	}
	key, err := grant.Nonce()
	if err != nil {
		return err
	}
	if err = r.client.Call("admissions/"+r.admission.ID+"/release", "POST", key, map[string]string{"state": "released", "reason": "The customer workload domain is empty and its enforcement objects are removed"}, nil); err != nil {
		return err
	}
	r.admission.ID = ""
	return nil
}
func (r *customerRun) cleanup() {
	// Retain enforcement on a failed domain cleanup. Publish a release only after cleanup succeeds.
	if err := r.release(); err != nil {
		fmt.Fprintln(os.Stderr, "customer workload cleanup failed; inspect the owned domain and retained evidence")
	}
}
func launchWorkload(runtime *kernel.Runtime, job workload.Job, deadline uint64) error {
	now, err := kernel.MonotonicNS()
	if err != nil || now >= deadline {
		return errors.New("customer workload deadline expired before release")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(deadline-now))
	defer cancel()
	read, write, err := os.Pipe()
	if err != nil {
		return err
	}
	defer read.Close()
	defer write.Close()
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, executable, "workload-child")
	command.ExtraFiles = []*os.File{read}
	command.Env = []string{"PATH=/usr/bin:/bin"}
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err = command.Start(); err != nil {
		return err
	}
	defer command.Process.Kill()
	if err = runtime.Move(command.Process.Pid); err != nil {
		return err
	}
	now, err = kernel.MonotonicNS()
	if err != nil || now >= deadline {
		return errors.New("customer workload deadline expired before its admission barrier")
	}
	if err = json.NewEncoder(write).Encode(job); err != nil {
		return err
	}
	write.Close()
	return command.Wait()
}
func verifyWorkloadAdmission(a controllerAdmission, cfg controlclient.Config, job workload.Job, node, boot, run string, domain, deadline uint64) (grant.Claims, error) {
	var claims grant.Claims
	parts := strings.Split(a.Token, ".")
	if len(parts) != 3 {
		return claims, errors.New("invalid customer grant")
	}
	raw, err := controlclient.Decode(parts[1])
	if err != nil {
		return claims, err
	}
	if err = json.Unmarshal(raw, &claims); err != nil {
		return claims, err
	}
	if a.RequestID != cfg.RequestID || a.RunID != run || a.AgentID != cfg.Agent || a.State != "issued" || claims.Deployment != "agentgate-community-v1" || claims.Node != node || claims.Boot != boot || claims.Run != run || claims.Domain != strconv.FormatUint(domain, 10) || claims.Agent != cfg.Agent || claims.AgentKey != cfg.AgentKey || claims.Workspace != job.Workspace+"/" || claims.DeadlineNS != strconv.FormatUint(deadline, 10) || claims.JobDigest != job.Digest() || claims.PolicyVersion != a.VersionID || claims.PolicyDigest != a.Digest || claims.Nonce != a.ID {
		return claims, errors.New("customer grant differs from the trusted workload declaration")
	}
	authority, err := grant.Public(cfg.Authority)
	if err != nil {
		return claims, err
	}
	return grant.Verify(a.Token, authority, claims, time.Now().Unix())
}
func workloadPolicy(c grant.Claims) (kernel.Policy, error) {
	host, text, err := net.SplitHostPort(c.Endpoint)
	if err != nil {
		return kernel.Policy{}, err
	}
	address := net.ParseIP(host).To4()
	port, err := strconv.ParseUint(text, 10, 16)
	if err != nil || address == nil {
		return kernel.Policy{}, errors.New("customer endpoint is outside the supported IPv4 TCP scope")
	}
	deadline, err := strconv.ParseUint(c.DeadlineNS, 10, 64)
	if err != nil {
		return kernel.Policy{}, err
	}
	policy := kernel.Policy{Generation: 1, ExpiresNS: deadline, AllowedIP: binary.LittleEndian.Uint32(address), AllowedPort: uint32(port>>8 | (port&255)<<8)}
	if !c.ReadOnly {
		copy(policy.Workspace[:], c.Workspace)
	}
	return policy, nil
}
func retainWorkloadEvidence(client *controlclient.Client, cfg controlclient.Config, a controllerAdmission, c grant.Claims, dir string, events []kernel.Event, counts kernel.Counters, object []byte, outcome string) (string, error) {
	trust := grant.Trust{Authority: cfg.Authority, Node: controlclient.EncodeKey(client.Key.Public().(ed25519.PublicKey)), Agent: cfg.AgentKey}
	if err := audit.Save(dir, a.Token, c, events, counts, grant.Keys{Node: client.Key, Trust: trust}, grant.Digest(object), outcome); err != nil {
		return "", err
	}
	stream, err := os.ReadFile(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		return "", err
	}
	terminal, err := os.ReadFile(filepath.Join(dir, "terminal.json"))
	if err != nil {
		return "", err
	}
	evidence := controllerEvidence{a.Token, string(stream), terminal}
	payload := map[string]any{"admission_id": a.ID, "evidence": evidence, "reason": "Retain the customer workload kernel decision evidence"}
	key, _ := grant.Nonce()
	var seal audit.Seal
	if err = client.Call("evidence/receipt", "POST", key, payload, &seal); err != nil {
		return "", err
	}
	terminal, err = json.Marshal(seal)
	if err != nil {
		return "", err
	}
	if err = os.WriteFile(filepath.Join(dir, "terminal.json"), terminal, 0600); err != nil {
		return "", err
	}
	evidence.Terminal = terminal
	payload["evidence"] = evidence
	verdict, verifyErr := audit.Verify(dir, trust)
	if verdict != audit.Complete && verdict != audit.Incomplete {
		return verdict, verifyErr
	}
	key, _ = grant.Nonce()
	if err = client.Call("evidence", "POST", key, payload, nil); err != nil {
		return verdict, err
	}
	return verdict, nil
}

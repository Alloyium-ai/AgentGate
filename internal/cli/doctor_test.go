// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// agentgate doctor against the real control service in process, with fake
// host agents over the real host protocol. Nothing here runs a real host,
// kernel or Docker: the capabilities are what the fake hosts report.
func TestDoctorAgainstTheRealService(t *testing.T) {
	svc := startRealService(t)
	dir := filepath.Join(t.TempDir(), "agentgate")
	shift := time.Duration(0)
	run := func(args ...string) result {
		t.Helper()
		var out, errOut bytes.Buffer
		a := &App{Stdin: strings.NewReader(adaPassword + "\n"), Stdout: &out, Stderr: &errOut, Getenv: func(k string) string {
			return map[string]string{"AGENTGATE_CONFIG_DIR": dir, "HOME": dir}[k]
		}, Term: &fakeTerm{}, Hostname: func() (string, error) { return "doctor", nil }, Version: "test",
			Now: func() time.Time { return time.Now().Add(shift) }}
		code := a.Main(context.Background(), args)
		return result{out.String(), errOut.String(), code}
	}
	expect := func(r result, code int, lines ...string) {
		t.Helper()
		if r.code != code {
			t.Fatalf("want exit %d: %v", code, r)
		}
		for _, l := range lines {
			if !strings.Contains(r.stdout+r.stderr, l) {
				t.Fatalf("output lacks %q:\n%s%s", l, r.stdout, r.stderr)
			}
		}
	}

	expect(run("doctor"), ExitFailure, "FAIL  service", "No service is configured", "fix: agentgate login URL")
	expect(run("login", svc.srv.URL, "--ca-file", svc.ca, "--username", "ada", "--password-stdin"), 0)
	expect(run("doctor"), ExitFailure, "ok    service", "ok    clock", "ok    token", "accepted for local:ada",
		"FAIL  target             no target named local", "fix: agentgate target add local")

	tokenFile := filepath.Join(t.TempDir(), "token")
	expect(run("target", "add", "local", "--token-file", tokenFile), 0)
	expect(run("doctor"), ExitFailure, "local has no host yet (pending enrollment)", "fix: on the host: agentgate up --target local")

	raw, _ := os.ReadFile(tokenFile)
	host := &fakeHostd{t: t, url: svc.srv.URL, client: svc.srv.Client()}
	_, host.key, _ = ed25519.GenerateKey(rand.Reader)
	host.box, _ = ecdh.X25519().GenerateKey(rand.Reader)
	enrolled := host.enroll(strings.TrimSpace(string(raw)))
	expect(run("doctor"), ExitFailure, "FAIL  host key", "waits for its host key "+enrolled.HostKeyID, "agentgate target approve-key local --host-key-id")

	expect(run("target", "approve-key", "local", "--host-key-id", enrolled.HostKeyID, "--reason", "Matches the host console"), 0)
	host.poll()
	// The fake host reports brokered secrets and a seal key, but no BPF LSM.
	r := run("doctor")
	expect(r, ExitFailure, "ok    target", "ok    host key", enrolled.HostKeyID+" approved and pinned here", "ok    heartbeat",
		"FAIL  kernel-bpf-lsm", "fix: boot the host with BPF LSM", "ok    brokered-secrets", "ok    seal key", "doctor_failed")

	// A stale heartbeat, read as the service reports it.
	expect(run("doctor", "--max-heartbeat-age", "1ns"), ExitFailure, "FAIL  heartbeat", "systemctl restart agentgate-hostd")

	// A host with BPF LSM and no broker: nothing fails, the broker is a warning.
	edge := filepath.Join(t.TempDir(), "edge-token")
	expect(run("target", "add", "edge", "--token-file", edge), 0)
	raw, _ = os.ReadFile(edge)
	second := &fakeHostd{t: t, url: svc.srv.URL, client: svc.srv.Client(), caps: []string{hostproto.CapabilityDocker, hostproto.CapabilityBPFLSM, hostproto.CapabilityPOCPolicyV2}}
	_, second.key, _ = ed25519.GenerateKey(rand.Reader)
	second.box, _ = ecdh.X25519().GenerateKey(rand.Reader)
	edgeKey := second.enroll(strings.TrimSpace(string(raw)))
	expect(run("target", "approve-key", "edge", "--host-key-id", edgeKey.HostKeyID, "--reason", "Matches the host console"), 0)
	second.poll()
	r = run("doctor", "--target", "edge")
	expect(r, 0, "ok    kernel-bpf-lsm", "warn  brokered-secrets", "--broker-image", "Nothing failed")

	// JSON names every check.
	r = run("doctor", "--target", "edge", "--json")
	var report struct {
		OK     bool          `json:"ok"`
		Checks []doctorCheck `json:"checks"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &report); err != nil || !report.OK || r.code != 0 {
		t.Fatalf("doctor --json: %v %v", r, err)
	}
	names := []string{}
	for _, c := range report.Checks {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "service,clock,token,target,host key,heartbeat,kernel-bpf-lsm,brokered-secrets" {
		t.Fatalf("checks %v", names)
	}

	// This machine's clock two minutes ahead of the service.
	shift = 2 * time.Minute
	expect(run("doctor", "--target", "edge"), ExitFailure, "FAIL  clock", "the service refuses host requests beyond 1m0s", "timedatectl set-ntp true")
	shift = 0

	// A revoked token.
	expect(run("logout"), 0)
	expect(run("doctor"), ExitFailure, "FAIL  token")
}

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
		"ok    host clock", "the host's clock was", "the service's at its last heartbeat",
		"FAIL  kernel-bpf-lsm", "fix: boot the host with BPF LSM", "ok    brokered-secrets", "ok    seal key",
		"warn  mount roots", "does not report mount roots of its own", "doctor_failed")

	// A stale heartbeat, read as the service reports it.
	expect(run("doctor", "--max-heartbeat-age", "1ns"), ExitFailure, "FAIL  heartbeat", "systemctl restart agentgate-hostd")

	// A host with BPF LSM and no broker: nothing fails, the broker is a warning.
	edge := filepath.Join(t.TempDir(), "edge-token")
	expect(run("target", "add", "edge", "--token-file", edge), 0)
	raw, _ = os.ReadFile(edge)
	hostRoots := []string{"/srv/repos"}
	second := &fakeHostd{t: t, url: svc.srv.URL, client: svc.srv.Client(), caps: []string{hostproto.CapabilityDocker, hostproto.CapabilityBPFLSM, hostproto.CapabilityPOCPolicyV2}, roots: &hostRoots}
	_, second.key, _ = ed25519.GenerateKey(rand.Reader)
	second.box, _ = ecdh.X25519().GenerateKey(rand.Reader)
	edgeKey := second.enroll(strings.TrimSpace(string(raw)))
	expect(run("target", "approve-key", "edge", "--host-key-id", edgeKey.HostKeyID, "--reason", "Matches the host console"), 0)
	second.poll()
	r = run("doctor", "--target", "edge")
	expect(r, 0, "ok    kernel-bpf-lsm", "warn  brokered-secrets", "--broker-image", "ok    mount roots", "no host folder may be mounted", "the host allows /srv/repos", "Nothing failed")
	// The service lists a root the host does not allow: a warning naming both lists and both fixes.
	expect(run("target", "mount-roots", "edge", "--root", "/srv/data", "--root", "/srv/repos/app", "--reason", "Mount the data set"), 0)
	expect(run("doctor", "--target", "edge"), 0, "warn  mount roots", "the host refuses mounts in /srv/data", "sudo agentgate-hostd mount-roots --root PATH")
	expect(run("target", "status", "edge"), 0, "host mount roots", "MISMATCH: the host refuses mounts in /srv/data")
	// The host's clock 20 s ahead: a warning with the fix on the host.
	second.skew = 20 * time.Second
	second.poll()
	expect(run("doctor", "--target", "edge"), 0, "warn  host clock", "s ahead of the service's", "timedatectl set-ntp true")
	second.skew = 0
	second.poll()

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
	if strings.Join(names, ",") != "service,clock,token,target,host key,heartbeat,host clock,kernel-bpf-lsm,brokered-secrets,mount roots" {
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

// As root on the target's own host, doctor reads agentgate-hostd status to say
// exactly why brokered-secrets is missing; otherwise it says what to check.
func TestDoctorExplainsAMissingBrokerFromTheLocalHostAgent(t *testing.T) {
	h := newHarness(t)
	h.login("local:ada", "admin")
	target := sampleTarget("active")
	h.api.reply("GET /api/v1/launch-spec-schema", 200, map[string]any{})
	h.api.reply("GET /api/v1/targets/{id}", 200, target)
	status := map[string]any{"enrolled": true, "target_id": target.ID, "broker": nil, "secret_root": "/var/lib/agentgate/secrets"}
	h.runner = &fakeRunner{respond: func(c Cmd) Result {
		if strings.Join(c.Args, " ") != "status --state-dir /srv/hostd" {
			return Result{Exit: 2, Stderr: []byte("unexpected " + strings.Join(c.Args, " "))}
		}
		raw, _ := json.Marshal(status)
		return Result{Stdout: raw}
	}}
	h.euid = 0
	if r := h.run("", "doctor", "--state-dir", "/srv/hostd"); !strings.Contains(r.stdout, "installed without a credential broker (--broker-image)") {
		t.Fatalf("%v", r)
	}
	status["broker"] = map[string]any{"image": brokerImage, "uid": 10002, "gid": 10002, "egress_network": "agentgate-egress"}
	if r := h.run("", "doctor", "--state-dir", "/srv/hostd"); !strings.Contains(r.stdout, "configured with broker image "+brokerImage) || !strings.Contains(r.stdout, "docker network inspect agentgate-egress") {
		t.Fatalf("%v", r)
	}
	// Another target's host agent, or no root: the generic explanation, and no command runs without root.
	status["target_id"] = strings.Repeat("0", 32)
	if r := h.run("", "doctor", "--state-dir", "/srv/hostd"); !strings.Contains(r.stdout, "it does only with --broker-image") {
		t.Fatalf("%v", r)
	}
	h.euid = 1000
	before := len(h.runner.(*fakeRunner).calls)
	if r := h.run("", "doctor", "--state-dir", "/srv/hostd"); !strings.Contains(r.stdout, "it does only with --broker-image") || len(h.runner.(*fakeRunner).calls) != before {
		t.Fatalf("%v", r)
	}
}

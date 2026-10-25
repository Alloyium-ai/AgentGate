// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeInstaller(t *testing.T) (*Installer, *[]string, string) {
	root := t.TempDir()
	instance := filepath.Join(root, "var/lib/agentgate-poc-demo")
	_ = os.MkdirAll(instance, 0o700)
	for _, name := range []string{"launch.py", "settings.json", "initialized", "pilot-network-diagnostic"} {
		_ = os.WriteFile(filepath.Join(instance, name), nil, 0o600)
	}
	_ = os.MkdirAll(filepath.Join(root, "sys/fs/cgroup"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "sys/fs/cgroup/cgroup.controllers"), nil, 0o644)
	var calls []string
	c := &clock{t: time.Now()}
	in := &Installer{Root: root, Service: newFakeService(t, c.now), Now: c.now, Euid: func() int { return 0 }, Out: &bytes.Buffer{},
		Look: func(name string) (string, error) { return "/usr/bin/" + name, nil },
		Run: func(_ context.Context, name string, args ...string) error {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return nil
		}}
	return in, &calls, root
}

func TestInstallIsIdempotentAndEnrollsOnce(t *testing.T) {
	in, calls, root := fakeInstaller(t)
	exe := filepath.Join(t.TempDir(), "agentgate-hostd")
	_ = os.WriteFile(exe, []byte("binary"), 0o755)
	o := InstallOptions{ServiceURL: "https://agentgate.example", Token: testToken, Runtime: RuntimeDockerHost, Executable: exe}
	if err := in.Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	unit, err := os.ReadFile(filepath.Join(root, "etc/systemd/system/agentgate-hostd.service"))
	if err != nil || !bytes.Contains(unit, []byte("ExecStart=/usr/local/sbin/agentgate-hostd run --state-dir /var/lib/agentgate-hostd")) {
		t.Fatalf("unit %s %v", unit, err)
	}
	if raw, _ := os.ReadFile(filepath.Join(root, "usr/local/sbin/agentgate-hostd")); string(raw) != "binary" {
		t.Fatal("binary not installed")
	}
	state := filepath.Join(root, "var/lib/agentgate-hostd")
	id, err := loadIdentity(state)
	if err != nil || id.TargetID != testTarget {
		t.Fatalf("identity %+v %v", id, err)
	}
	cfg, _ := loadConfig(state)
	if cfg.Launcher[2] != "/var/lib/agentgate-poc-demo/launch.py" {
		t.Fatalf("launcher %v", cfg.Launcher)
	}
	// The operator sees the id to approve and the fingerprint to pin.
	out := in.Out.(*bytes.Buffer).String()
	key, err := readHostKey(state)
	if err != nil || key.ID != id.HostKeyID || !strings.HasPrefix(key.Fingerprint, "SHA256:") {
		t.Fatalf("host key %+v %v", key, err)
	}
	for _, want := range []string{"host key id (compare and approve this): " + id.HostKeyID, "host key fingerprint (SHA-256 of the key; sealing clients pin it): " + key.Fingerprint,
		"agentgate target approve-key " + id.TargetName + " --host-key-id " + id.HostKeyID} {
		if !strings.Contains(out, want) {
			t.Fatalf("install output lacks %q:\n%s", want, out)
		}
	}
	report, err := Status(state)
	if err != nil || report.HostKeyID != id.HostKeyID || report.HostKeyFingerprint != key.Fingerprint || report.TargetName != id.TargetName || len(report.Approve) != 4 {
		t.Fatalf("status %+v %v", report, err)
	}
	in.Out.(*bytes.Buffer).Reset()
	// Again, with an already used token: nothing changes, no enrollment.
	o.Token = ""
	if err = in.Install(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	again, _ := loadIdentity(state)
	if again != id {
		t.Fatal("a second install changed the identity")
	}
	if !strings.Contains(in.Out.(*bytes.Buffer).String(), "host key id (compare and approve this): "+id.HostKeyID) {
		t.Fatal("a repeated install does not show the host key id")
	}
	if len(*calls) != 4 || (*calls)[0] != "systemctl daemon-reload" || (*calls)[1] != "systemctl enable --now agentgate-hostd.service" {
		t.Fatalf("calls %v", *calls)
	}
	// A different service is refused instead of silently re-enrolling.
	o.ServiceURL = "https://other.example"
	if err = in.Install(context.Background(), o); err == nil || !strings.Contains(err.Error(), "already installed") {
		t.Fatalf("re-target accepted: %v", err)
	}
}

func TestInstallNamesEveryMissingPrerequisite(t *testing.T) {
	in, _, root := fakeInstaller(t)
	in.Look = func(name string) (string, error) {
		if name == "docker" {
			return "", errors.New("absent")
		}
		return "/usr/bin/" + name, nil
	}
	_ = os.Remove(filepath.Join(root, "var/lib/agentgate-poc-demo/initialized"))
	err := in.Install(context.Background(), InstallOptions{ServiceURL: "https://agentgate.example", Token: testToken, Runtime: RuntimeDockerHost})
	if err == nil || !strings.Contains(err.Error(), "docker command") || !strings.Contains(err.Error(), "configure.py") {
		t.Fatalf("prerequisites: %v", err)
	}
	in.Euid = func() int { return 1000 }
	if err = in.Install(context.Background(), InstallOptions{ServiceURL: "https://agentgate.example"}); err == nil {
		t.Fatal("a non-root install ran")
	}
	in.Euid = func() int { return 0 }
	if err = in.Install(context.Background(), InstallOptions{ServiceURL: "http://agentgate.example", Token: testToken, Runtime: RuntimeDockerHost}); err == nil {
		t.Fatal("plain http was accepted")
	}
}

// fakeLauncher writes a shell script that behaves like launch.py's interface.
func fakeLauncher(t *testing.T, body string) []string {
	path := filepath.Join(t.TempDir(), "launch")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return []string{path}
}

func TestCommandRuntimeStreamsLinesAndBoundsThem(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no shell")
	}
	long := strings.Repeat("x", maxLauncherLine+10)
	runtime := &CommandRuntime{Launcher: fakeLauncher(t, `cat >/dev/null
echo '{"event":"state","state":"provisioning"}'
printf '%s\n' '`+long+`'
echo 'not json'
echo '{"event":"receipt","receipt":{"launch_id":"x"}}'
`)}
	var events []LauncherEvent
	err := runtime.Run(context.Background(), []byte("{}"), func(e LauncherEvent) { events = append(events, e) })
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("over-long line not reported: %v", err)
	}
	if len(events) != 2 || events[0].State != "provisioning" || !json.Valid(events[1].Receipt) {
		t.Fatalf("events %+v", events)
	}
}

func TestCommandRuntimeMapsExitCodes(t *testing.T) {
	busy := &CommandRuntime{Launcher: fakeLauncher(t, "echo 'agentgate-launch-busy: held' >&2; exit 75\n")}
	if _, err := busy.Stop(context.Background(), "x", 1, "stop_requested"); !errors.Is(err, ErrRuntimeBusy) {
		t.Fatalf("busy: %v", err)
	}
	unknown := &CommandRuntime{Launcher: fakeLauncher(t, "echo 'agentgate-launch-invalid: unknown launch: x' >&2; exit 2\n")}
	if _, err := unknown.Receipt(context.Background(), "x"); !errors.Is(err, ErrUnknownLaunch) {
		t.Fatalf("unknown: %v", err)
	}
	args := &CommandRuntime{Launcher: fakeLauncher(t, `printf '%s|' "$@"; echo`)}
	raw, err := args.output(context.Background(), nil, 1024, "stop", "id-1", "--grace", "5")
	if err != nil || string(raw) != "stop|id-1|--grace|5|\n" {
		t.Fatalf("argv %q %v", raw, err)
	}
	if _, err = args.output(context.Background(), nil, 4, "stop"); err == nil {
		t.Fatal("unbounded output accepted")
	}
	ready := &CommandRuntime{Provisioner: fakeLauncher(t, "echo building; echo ready=true\n")}
	if _, err = ready.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}
	notReady := &CommandRuntime{Provisioner: fakeLauncher(t, "echo 'agentgate-appliance-error: no kvm' >&2; exit 1\n")}
	if _, err = notReady.Provision(context.Background()); err == nil || !strings.Contains(err.Error(), "no kvm") {
		t.Fatalf("provision error not surfaced: %v", err)
	}
	silent := &CommandRuntime{Provisioner: fakeLauncher(t, "echo done\n")}
	if _, err = silent.Provision(context.Background()); err == nil {
		t.Fatal("bring-up without ready=true succeeded")
	}
}

func TestCancelledRunSendsSIGTERMFirst(t *testing.T) {
	runtime := &CommandRuntime{StopWait: 5 * time.Second, Launcher: fakeLauncher(t, `trap 'echo "{\"event\":\"state\",\"state\":\"stopping\"}"; exit 0' TERM
cat >/dev/null
echo '{"event":"state","state":"running"}'
while :; do sleep 0.1; done
`)}
	ctx, cancel := context.WithCancel(context.Background())
	var states []string
	done := make(chan error)
	go func() {
		done <- runtime.Run(ctx, []byte("{}"), func(e LauncherEvent) {
			states = append(states, e.State)
			if e.State == "running" {
				cancel()
			}
		})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a cancelled runtime did not stop")
	}
	if strings.Join(states, ",") != "running,stopping" {
		t.Fatalf("states %v (graceful SIGTERM path not taken)", states)
	}
}

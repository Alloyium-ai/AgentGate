// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

//go:embed agentgate-hostd.service
var unitTemplate string

// UnitFile renders the systemd unit for a binary and state directory.
func UnitFile(binary, stateDir string) string {
	return strings.NewReplacer("@BINARY@", binary, "@STATE@", stateDir).Replace(unitTemplate)
}

// InstallOptions are the install command's inputs.
type InstallOptions struct {
	ServiceURL        string
	Token             string
	AllowLoopbackHTTP bool
	CAFile            string
	Runtime           string
	Instance          string
	// ApplianceState and Source are used for the appliance runtime.
	ApplianceState string
	Source         string
	StateDir       string
	BinaryPath     string // where the daemon binary is installed
	UnitPath       string
	Executable     string // the running binary, copied to BinaryPath
	Hostname       string
	NoStart        bool
}

// Installer performs an idempotent install. Its file roots and commands are
// replaceable so tests never touch the real system.
type Installer struct {
	Root    string // prefix for every system path; "" on a real host
	Run     func(ctx context.Context, name string, args ...string) error
	Look    func(name string) (string, error)
	Service Service
	Out     io.Writer
	Now     func() time.Time
	Euid    func() int
}

func (in *Installer) path(p string) string { return filepath.Join(in.Root, p) }

func (in *Installer) say(format string, args ...any) {
	if in.Out != nil {
		fmt.Fprintf(in.Out, format+"\n", args...)
	}
}

// launcherFor derives the launch runtime command for a runtime kind.
func launcherFor(o InstallOptions) ([]string, []string, error) {
	switch o.Runtime {
	case RuntimeDockerHost:
		return []string{"/usr/bin/python3", "-I", "/var/lib/agentgate-poc-" + o.Instance + "/launch.py"}, nil, nil
	case RuntimeAppliance:
		if !filepath.IsAbs(o.ApplianceState) || !filepath.IsAbs(o.Source) {
			return nil, nil, errors.New("hostd: the appliance runtime needs --appliance-state DIR and --source DIR (absolute)")
		}
		info, err := os.Stat(o.ApplianceState)
		if err != nil {
			return nil, nil, fmt.Errorf("hostd: appliance state %s: %w", o.ApplianceState, err)
		}
		stat := info.Sys().(*syscall.Stat_t)
		// appliance.py requires its state directory to be owned by the caller.
		prefix := []string{"/usr/bin/setpriv", "--reuid=" + strconv.Itoa(int(stat.Uid)), "--regid=" + strconv.Itoa(int(stat.Gid)),
			"--init-groups", "--", "/usr/bin/python3", "-I", filepath.Join(o.Source, "poc/ssh-diagnostic/appliance.py")}
		launcher := append(append([]string{}, prefix...), "guest-launch", "--state", o.ApplianceState, "--")
		provisioner := append(append([]string{}, prefix...), "start", "--state", o.ApplianceState)
		return launcher, provisioner, nil
	}
	return nil, nil, errors.New("hostd: --runtime must be docker-host or appliance")
}

// prerequisites names every missing piece with a clear fix.
func (in *Installer) prerequisites(o InstallOptions) error {
	var missing []string
	for _, tool := range []string{"docker", "python3", "systemctl", "setpriv"} {
		if _, err := in.Look(tool); err != nil {
			missing = append(missing, "the "+tool+" command is not installed")
		}
	}
	switch o.Runtime {
	case RuntimeDockerHost:
		root := in.path("/var/lib/agentgate-poc-" + o.Instance)
		for _, name := range []string{"launch.py", "settings.json", "initialized", "pilot-network-diagnostic"} {
			if _, err := os.Stat(filepath.Join(root, name)); err != nil {
				missing = append(missing, fmt.Sprintf("%s/%s is absent: configure the instance first with poc/ssh-diagnostic/configure.py", root, name))
			}
		}
		if _, err := os.Stat(in.path("/sys/fs/cgroup/cgroup.controllers")); err != nil {
			missing = append(missing, "cgroup v2 is not mounted at /sys/fs/cgroup")
		}
	case RuntimeAppliance:
		if _, err := os.Stat(filepath.Join(o.Source, "poc/ssh-diagnostic/appliance.py")); err != nil {
			missing = append(missing, "the source checkout lacks poc/ssh-diagnostic/appliance.py")
		}
	}
	if len(missing) > 0 {
		return errors.New("hostd: prerequisites missing:\n  - " + strings.Join(missing, "\n  - "))
	}
	return nil
}

// Install enrolls once, writes the configuration, binary and unit, and starts
// the service. Running it again with the same inputs changes nothing.
func (in *Installer) Install(ctx context.Context, o InstallOptions) error {
	if in.Euid() != 0 {
		return errors.New("hostd: install runs as root")
	}
	if o.StateDir == "" {
		o.StateDir = DefaultStateDir
	}
	if o.BinaryPath == "" {
		o.BinaryPath = "/usr/local/sbin/agentgate-hostd"
	}
	if o.UnitPath == "" {
		o.UnitPath = "/etc/systemd/system/agentgate-hostd.service"
	}
	if o.Instance == "" {
		o.Instance = "demo"
	}
	launcher, provisioner, err := launcherFor(o)
	if err != nil {
		return err
	}
	cfg := Config{ServiceURL: o.ServiceURL, AllowLoopbackHTTP: o.AllowLoopbackHTTP, CAFile: o.CAFile, Runtime: o.Runtime,
		Launcher: launcher, Provisioner: provisioner, Instance: o.Instance}
	if err = cfg.Validate(); err != nil {
		return err
	}
	origin, _ := ServiceOrigin(o.ServiceURL, o.AllowLoopbackHTTP)
	if err = in.prerequisites(o); err != nil {
		return err
	}
	stateDir := in.path(o.StateDir)
	if err = os.MkdirAll(filepath.Dir(stateDir), 0o755); err != nil {
		return err
	}
	if err = ensurePrivateDir(stateDir); err != nil {
		return err
	}
	if existing, loadErr := loadConfig(stateDir); loadErr == nil {
		if existing.ServiceURL != cfg.ServiceURL || existing.Runtime != cfg.Runtime || existing.Instance != cfg.Instance {
			return fmt.Errorf("hostd: this host is already installed for %s (%s, instance %s); uninstall it before changing the service or runtime",
				existing.ServiceURL, existing.Runtime, existing.Instance)
		}
	} else if !errors.Is(loadErr, os.ErrNotExist) {
		return loadErr
	}
	if err = saveConfig(stateDir, cfg); err != nil {
		return err
	}
	if id, idErr := loadIdentity(stateDir); idErr == nil {
		if id.ServiceURL != origin {
			return errors.New("hostd: the host is enrolled with another service")
		}
		in.say("already enrolled as target %s; the token was not used", id.TargetID)
	} else {
		if o.Token == "" {
			return errors.New("hostd: enrollment needs --token or --token-file")
		}
		hostname := o.Hostname
		if hostname == "" {
			hostname, _ = os.Hostname()
		}
		id, err = Enroll(ctx, stateDir, cfg, in.Service, o.Token, hostname, []string{"docker", "pocpolicy-v2"}, in.Now, rand.Reader)
		if err != nil {
			return err
		}
		in.say("enrolled as target %s (%s)", id.TargetID, id.TargetName)
	}
	if o.Executable != "" {
		if err = in.copyBinary(o.Executable, in.path(o.BinaryPath)); err != nil {
			return err
		}
	}
	unit := []byte(UnitFile(o.BinaryPath, o.StateDir))
	if current, readErr := os.ReadFile(in.path(o.UnitPath)); readErr != nil || !bytes.Equal(current, unit) {
		if err = os.MkdirAll(filepath.Dir(in.path(o.UnitPath)), 0o755); err != nil {
			return err
		}
		if err = writeFileAtomic(in.path(o.UnitPath), unit, 0o644); err != nil {
			return err
		}
		in.say("wrote %s", o.UnitPath)
	}
	if o.NoStart {
		return nil
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "agentgate-hostd.service"}} {
		if err = in.Run(ctx, "systemctl", args...); err != nil {
			return fmt.Errorf("hostd: systemctl %s: %w", strings.Join(args, " "), err)
		}
	}
	in.say("agentgate-hostd is running")
	return nil
}

func (in *Installer) copyBinary(source, target string) error {
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if current, readErr := os.ReadFile(target); readErr == nil && bytes.Equal(current, raw) {
		return nil
	}
	if err = os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return writeFileAtomic(target, raw, 0o755)
}

// SystemInstaller runs real commands.
func SystemInstaller(service Service, out io.Writer) *Installer {
	return &Installer{Run: func(ctx context.Context, name string, args ...string) error {
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = cleanEnv
		output, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(output)))
		}
		return nil
	}, Look: exec.LookPath, Service: service, Out: out, Now: time.Now, Euid: os.Geteuid}
}

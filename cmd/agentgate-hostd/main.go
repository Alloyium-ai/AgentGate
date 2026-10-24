// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Command agentgate-hostd is the AgentGate host agent.
//
//	agentgate-hostd install --service-url URL (--token T | --token-file F) [--runtime docker-host|appliance] ...
//	agentgate-hostd run [--state-dir DIR]
//	agentgate-hostd provision (--appliance-state DIR --source DIR [--policy F --token-file F] | --state-dir DIR)
//	agentgate-hostd status [--state-dir DIR]
//	agentgate-hostd unit
//	agentgate-hostd version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/hostd"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "agentgate-hostd:", err)
		var exit *exitCode
		if errors.As(err, &exit) {
			os.Exit(exit.code)
		}
		os.Exit(1)
	}
}

type exitCode struct {
	code int
	err  error
}

func (e *exitCode) Error() string { return e.err.Error() }

func usage() error {
	return &exitCode{2, errors.New("usage: agentgate-hostd install|run|provision|status|unit|version [flags]; see --help of each")}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "install":
		return install(args[1:], stdout)
	case "run":
		return daemon(args[1:], stderr)
	case "provision":
		return provision(args[1:], stdout, stderr)
	case "status":
		return status(args[1:], stdout)
	case "unit":
		fmt.Fprint(stdout, hostd.UnitFile("/usr/local/sbin/agentgate-hostd", hostd.DefaultStateDir))
		return nil
	case "version":
		fmt.Fprintln(stdout, hostd.Version)
		return nil
	}
	return usage()
}

func readToken(token, file string) (string, error) {
	if token != "" && file != "" {
		return "", errors.New("use --token or --token-file, not both")
	}
	if file == "" {
		return token, nil
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	if len(raw) > 256 {
		return "", errors.New("the token file is too large")
	}
	return strings.TrimSpace(string(raw)), nil
}

func install(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	o := hostd.InstallOptions{}
	var tokenFile string
	flags.StringVar(&o.ServiceURL, "service-url", "", "service origin, https://HOST[:PORT]")
	flags.StringVar(&o.Token, "token", "", "one-time enrollment token (prefer --token-file: arguments are visible to other users)")
	flags.StringVar(&tokenFile, "token-file", "", "file holding the one-time enrollment token")
	flags.BoolVar(&o.AllowLoopbackHTTP, "allow-loopback-http", false, "allow http:// to a loopback service")
	flags.StringVar(&o.CAFile, "ca-file", "", "trust only this CA for the service")
	flags.StringVar(&o.Runtime, "runtime", hostd.RuntimeDockerHost, "docker-host or appliance")
	flags.StringVar(&o.Instance, "instance", "demo", "POC instance name (/var/lib/agentgate-poc-NAME)")
	flags.StringVar(&o.ApplianceState, "appliance-state", "", "appliance state directory (appliance runtime)")
	flags.StringVar(&o.Source, "source", "", "AgentGate source checkout (appliance runtime)")
	flags.StringVar(&o.StateDir, "state-dir", hostd.DefaultStateDir, "host agent state directory")
	flags.StringVar(&o.Hostname, "hostname", "", "name reported at enrollment")
	flags.BoolVar(&o.NoStart, "no-start", false, "write everything but do not start the service")
	if err := flags.Parse(args); err != nil {
		return &exitCode{2, err}
	}
	var err error
	if o.Token, err = readToken(o.Token, tokenFile); err != nil {
		return &exitCode{2, err}
	}
	if o.Executable, err = os.Executable(); err != nil {
		return err
	}
	origin, err := hostd.ServiceOrigin(o.ServiceURL, o.AllowLoopbackHTTP)
	if err != nil {
		return &exitCode{2, err}
	}
	service, err := hostd.NewHTTPService(origin, o.CAFile)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return hostd.SystemInstaller(service, stdout).Install(ctx, o)
}

func daemon(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	stateDir := flags.String("state-dir", hostd.DefaultStateDir, "host agent state directory")
	if err := flags.Parse(args); err != nil {
		return &exitCode{2, err}
	}
	if os.Geteuid() != 0 {
		return errors.New("the host agent runs as root")
	}
	logger := log.New(stderr, "agentgate-hostd: ", log.LstdFlags|log.LUTC)
	cfg, err := hostd.LoadConfig(*stateDir)
	if err != nil {
		return err
	}
	origin, err := hostd.ServiceOrigin(cfg.ServiceURL, cfg.AllowLoopbackHTTP)
	if err != nil {
		return err
	}
	service, err := hostd.NewHTTPService(origin, cfg.CAFile)
	if err != nil {
		return err
	}
	runtime := &hostd.CommandRuntime{Launcher: cfg.Launcher, Provisioner: cfg.Provisioner}
	d, err := hostd.Open(*stateDir, service, runtime, logger)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	err = d.Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

// provision brings the appliance online with the existing appliance.py start
// machinery and reports its readiness or failure verbatim.
func provision(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("provision", flag.ContinueOnError)
	state := flags.String("appliance-state", "", "appliance state directory")
	source := flags.String("source", "", "AgentGate source checkout")
	policy := flags.String("policy", "", "initial policy file (first start only)")
	tokenFile := flags.String("token-file", "", "taskboard token file (first start only)")
	port := flags.Int("port", 0, "host loopback SSH port")
	stateDir := flags.String("state-dir", "", "use the installed host agent's provisioner instead")
	if err := flags.Parse(args); err != nil {
		return &exitCode{2, err}
	}
	var argv []string
	switch {
	case *stateDir != "":
		cfg, err := hostd.LoadConfig(*stateDir)
		if err != nil {
			return err
		}
		if len(cfg.Provisioner) == 0 {
			return errors.New("this host's runtime has no bring-up command (docker-host targets are configured with configure.py)")
		}
		argv = cfg.Provisioner
	case *state != "" && *source != "":
		argv = hostd.ProvisionCommand(*source, *state, *policy, *tokenFile, *port)
	default:
		return &exitCode{2, errors.New("provision needs --appliance-state DIR --source DIR, or --state-dir DIR")}
	}
	if !filepath.IsAbs(argv[0]) {
		return &exitCode{2, errors.New("the bring-up command must be absolute")}
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	var output strings.Builder
	cmd.Stdout = io.MultiWriter(stdout, &output)
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bring-up failed (%v); the appliance error above is verbatim", err)
	}
	if !hostd.ReportsReady(output.String()) {
		return errors.New("bring-up ended without ready=true")
	}
	return nil
}

func status(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	stateDir := flags.String("state-dir", hostd.DefaultStateDir, "host agent state directory")
	if err := flags.Parse(args); err != nil {
		return &exitCode{2, err}
	}
	report, err := hostd.Status(*stateDir)
	if err != nil {
		return err
	}
	encoded, _ := json.MarshalIndent(report, "", "  ")
	fmt.Fprintln(stdout, string(encoded))
	return nil
}

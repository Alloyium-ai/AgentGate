// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf

// Command agentgate-broker is the per-launch credential broker. The host agent
// starts one per launch, next to the target, from a root-owned configuration:
//
//	agentgate-broker validate [--skip-secrets] CONFIG
//	agentgate-broker run [--config-sha256 HEX] CONFIG
//
// It never prints, logs or exposes a secret value. See docs/BROKER.md.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"alloyium.local/kernel-poc/internal/broker"
	"alloyium.local/kernel-poc/internal/buildinfo"
	"golang.org/x/sys/unix"
)

// Exit codes.
const (
	exitOK       = 0
	exitRuntime  = 1
	exitConfig   = 2
	exitSecret   = 3
	exitListen   = 4
	exitIdentity = 5
	exitUsage    = 64
)

func main() {
	os.Exit(realMain(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(stderr io.Writer) int {
	fmt.Fprintln(stderr, "usage: agentgate-broker validate [--skip-secrets] CONFIG")
	fmt.Fprintln(stderr, "       agentgate-broker run [--config-sha256 HEX] CONFIG")
	fmt.Fprintln(stderr, "       agentgate-broker version")
	return exitUsage
}

func realMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return usage(stderr)
	}
	switch args[0] {
	case "validate":
		return validate(args[1:], stdout, stderr)
	case "run":
		return run(args[1:], stdout, stderr)
	case "version":
		rev := buildinfo.SourceRevision
		if rev == "" {
			rev = "unversioned"
		}
		fmt.Fprintln(stdout, "agentgate-broker "+rev)
		return exitOK
	}
	return usage(stderr)
}

// parseArgs accepts the flags listed in allowed (each taking a value unless
// it is in boolean) followed by exactly one CONFIG path.
func parseArgs(args []string, valued, boolean map[string]bool) (map[string]string, string, bool) {
	flags := map[string]string{}
	var rest []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case boolean[a]:
			flags[a] = "true"
		case valued[a]:
			if i+1 >= len(args) {
				return nil, "", false
			}
			flags[a] = args[i+1]
			i++
		case strings.HasPrefix(a, "-"):
			return nil, "", false
		default:
			rest = append(rest, a)
		}
	}
	if len(rest) != 1 {
		return nil, "", false
	}
	return flags, rest[0], true
}

// readConfig reads the configuration with custody checks: a regular file,
// not a symlink, owned by root or this user, not writable by group or others,
// and within the size bound.
func readConfig(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("broker config: file cannot be opened")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Nlink != 1 ||
		(st.Uid != 0 && int(st.Uid) != os.Geteuid()) || st.Mode&0o022 != 0 || st.Size > broker.MaxConfigBytes {
		return nil, errors.New("broker config: file custody is invalid (regular, unlinked, root-owned, not group or world writable)")
	}
	raw, err := io.ReadAll(io.LimitReader(f, broker.MaxConfigBytes+1))
	if err != nil || int64(len(raw)) != st.Size {
		return nil, errors.New("broker config: file cannot be read")
	}
	return raw, nil
}

type routeSummary struct {
	Name     string `json:"name"`
	BaseURL  string `json:"base_url"`
	Upstream string `json:"upstream"`
	Rules    int    `json:"rules"`
}

type summary struct {
	OK             bool           `json:"ok"`
	Error          string         `json:"error,omitempty"`
	ConfigSHA256   string         `json:"config_sha256,omitempty"`
	LaunchID       string         `json:"launch_id,omitempty"`
	TargetID       string         `json:"target_id,omitempty"`
	Listen         string         `json:"listen,omitempty"`
	Deadline       string         `json:"deadline,omitempty"`
	Routes         []routeSummary `json:"routes,omitempty"`
	SecretsChecked bool           `json:"secrets_checked"`
	Unchecked      []string       `json:"secrets_unchecked,omitempty"`
}

func emit(stdout io.Writer, s summary) {
	raw, _ := json.MarshalIndent(s, "", "  ")
	stdout.Write(append(raw, '\n'))
}

func validate(args []string, stdout, stderr io.Writer) int {
	flags, path, ok := parseArgs(args, nil, map[string]bool{"--skip-secrets": true})
	if !ok {
		return usage(stderr)
	}
	raw, err := readConfig(path)
	if err != nil {
		emit(stdout, summary{Error: err.Error()})
		return exitConfig
	}
	cfg, err := broker.ParseConfig(raw)
	if err == nil {
		_, err = cfg.Validate(time.Now())
	}
	if err != nil {
		emit(stdout, summary{Error: err.Error()})
		return exitConfig
	}
	s := summary{OK: true, ConfigSHA256: broker.ConfigDigest(raw), LaunchID: cfg.LaunchID, TargetID: cfg.TargetID,
		Deadline: cfg.Deadline}
	if cfg.Listen.Network == "unix" {
		s.Listen = "unix:" + cfg.Listen.Path
	} else {
		s.Listen = "tcp:" + cfg.Listen.ListenAuthority()
	}
	for _, r := range cfg.Routes {
		s.Routes = append(s.Routes, routeSummary{Name: r.Name, BaseURL: broker.BaseURL(cfg, r.Name),
			Upstream: fmt.Sprintf("%s:%d", r.Upstream.Host, r.Upstream.Port), Rules: len(r.Rules)})
	}
	if flags["--skip-secrets"] == "" {
		broker.HardenProcess()
		unchecked, err := broker.CheckSecrets(cfg)
		if err != nil {
			emit(stdout, summary{Error: err.Error()})
			return exitSecret
		}
		s.SecretsChecked, s.Unchecked = true, unchecked
	}
	emit(stdout, s)
	return exitOK
}

func run(args []string, stdout, stderr io.Writer) int {
	// Disable core dumps and same-user inspection before reading anything.
	if h := broker.HardenProcess(); !h.NotDumpable || !h.CoreLimitZero {
		fmt.Fprintln(stderr, "agentgate-broker: refused: core dumps cannot be disabled")
		return exitIdentity
	}
	flags, path, ok := parseArgs(args, map[string]bool{"--config-sha256": true}, nil)
	if !ok {
		return usage(stderr)
	}
	raw, err := readConfig(path)
	if err != nil {
		fmt.Fprintln(stderr, "agentgate-broker: "+err.Error())
		return exitConfig
	}
	digest := broker.ConfigDigest(raw)
	if want, ok := flags["--config-sha256"]; ok && want != digest {
		fmt.Fprintln(stderr, "agentgate-broker: broker config: digest does not match --config-sha256")
		return exitConfig
	}
	cfg, err := broker.ParseConfig(raw)
	if err != nil {
		fmt.Fprintln(stderr, "agentgate-broker: "+err.Error())
		return exitConfig
	}
	srv, err := broker.New(cfg, digest, stderr, broker.Overrides{})
	if err != nil {
		fmt.Fprintln(stderr, "agentgate-broker: "+err.Error())
		if errors.Is(err, broker.ErrSecretCustody) {
			return exitSecret
		}
		return exitConfig
	}
	if err := srv.Listen(); err != nil {
		srv.Close()
		fmt.Fprintln(stderr, "agentgate-broker: "+err.Error())
		return exitListen
	}
	if err := broker.DropPrivileges(cfg.RunAs); err != nil {
		srv.Close()
		fmt.Fprintln(stderr, "agentgate-broker: "+err.Error())
		return exitIdentity
	}
	// A uid change resets the dumpable flag to fs.suid_dumpable; set it again
	// and record what holds while serving.
	h := broker.HardenProcess()
	if !h.NotDumpable || !h.CoreLimitZero || h.UID == 0 {
		srv.Close()
		fmt.Fprintln(stderr, "agentgate-broker: refused: hardening did not hold after the identity change")
		return exitIdentity
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	reason, err := srv.Serve(ctx, h)
	if err != nil {
		fmt.Fprintln(stderr, "agentgate-broker: stopped with an error: "+err.Error())
		return exitRuntime
	}
	_ = reason
	return exitOK
}

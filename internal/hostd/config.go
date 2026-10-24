// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// Runtime kinds a target can be.
const (
	RuntimeDockerHost = "docker-host"
	RuntimeAppliance  = "appliance"
)

// DefaultStateDir holds the key, identity, sequence, ledger and outbox.
const DefaultStateDir = "/var/lib/agentgate-hostd"

const configName = "config.json"

var instancePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// Config is the daemon's protected local configuration (state dir, mode 0600).
type Config struct {
	ServiceURL string `json:"service_url"`
	// AllowLoopbackHTTP permits http:// only to a loopback address, for a
	// service started on the same machine by "agentgate up".
	AllowLoopbackHTTP bool   `json:"allow_loopback_http,omitempty"`
	CAFile            string `json:"ca_file,omitempty"`
	Runtime           string `json:"runtime"`
	// Launcher is the argument vector prefix of the launch runtime: launch.py
	// on a Docker host, or appliance.py guest-launch for the appliance.
	Launcher []string `json:"launcher"`
	// Provisioner is the argument vector of the bring-up command (appliance.py start).
	Provisioner []string `json:"provisioner,omitempty"`
	Instance    string   `json:"instance"`
}

// Validate refuses anything that is not exactly a safe configuration.
func (c Config) Validate() error {
	if _, err := ServiceOrigin(c.ServiceURL, c.AllowLoopbackHTTP); err != nil {
		return err
	}
	if c.CAFile != "" && (!filepath.IsAbs(c.CAFile) || filepath.Clean(c.CAFile) != c.CAFile) {
		return errors.New("hostd: ca_file must be a canonical absolute path")
	}
	if c.Runtime != RuntimeDockerHost && c.Runtime != RuntimeAppliance {
		return errors.New("hostd: runtime must be docker-host or appliance")
	}
	if !instancePattern.MatchString(c.Instance) {
		return errors.New("hostd: instance must match " + instancePattern.String())
	}
	if err := checkArgv(c.Launcher, "launcher", true); err != nil {
		return err
	}
	return checkArgv(c.Provisioner, "provisioner", false)
}

func checkArgv(argv []string, label string, required bool) error {
	if len(argv) == 0 {
		if required {
			return fmt.Errorf("hostd: %s command required", label)
		}
		return nil
	}
	if len(argv) > 16 || !filepath.IsAbs(argv[0]) || filepath.Clean(argv[0]) != argv[0] {
		return fmt.Errorf("hostd: %s must start with an absolute program path", label)
	}
	for _, item := range argv {
		if item == "" || len(item) > 4096 || strings.ContainsAny(item, "\x00\n") {
			return fmt.Errorf("hostd: %s argument invalid", label)
		}
	}
	return nil
}

// ServiceOrigin returns the canonical service origin. Only https is allowed,
// except http to a loopback address when explicitly permitted.
func ServiceOrigin(raw string, allowLoopbackHTTP bool) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return "", errors.New("hostd: the service URL must be an origin such as https://agentgate.example:8443")
	}
	switch u.Scheme {
	case "https":
	case "http":
		host := u.Hostname()
		ip := net.ParseIP(host)
		if !allowLoopbackHTTP || !(host == "localhost" || ip != nil && ip.IsLoopback()) {
			return "", errors.New("hostd: the service URL must use https (http is allowed only to loopback with --allow-loopback-http)")
		}
	default:
		return "", errors.New("hostd: the service URL must use https")
	}
	return u.Scheme + "://" + u.Host, nil
}

func loadConfig(stateDir string) (Config, error) {
	var c Config
	raw, err := readPrivateFile(filepath.Join(stateDir, configName), 64<<10)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&c); err != nil {
		return c, fmt.Errorf("hostd: config: %w", err)
	}
	return c, c.Validate()
}

func saveConfig(stateDir string, c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(stateDir, configName), append(raw, '\n'), 0o600)
}

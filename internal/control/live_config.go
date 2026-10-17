// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"sync"
	"time"
)

type DeploymentSettings struct {
	Schema         string              `json:"schema"`
	PublicURL      string              `json:"public_url"`
	Issuer         string              `json:"oidc_issuer"`
	ClientID       string              `json:"oidc_client_id"`
	GroupRoles     map[string][]string `json:"group_roles"`
	Listen         string              `json:"listen"`
	SessionSeconds int                 `json:"session_seconds"`
}
type VerifiedSettings struct {
	Schema     string             `json:"schema"`
	Subject    string             `json:"subject"`
	Deployment string             `json:"deployment_id"`
	Target     string             `json:"target"`
	Key        string             `json:"key"`
	Revision   int64              `json:"revision"`
	Digest     string             `json:"snapshot_sha256"`
	Deadline   int64              `json:"authoritative_until_ms"`
	Settings   DeploymentSettings `json:"settings"`
}
type LiveConfig struct {
	mu     sync.Mutex
	cmd    *exec.Cmd
	input  io.WriteCloser
	output *bufio.Reader
	floor  int64
	digest string
	failed bool
}

// Only the packaged signed resolver supplies these private pipes. No HTTP/config-file fallback exists.
func OpenLiveConfig() (*LiveConfig, error) {
	if os.Getenv("RUNTIME_CONFIG_BOOTSTRAP_FILE") == "" {
		return nil, errors.New("the enrolled runtime configuration bootstrap is required")
	}
	cmd := exec.Command("/opt/alloyium-control/config-adapter")
	cmd.Stderr = os.Stderr
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		input.Close()
		return nil, err
	}
	return &LiveConfig{cmd: cmd, input: input, output: bufio.NewReaderSize(output, 4096)}, nil
}
func (c *LiveConfig) Close() { c.mu.Lock(); defer c.mu.Unlock(); c.stop() }
func (c *LiveConfig) stop() {
	if !c.failed {
		c.failed = true
		c.input.Close()
		c.cmd.Process.Kill()
		c.cmd.Wait()
	}
}
func (c *LiveConfig) Read() (VerifiedSettings, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed {
		return VerifiedSettings{}, configurationUnavailable()
	}
	type result struct {
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		_, err := io.WriteString(c.input, "{\"operation\":\"settings\"}\n")
		if err != nil {
			done <- result{err: err}
			return
		}
		var data []byte
		for {
			part, prefix, e := c.output.ReadLine()
			if e != nil {
				done <- result{err: e}
				return
			}
			data = append(data, part...)
			if len(data) > 65536 {
				done <- result{err: errors.New("bounded response exceeded")}
				return
			}
			if !prefix {
				break
			}
		}
		done <- result{data: data}
	}()
	select {
	case response := <-done:
		if response.err != nil {
			c.stop()
			return VerifiedSettings{}, configurationUnavailable()
		}
		var envelope struct {
			OK    bool             `json:"ok"`
			Value VerifiedSettings `json:"value"`
			Error string           `json:"error"`
		}
		if json.Unmarshal(response.data, &envelope) != nil || !envelope.OK {
			return VerifiedSettings{}, configurationUnavailable()
		}
		v := envelope.Value
		if err := validateVerifiedSettings(v, c.floor, c.digest, time.Now()); err != nil {
			return VerifiedSettings{}, err
		}
		c.floor, c.digest = v.Revision, v.Digest
		return v, nil
	case <-time.After(4 * time.Second):
		c.stop()
		return VerifiedSettings{}, configurationUnavailable()
	}
}
func configurationUnavailable() error {
	return fail(503, "configuration_unavailable", "The current signed configuration does not grant authority.")
}
func validateVerifiedSettings(v VerifiedSettings, floor int64, digest string, now time.Time) error {
	if v.Schema != "agentgate.verified-settings.v1" || v.Subject != "agentgate-control" || v.Deployment != "dev" || v.Target != "service:agentgate" || v.Key != "agentgate.control.settings" || v.Revision < 1 || v.Revision < floor || len(v.Digest) != 64 || v.Revision == floor && digest != "" && v.Digest != digest || v.Deadline <= now.UnixMilli() {
		return configurationUnavailable()
	}
	if v.Settings.Schema != "agentgate.control.settings.v1" || v.Settings.SessionSeconds < 60 || v.Settings.SessionSeconds > 3600 {
		return configurationUnavailable()
	}
	return ValidateAuthConfig(v.Settings.AuthConfig())
}
func (s DeploymentSettings) AuthConfig() AuthConfig {
	return AuthConfig{Issuer: s.Issuer, ClientID: s.ClientID, PublicURL: s.PublicURL, GroupRoles: s.GroupRoles, SessionLifetime: time.Duration(s.SessionSeconds) * time.Second}
}

// Origin, issuer, audience and listener changes need a new server epoch. Role changes take effect on each boundary.
func currentSettings(read func() (VerifiedSettings, error), initial DeploymentSettings) func() (AuthConfig, error) {
	return func() (AuthConfig, error) {
		value, err := read()
		if err != nil {
			return AuthConfig{}, err
		}
		a, b := initial, value.Settings
		a.GroupRoles = nil
		b.GroupRoles = nil
		if !reflect.DeepEqual(a, b) {
			return AuthConfig{}, fail(503, "configuration_restart_required", "The approved identity or listener configuration requires a server restart.")
		}
		return value.Settings.AuthConfig(), nil
	}
}
func (a *Auth) BindLiveConfig(read func() (VerifiedSettings, error), initial DeploymentSettings) {
	a.CurrentConfig = currentSettings(read, initial)
	a.Store.CheckConfiguration = func() error { _, err := a.CurrentConfig(); return err }
}

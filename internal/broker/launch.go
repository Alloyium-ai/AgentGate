// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// LaunchSecret is one brokered secret as the host agent knows it from a
// launch job (hostproto.LaunchSecret) plus the host's own secret file.
type LaunchSecret struct {
	Ref        string
	Env        string
	Upstreams  []string // "host" or "host:port", exact names
	Header     string
	Scheme     string // "", "Bearer" or "Basic"; empty means the default below
	Username   string // Basic only
	Rules      []Rule // empty means the default below
	SecretFile string
	Extra      map[string]string
}

// LaunchInput is everything the host agent decides for one launch's broker.
type LaunchInput struct {
	LaunchID  string
	TargetID  string
	Deadline  time.Time
	Listen    Listen
	StatsPath string
	RunAs     Identity
	Limits    *Limits
	Secrets   []LaunchSecret
}

// DefaultRules is the interim rule set when a launch job carries no path
// rules: every allowed method on every path of the one origin. It is the
// widest setting; the contract asks for explicit rules per secret.
func DefaultRules() []Rule {
	return []Rule{{Methods: []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, Path: "/", Match: "prefix"}}
}

// RouteName is the route for upstream index i of secret ref: the ref itself
// for the first upstream, ref-2, ref-3 ... for the others.
func RouteName(ref string, i int) string {
	if i == 0 {
		return ref
	}
	return ref + "-" + strconv.Itoa(i+1)
}

// BuildLaunchConfig maps a launch's secrets onto one broker configuration:
// one route per (secret, upstream) pair, each binding exactly one secret file
// to exactly one origin. It returns the configuration bytes (write them
// root-owned, not group or world writable, outside every sandbox mount), the
// parsed configuration, and the environment the agent receives: each
// expose.env name mapped to its first route's base URL. The result is
// validated exactly as the broker will validate it.
func BuildLaunchConfig(in LaunchInput, now time.Time) ([]byte, *Config, map[string]string, error) {
	if len(in.Secrets) == 0 {
		return nil, nil, nil, errors.New("broker launch: no secrets")
	}
	run := in.RunAs
	cfg := Config{Version: ConfigVersion, LaunchID: in.LaunchID, TargetID: in.TargetID,
		Deadline: in.Deadline.UTC().Format(time.RFC3339), Listen: in.Listen, StatsPath: in.StatsPath, RunAs: &run, Limits: in.Limits}
	env := map[string]string{}
	for _, s := range in.Secrets {
		if len(s.Upstreams) == 0 {
			return nil, nil, nil, fmt.Errorf("broker launch: secret %s has no upstream", s.Ref)
		}
		scheme := s.Scheme
		if scheme == "" && strings.EqualFold(s.Header, "authorization") {
			scheme = "Bearer"
		}
		rules := s.Rules
		if len(rules) == 0 {
			rules = DefaultRules()
		}
		for i, up := range s.Upstreams {
			host, port := up, 443
			if h, p, err := net.SplitHostPort(up); err == nil {
				n, err := strconv.Atoi(p)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("broker launch: secret %s upstream port is invalid", s.Ref)
				}
				host, port = h, n
			}
			cfg.Routes = append(cfg.Routes, Route{Name: RouteName(s.Ref, i), Upstream: Upstream{Host: host, Port: port},
				Credential: Credential{SecretFile: s.SecretFile, Header: strings.ToLower(s.Header), Scheme: scheme,
					Username: s.Username, ExtraHeaders: s.Extra},
				Rules: rules})
		}
		if s.Env != "" {
			if _, dup := env[s.Env]; dup {
				return nil, nil, nil, fmt.Errorf("broker launch: environment name %s is used twice", s.Env)
			}
			env[s.Env] = ""
		}
	}
	raw, err := json.MarshalIndent(&cfg, "", "  ")
	if err != nil {
		return nil, nil, nil, err
	}
	parsed, err := ParseConfig(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := parsed.Validate(now); err != nil {
		return nil, nil, nil, err
	}
	for _, s := range in.Secrets {
		if s.Env != "" {
			env[s.Env] = BaseURL(parsed, RouteName(s.Ref, 0))
		}
	}
	return raw, parsed, env, nil
}

// BrokerCounts folds a stats document into hostproto.Receipt.BrokerCounts:
// requests forwarded per upstream, keyed "host" for port 443 and "host:port"
// otherwise.
func BrokerCounts(doc *StatsDocument) map[string]uint64 {
	out := map[string]uint64{}
	if doc == nil {
		return out
	}
	for _, r := range doc.Routes {
		key := strings.TrimSuffix(r.Upstream, ":443")
		out[key] += r.Forwarded
	}
	return out
}

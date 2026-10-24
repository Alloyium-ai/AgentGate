// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package localconfig

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type Settings struct {
	Schema         string              `json:"schema"`
	PublicURL      string              `json:"public_url"`
	Listen         string              `json:"listen"`
	SessionSeconds int                 `json:"session_seconds"`
	AuthMode       string              `json:"auth_mode"`
	Issuer         string              `json:"oidc_issuer,omitempty"`
	ClientID       string              `json:"oidc_client_id,omitempty"`
	GroupRoles     map[string][]string `json:"group_roles"`
}

func (s Settings) LocalEnabled() bool { return s.AuthMode == "local" || s.AuthMode == "both" }
func (s Settings) OIDCEnabled() bool  { return s.AuthMode == "oidc" || s.AuthMode == "both" }

func secureURL(value string, origin bool) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil &&
		u.RawQuery == "" && u.Fragment == "" && (!origin || u.Path == "" || u.Path == "/")
}

func (s Settings) Validate() error {
	if s.Schema != "agentgate.community.settings.v1" || !secureURL(s.PublicURL, true) ||
		s.SessionSeconds < 60 || s.SessionSeconds > 3600 ||
		!s.LocalEnabled() && !s.OIDCEnabled() {
		return errors.New("invalid protected Community settings")
	}
	host, port, err := net.SplitHostPort(s.Listen)
	if err != nil || strings.TrimSpace(host) != host || host == "" || port == "" {
		return errors.New("invalid service listener")
	}
	if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 || net.ParseIP(host) == nil {
		return errors.New("listener requires a literal address and valid port")
	}
	if s.OIDCEnabled() && (!secureURL(s.Issuer, false) || len(s.ClientID) < 1 || len(s.ClientID) > 200) {
		return errors.New("OIDC requires an exact HTTPS issuer and client")
	}
	if !s.OIDCEnabled() && (s.Issuer != "" || s.ClientID != "") {
		return errors.New("OIDC settings require explicit OIDC authentication")
	}
	valid := map[string]bool{"viewer": true, "editor": true, "launcher": true, "approver": true, "auditor": true, "admin": true}
	if len(s.GroupRoles) > 64 {
		return errors.New("too many group mappings")
	}
	for name, roles := range s.GroupRoles {
		if len(name) < 1 || len(name) > 128 || len(roles) < 1 || len(roles) > len(valid) {
			return errors.New("invalid basic group mapping")
		}
		for _, role := range roles {
			if !valid[role] {
				return errors.New("unknown basic role")
			}
		}
	}
	return nil
}

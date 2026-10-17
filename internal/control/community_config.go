// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"alloyium.local/kernel-poc/internal/localconfig"
	"crypto/ed25519"
	"reflect"
	"time"
)

func CommunityAuthConfig(settings localconfig.Settings, instance string) AuthConfig {
	return AuthConfig{AuthMode: settings.AuthMode, Instance: instance, Issuer: settings.Issuer, ClientID: settings.ClientID, PublicURL: settings.PublicURL, GroupRoles: settings.GroupRoles, SessionLifetime: time.Duration(settings.SessionSeconds) * time.Second}
}
func (a *Auth) BindCommunityConfig(config *localconfig.Store, initial localconfig.Record) {
	a.CurrentConfig = func() (AuthConfig, error) {
		current, err := config.Read()
		if err != nil {
			return AuthConfig{}, configurationUnavailable()
		}
		before, after := initial.Settings, current.Settings
		before.GroupRoles = nil
		after.GroupRoles = nil
		if !reflect.DeepEqual(before, after) || current.Instance != initial.Instance {
			return AuthConfig{}, fail(503, "configuration_restart_required", "The approved identity or listener configuration requires a server restart.")
		}
		return CommunityAuthConfig(current.Settings, current.Instance), nil
	}
	a.Store.CheckConfiguration = func() error {
		if err := config.VerifyAuthority(EncodePublic(a.Store.Authority.Public().(ed25519.PublicKey))); err != nil {
			return configurationUnavailable()
		}
		_, err := a.CurrentConfig()
		return err
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"testing"
	"time"
)

func configFixture() VerifiedSettings {
	return VerifiedSettings{Schema: "agentgate.verified-settings.v1", Subject: "agentgate-control", Deployment: "dev", Target: "service:agentgate", Key: "agentgate.control.settings", Revision: 19, Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Deadline: time.Now().Add(time.Minute).UnixMilli(), Settings: DeploymentSettings{Schema: "agentgate.control.settings.v1", PublicURL: "https://control.example.test", Issuer: "https://identity.example.test/application/o/agentgate/", ClientID: "agentgate", GroupRoles: map[string][]string{"admins": {"admin"}}, Listen: "0.0.0.0:8930", SessionSeconds: 1800}}
}
func TestConfigBindingDeadlineRollback(t *testing.T) {
	base := configFixture()
	if err := validateVerifiedSettings(base, 19, base.Digest, time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*VerifiedSettings){func(v *VerifiedSettings) { v.Subject = "other" }, func(v *VerifiedSettings) { v.Target = "other" }, func(v *VerifiedSettings) { v.Deployment = "prod" }, func(v *VerifiedSettings) { v.Key = "other" }, func(v *VerifiedSettings) { v.Revision = 18 }, func(v *VerifiedSettings) {
		v.Digest = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	}, func(v *VerifiedSettings) { v.Deadline = time.Now().UnixMilli() }} {
		v := base
		change(&v)
		if validateVerifiedSettings(v, 19, base.Digest, time.Now()) == nil {
			t.Fatal("invalid binding authorized")
		}
	}
}
func TestConfigCurrentRolesAndRestart(t *testing.T) {
	current := configFixture()
	initial := current.Settings
	read := func() (VerifiedSettings, error) { return current, nil }
	get := currentSettings(read, initial)
	current.Settings.GroupRoles = map[string][]string{"admins": {"viewer"}}
	cfg, err := get()
	if err != nil || cfg.GroupRoles["admins"][0] != "viewer" {
		t.Fatal("obsolete role map", err)
	}
	current.Settings.Issuer = "https://other.example/"
	if _, err = get(); err == nil {
		t.Fatal("identity change needs restart")
	}
}
func TestConfigLeaseFailsBeforeMutationCommitAndCachedReply(t *testing.T) {
	s := storeFixture(t)
	live := true
	s.CheckConfiguration = func() error {
		if !live {
			return configurationUnavailable()
		}
		return nil
	}
	op := Operation{Actor: Actor{Subject: "config-test", Kind: "system", Scopes: []string{"policy:write"}}, Action: "config.test", Resource: "policy", Reason: "Test configuration expiry", RequestID: "config-test", Idempotency: "once", BodyDigest: "a"}
	_, err := s.Mutation(op, "policy:write", false, func(tx *sql.Tx, op *Operation) (any, error) {
		live = false
		_, e := tx.Exec("INSERT INTO policies VALUES('expired','expired','','now')")
		return map[string]string{"id": "expired"}, e
	})
	if err == nil {
		t.Fatal("expired authority committed")
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM policies WHERE id='expired'").Scan(&count)
	if count != 0 {
		t.Fatal("mutation survived rollback")
	}
	live = true
	_, err = s.Mutation(op, "policy:write", false, func(tx *sql.Tx, op *Operation) (any, error) { return map[string]string{"id": "ok"}, nil })
	if err != nil {
		t.Fatal(err)
	}
	live = false
	if _, err = s.Mutation(op, "policy:write", false, func(*sql.Tx, *Operation) (any, error) { t.Fatal("cached function reran"); return nil, nil }); err == nil {
		t.Fatal("cached authority survived expiry")
	}
}
func TestLiveRoleMapRemovesPreparedSessionPrivileges(t *testing.T) {
	s := storeFixture(t)
	current := configFixture()
	initial := current.Settings
	read := func() (VerifiedSettings, error) {
		if err := validateVerifiedSettings(current, 0, "", time.Now()); err != nil {
			return VerifiedSettings{}, err
		}
		return current, nil
	}
	auth := &Auth{Store: s, Config: initial.AuthConfig()}
	s.ResolveRoles = auth.roles
	auth.BindLiveConfig(read, initial)
	op := humanOp()
	op.Action = "configuration.role.test"
	op.Resource = "policy"
	op.Reason = "Test current role enforcement"
	op.Idempotency = "role-once"
	_, err := s.Mutation(op, "policy:write", true, func(tx *sql.Tx, op *Operation) (any, error) {
		current.Settings.GroupRoles = map[string][]string{"admins": {"viewer"}}
		_, e := tx.Exec("INSERT INTO policies VALUES('role-withdrawn','role-withdrawn','','now')")
		return map[string]string{"id": "role-withdrawn"}, e
	})
	if err == nil {
		t.Fatal("the prepared session retained obsolete admin rights")
	}
	var count int
	s.DB.QueryRow("SELECT count(*) FROM policies WHERE id='role-withdrawn'").Scan(&count)
	if count != 0 {
		t.Fatal("role withdrawal did not roll back")
	}
	current.Settings.GroupRoles = map[string][]string{"admins": {"admin"}}
	_, err = s.Mutation(op, "policy:write", true, func(*sql.Tx, *Operation) (any, error) { return map[string]string{"id": "cached"}, nil })
	if err != nil {
		t.Fatal(err)
	}
	current.Settings.GroupRoles = map[string][]string{"admins": {"viewer"}}
	if _, err = s.Mutation(op, "policy:write", true, func(*sql.Tx, *Operation) (any, error) { t.Fatal("cached function reran"); return nil, nil }); err == nil {
		t.Fatal("cached reply retained obsolete rights")
	}
	current.Settings.GroupRoles = map[string][]string{"admins": {"admin"}}
	current.Deadline = time.Now().Add(-time.Second).UnixMilli()
	if _, err = s.Mutation(op, "policy:write", true, func(*sql.Tx, *Operation) (any, error) { return nil, nil }); err == nil {
		t.Fatal("cached reply retained expired authority")
	}
}

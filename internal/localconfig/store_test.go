// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package localconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func sample() Settings {
	return Settings{Schema: "agentgate.community.settings.v1", PublicURL: "https://control.example.test", Listen: "127.0.0.1:8930", SessionSeconds: 1800, AuthMode: "local", GroupRoles: map[string][]string{}}
}
func fixture(t *testing.T) (*Store, string, string) {
	t.Helper()
	root := t.TempDir()
	dir, trust := filepath.Join(root, "state"), filepath.Join(root, "trust")
	s, err := New(dir, trust, sample())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.DB.Close() })
	return s, dir, trust
}
func admin() Operation {
	return Operation{Actor: "deployment-administrator", Kind: "system", Reason: "Update the owned product configuration.", RequestID: "fixture-update"}
}

func TestProtectedLocalStartAndUnchangedRestart(t *testing.T) {
	s, dir, trust := fixture(t)
	r, err := s.Read()
	if err != nil || r.Revision != 1 || !r.Settings.LocalEnabled() || r.Settings.OIDCEnabled() {
		t.Fatalf("read: %v %+v", err, r)
	}
	reopened, err := Open(dir, trust)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.DB.Close()
	after, err := reopened.Read()
	if err != nil || after.Instance != r.Instance || after.Revision != r.Revision {
		t.Fatal("unchanged restart lost the protected instance", err)
	}
}

func TestConfigurationAuditAndParentConflict(t *testing.T) {
	s, _, _ := fixture(t)
	next := sample()
	next.GroupRoles = map[string][]string{"Auditors": {"auditor"}}
	if _, err := s.Publish(admin(), next, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(admin(), sample(), 1); err == nil {
		t.Fatal("stale parent accepted")
	}
	var versions, audit int
	s.DB.QueryRow("SELECT count(*) FROM config_versions").Scan(&versions)
	s.DB.QueryRow("SELECT count(*) FROM config_audit").Scan(&audit)
	if versions != 2 || audit != 2 {
		t.Fatalf("versions %d audit %d", versions, audit)
	}
	if _, err := s.DB.Exec("UPDATE config_versions SET record='{}' WHERE revision=1"); err == nil {
		t.Fatal("configuration history changed")
	}
}

func TestAuditFailureRollsBackActiveConfiguration(t *testing.T) {
	s, _, _ := fixture(t)
	if _, err := s.DB.Exec("CREATE TRIGGER fixture_audit_failure BEFORE INSERT ON config_audit BEGIN SELECT RAISE(ABORT,'fixture'); END;"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(admin(), sample(), 1); err == nil {
		t.Fatal("audit failure accepted")
	}
	r, err := s.Read()
	if err != nil || r.Revision != 1 {
		t.Fatal("failed mutation changed the active configuration", err)
	}
}

func TestRollbackAndMissingAnchorFailClosed(t *testing.T) {
	s, _, trust := fixture(t)
	if _, err := s.Publish(admin(), sample(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("UPDATE config_active SET revision=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err == nil {
		t.Fatal("rollback accepted")
	}
	if err := os.Remove(filepath.Join(trust, "anchor.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err == nil {
		t.Fatal("missing independent anchor accepted")
	}
}

func TestWrongKeyAndModifiedRecordFailClosed(t *testing.T) {
	s, dir, trust := fixture(t)
	if _, err := s.DB.Exec("DROP TRIGGER config_version_no_update"); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := s.DB.QueryRow("SELECT record FROM config_versions WHERE revision=1").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var record Record
	json.Unmarshal([]byte(raw), &record)
	record.Settings.SessionSeconds = 600
	data, _ := json.Marshal(record)
	if _, err := s.DB.Exec("UPDATE config_versions SET record=? WHERE revision=1", string(data)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err == nil {
		t.Fatal("changed signed record accepted")
	}
	key, _ := os.ReadFile(filepath.Join(dir, "config.key"))
	key[0] ^= 1
	os.WriteFile(filepath.Join(dir, "config.key"), key, 0600)
	if _, err := Open(dir, trust); err == nil {
		t.Fatal("inconsistent private seed accepted")
	}
}

func TestExplicitAuthenticationAndLiteralListenerRequired(t *testing.T) {
	for _, change := range []func(*Settings){func(s *Settings) { s.AuthMode = "" }, func(s *Settings) { s.PublicURL = "http://control.example.test" }, func(s *Settings) { s.Listen = "127.0.0.1:invalid" }, func(s *Settings) { s.AuthMode = "oidc" }, func(s *Settings) { s.GroupRoles = map[string][]string{"unknown": {"superuser"}} }} {
		s := sample()
		change(&s)
		if s.Validate() == nil {
			t.Fatal("invalid authentication, origin, listener or role accepted")
		}
	}
}

func TestSignedRecordBindsDatabaseRevision(t *testing.T) {
	s, _, _ := fixture(t)
	if _, err := s.DB.Exec("INSERT INTO config_versions SELECT 2,record,signature FROM config_versions WHERE revision=1; UPDATE config_active SET revision=2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Read(); err == nil {
		t.Fatal("a signed record at a different database revision was accepted")
	}
}
func TestIndependentApplicationAuthorityPin(t *testing.T) {
	s, _, _ := fixture(t)
	const public = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if err := s.PinAuthority(public); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifyAuthority(public); err != nil {
		t.Fatal(err)
	}
	if err := s.PinAuthority(public); err == nil {
		t.Fatal("authority pin overwrite accepted")
	}
	if err := s.VerifyAuthority("different"); err == nil {
		t.Fatal("untrusted application signer accepted")
	}
}

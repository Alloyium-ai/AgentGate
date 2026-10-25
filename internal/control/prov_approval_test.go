// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"encoding/json"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/pocpolicy"
)

func hasReason(plan LaunchPlan, part string) bool {
	for _, r := range plan.ApprovalReasons {
		if strings.Contains(r, part) {
			return true
		}
	}
	return false
}

// Regression for the review repro TestReviewEditorWidensAutoApprovedProfile:
// an administrator let launches of a narrow profile skip approval; an editor
// then added versions that point DNS at an arbitrary resolver, enable
// anonymous executable memory and re-point the taskboard at the Docker API,
// and a launcher started the new version with nobody reviewing it.
func TestEditorWideningAnAutoApprovedProfileNeedsApproval(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	created := f.profile("safe", false) // an administrator reviewed version 1
	if created.ApprovedVersion != 1 || created.ApprovedDigest == "" || created.ApprovedBy != "oidc:ada" {
		t.Fatalf("the profile records the approved version: %+v", created)
	}
	l, plan := f.launch(f.launcher(), specMap("safe"))
	if l.State != StateQueued || plan.Approval != "auto" {
		t.Fatalf("the approved version launches alone: %s %s %v", l.State, plan.Approval, plan.ApprovalReasons)
	}
	must(f.s.StopLaunch(f.launcher(), l.ID, DecisionInput{Reason: "cleanup"}))

	out := must(f.s.ApplyGrants(f.editor(), "safe", "1", GrantInput{Edits: []access.Edit{
		{Action: access.ActionDNS, Values: []string{"45.33.32.156"}},
		{Action: access.ActionAnonExec},
	}, Reason: "Editor widens the auto profile"})).(map[string]any)
	v := out["version"].(ProfileVersion)
	doc, _ := pocpolicy.Parse(v.Document)
	doc.Taskboard = pocpolicy.Taskboard{Address: "172.17.0.1", Protocol: "tcp", Port: 2375, TaskID: 1}
	doc.Filesystem.Deny = doc.Filesystem.Deny[1:]
	doc.Filesystem.Execute = append(doc.Filesystem.Execute, "/opt")
	raw, _ := json.Marshal(doc)
	must(f.s.CreateProfileVersion(f.editor(), "safe", ProfileVersionInput{ParentVersion: v.Number, Document: raw, Reason: "Editor re-points the taskboard"}))

	m := specMap("safe")
	m["access"] = map[string]any{"profile": "safe", "version": 3}
	l, plan = f.launch(f.launcher(), m)
	if l.State != StateApprovalPending || plan.Approval != "required" {
		t.Fatalf("an editor's version launched without approval: %s %s", l.State, plan.Approval)
	}
	for _, part := range []string{"is not the administrator-approved version 1", "DNS resolvers", "taskboard endpoint", "anonymous executable memory",
		"execute not in the approved version: /opt", "deny trees removed since the approved version"} {
		if !hasReason(plan, part) {
			t.Errorf("the approval reasons do not name %q: %v", part, plan.ApprovalReasons)
		}
	}
	// The editor cannot approve the version for launches without approval.
	v3 := must(f.s.ProfileVersionDetail("safe", "3"))
	if _, err := f.s.SetProfileApproval(f.editor(), "safe", ProfileSettingsInput{RequireApproval: false, Version: 3, Digest: v3.Digest, Reason: "Editor approves its own version"}); errCode(err) != "forbidden" {
		t.Fatalf("an editor approved a version: %v", err)
	}
	// The approver decides this launch; it cannot be the launcher.
	must(f.s.DecideLaunch(f.approver(), l.ID, true, DecisionInput{Reason: "Reviewed the widened version"}))
}

func TestOnlyTheAdministratorApprovedDigestLaunchesAlone(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	f.profile("dev", true) // an editor's profile: approval required
	l, plan := f.launch(f.launcher(), specMap("dev"))
	if l.State != StateApprovalPending || !hasReason(plan, "the profile requires approval") {
		t.Fatalf("%s %v", l.State, plan.ApprovalReasons)
	}
	v1 := must(f.s.ProfileVersionDetail("dev", "1"))
	// Relaxing the profile names the reviewed version and its digest.
	if _, err := f.s.SetProfileApproval(f.admin(), "dev", ProfileSettingsInput{RequireApproval: false, Reason: "Skip approval"}); errCode(err) != "approved_version_required" {
		t.Fatalf("relaxing without a version: %v", err)
	}
	wrong := strings.Repeat("0", 64)
	if _, err := f.s.SetProfileApproval(f.admin(), "dev", ProfileSettingsInput{RequireApproval: false, Version: 1, Digest: wrong, Reason: "Skip approval"}); errCode(err) != "digest_mismatch" {
		t.Fatalf("a digest the version does not have: %v", err)
	}
	p := must(f.s.SetProfileApproval(f.admin(), "dev", ProfileSettingsInput{RequireApproval: false, Version: 1, Digest: v1.Digest, Reason: "Reviewed version 1"})).(Profile)
	if p.RequireApproval || p.ApprovedVersion != 1 || p.ApprovedDigest != v1.Digest {
		t.Fatalf("%+v", p)
	}
	var audited int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='profile.approval.changed' AND result='committed' AND version=?", v1.ID).Scan(&audited)
	if audited != 1 {
		t.Fatalf("approval audit rows %d", audited)
	}
	if l, plan = f.launch(f.launcher(), specMap("dev")); l.State != StateQueued {
		t.Fatalf("the approved version: %s %v", l.State, plan.ApprovalReasons)
	}
	must(f.s.StopLaunch(f.launcher(), l.ID, DecisionInput{Reason: "cleanup"}))
	// A new version by anyone, even an identical-looking one, is not approved.
	must(f.s.ApplyGrants(f.admin(), "dev", "1", GrantInput{Edits: []access.Edit{{Action: access.ActionDNS, Values: []string{"9.9.9.9"}}}, Reason: "Admin edits"}))
	m := specMap("dev")
	m["access"] = map[string]any{"profile": "dev", "version": 2}
	if l, plan = f.launch(f.launcher(), m); l.State != StateApprovalPending || !hasReason(plan, "not the administrator-approved version 1") {
		t.Fatalf("version 2: %s %v", l.State, plan.ApprovalReasons)
	}
	// Requiring approval again clears the approved version.
	p = must(f.s.SetProfileApproval(f.admin(), "dev", ProfileSettingsInput{RequireApproval: true, Reason: "Require a second person"})).(Profile)
	if !p.RequireApproval || p.ApprovedDigest != "" || p.ApprovedVersion != 0 {
		t.Fatalf("%+v", p)
	}
	// The database refuses an approved digest that names no version of the profile.
	if _, err := f.s.DB.Exec("UPDATE profiles SET approved_version_id=?,approved_digest=?,approved_by='x',approved_at='y' WHERE name='dev'", v1.ID, wrong); err == nil {
		t.Fatal("the trigger accepted a digest of no version")
	}
}

// A profile that skips approval but whose approval was never recorded (for
// example one migrated from schema 7) launches nothing alone.
func TestAProfileWithoutAnApprovedVersionNeedsApproval(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	f.profile("dev", false)
	if _, err := f.s.DB.Exec("UPDATE profiles SET approved_version_id='',approved_digest='',approved_by='',approved_at='' WHERE name='dev'"); err != nil {
		t.Fatal(err)
	}
	l, plan := f.launch(f.launcher(), specMap("dev"))
	if l.State != StateApprovalPending || !hasReason(plan, "no version of profile dev is approved") {
		t.Fatalf("%s %v", l.State, plan.ApprovalReasons)
	}
}

// Schema 8 adds the approved version columns to a version 7 database once
// (the second migration-8 row; the first is the fresh database's own),
// and a relaxed profile from before it approves no version.
func TestSchemaEightMigratesAVersionSevenDatabase(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	f.profile("dev", false)
	for _, stmt := range []string{"DROP TRIGGER profile_approved_version_exists", "DROP TRIGGER profile_approved_pair", "ALTER TABLE profiles DROP COLUMN approved_version_id",
		"ALTER TABLE profiles DROP COLUMN approved_digest", "ALTER TABLE profiles DROP COLUMN approved_by", "ALTER TABLE profiles DROP COLUMN approved_at", "PRAGMA user_version=7"} {
		if _, err := f.s.DB.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	f.http.Close()
	f.s.DB.Close()
	for i := 0; i < 2; i++ {
		s, err := OpenStore(f.dir)
		if err != nil {
			t.Fatal(err)
		}
		var version, eight int
		s.DB.QueryRow("PRAGMA user_version").Scan(&version)
		s.DB.QueryRow("SELECT count(*) FROM audit WHERE request_id='migration-8'").Scan(&eight)
		p, err := s.ProfileDetail("dev")
		s.DB.Close()
		if err != nil || version != SchemaVersion || eight != 2 || p.RequireApproval || p.ApprovedDigest != "" {
			t.Fatalf("open %d: version %d, migration eight %d times, %+v %v", i, version, eight, p, err)
		}
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"strings"
	"testing"
)

// reviewHostPaths are the host folders of the review repro
// TestReviewSnapshotMountOfHostPathNeedsNoApproval.
var reviewHostPaths = []string{"/var/backups", "/var/lib/postgresql", "/var/lib/rancher", "/var/lib/containers", "/var/lib/systemd",
	"/home/alice/work", "/srv", "/opt", "/var/log", "/var/spool", "/var/mail"}

// Regression for TestReviewSnapshotMountOfHostPathNeedsNoApproval: a snapshot
// of any non-protected host path was queued with no approval and no
// allowlist.
func TestEveryHostFolderMountNeedsAMountRootAndApproval(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	f.profile("safe", false)
	try := func(src, mode string) (string, error) {
		m := specMap("safe")
		m["mounts"] = []any{map[string]any{"name": "loot", "source": src, "mode": mode}}
		value, err := f.s.CreateLaunch(f.launcher(), specBytes(t, m))
		if err != nil {
			return "", err
		}
		out := value.(map[string]any)
		l, plan := out["launch"].(Launch), out["plan"].(LaunchPlan)
		must(f.s.StopLaunch(f.launcher(), l.ID, DecisionInput{Reason: "cleanup"}))
		return plan.Approval, nil
	}
	// No mount roots (the default): every host folder is refused.
	for _, src := range reviewHostPaths {
		for _, mode := range []string{"snapshot", "read-only", "read-write"} {
			if approval, err := try(src, mode); err == nil {
				t.Errorf("%s %s planned (%s) without a mount root", mode, src, approval)
			}
		}
	}
	// System state, backups, logs and spools stay protected even as roots.
	for _, root := range []string{"/var/backups", "/var/lib/rancher", "/var/lib/containers", "/var/lib/systemd", "/var/log", "/var/spool", "/var/mail"} {
		if _, err := f.s.SetTargetMountRoots(f.admin(), "local", TargetMountRootsInput{MountRoots: []string{root}, Reason: "List a protected tree"}); errCode(err) != "invalid_mount_roots" {
			t.Errorf("mount root %s: %v", root, err)
		}
	}
	// Listed roots: every mount below them still needs a second human.
	f.mountRoots("local", "/srv", "/opt", "/home/alice/work", "/var/lib/postgresql")
	for _, src := range []string{"/srv", "/opt/tools", "/home/alice/work", "/var/lib/postgresql/16"} {
		for _, mode := range []string{"snapshot", "read-only", "read-write"} {
			approval, err := try(src, mode)
			if err != nil || approval != "required" {
				t.Errorf("%s %s: %s %v", mode, src, approval, err)
			}
		}
	}
	if _, err := try("/var/lib/other", "snapshot"); errCode(err) != "mount_root_not_allowed" {
		t.Fatalf("a folder outside the roots: %v", err)
	}
}

func TestMountRootsAreAdministeredAndAudited(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	in := TargetMountRootsInput{MountRoots: []string{"/srv/repos"}, Reason: "Repositories may be mounted"}
	if _, err := f.s.SetTargetMountRoots(f.editor(), "local", in); errCode(err) != "forbidden" {
		t.Fatalf("an editor set mount roots: %v", err)
	}
	for _, bad := range [][]string{{"/"}, {"/etc"}, {"/home/alice"}, {"/srv/../etc"}, {"relative"}, {"/srv", "/srv"}, {"/home/a/.ssh"},
		{"/s1", "/s2", "/s3", "/s4", "/s5", "/s6", "/s7", "/s8", "/s9", "/s10", "/s11", "/s12", "/s13", "/s14", "/s15", "/s16", "/s17"}} {
		if _, err := f.s.SetTargetMountRoots(f.admin(), "local", TargetMountRootsInput{MountRoots: bad, Reason: "Try a bad root"}); errCode(err) != "invalid_mount_roots" {
			t.Errorf("%v: %v", bad, err)
		}
	}
	tg := must(f.s.SetTargetMountRoots(f.admin(), "local", in)).(Target)
	if strings.Join(tg.MountRoots, ",") != "/srv/repos" {
		t.Fatalf("%v", tg.MountRoots)
	}
	var audited int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='target.mount_roots.changed' AND result='committed' AND resource=?", "target:"+tg.ID).Scan(&audited)
	if audited != 1 {
		t.Fatalf("audit rows %d", audited)
	}
	// Over HTTP the endpoint is admin only and validated like the store.
	admin, editor := f.token(f.admin(), "admin"), f.token(f.editor(), "editor")
	if resp, _ := f.apiRequest("POST", "/api/v1/targets/local/mount-roots", editor, []byte(`{"mount_roots":[],"reason":"Clear them"}`)); resp.StatusCode != 403 {
		t.Fatalf("editor over HTTP: %d", resp.StatusCode)
	}
	if resp, _ := f.apiRequest("POST", "/api/v1/targets/local/mount-roots", admin, []byte(`{"mount_roots":["/srv"],"reason":"Wider","extra":1}`)); resp.StatusCode != 422 {
		t.Fatalf("unknown field: %d", resp.StatusCode)
	}
	if resp, out := f.apiRequest("POST", "/api/v1/targets/local/mount-roots", admin, []byte(`{"mount_roots":[],"reason":"Clear them"}`)); resp.StatusCode != 200 || len(out["mount_roots"].([]any)) != 0 {
		t.Fatalf("clear: %d %v", resp.StatusCode, out)
	}
}

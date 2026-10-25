// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"encoding/json"
	"testing"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// Regression for the review repro TestReviewRotationStrandsPendingApprovalTarget:
// a host that enrolled (awaiting approval) just before a job key rotation kept
// the retired key; approving it produced an "active" target whose every job
// was cancelled silently at poll.
func TestRotationMovesAPendingApprovalTargetToRekeyRequired(t *testing.T) {
	f := newProv(t)
	value := must(f.s.CreateTarget(f.admin(), TargetInput{Name: "local", Reason: "Enroll the synthetic host"}))
	token := value.(map[string]any)["enrollment"].(map[string]any)["token"].(string)
	h := newHost(f)
	resp := must(h.enroll(token))
	if _, err := f.s.RotateJobKey(f.dir, "Scheduled rotation"); err != nil {
		t.Fatal(err)
	}
	tg := must(f.s.TargetDetail("local"))
	if tg.State != "rekey_required" {
		t.Fatalf("after rotation the pending target is %s", tg.State)
	}
	_, err := f.s.ApproveTargetKey(f.admin(), resp.TargetID, KeyApprovalInput{HostKeyID: resp.HostKeyID, Reason: "The fingerprint matches the host console"})
	if errCode(err) != "no_pending_key" {
		t.Fatalf("approving a key bound to a retired job key: %v", err)
	}
	var audited int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='target.rekey.required' AND resource=?", "target:"+resp.TargetID).Scan(&audited)
	if audited != 1 {
		t.Fatalf("rekey audit rows %d", audited)
	}
	// Enrolling again with a new token binds the active key and works.
	value = must(f.s.IssueEnrollment(f.admin(), "local", ReasonInput{Reason: "Re-enroll after the rotation"}))
	token = value.(map[string]any)["enrollment"].(map[string]any)["token"].(string)
	h = newHost(f)
	resp = must(h.enroll(token))
	must(f.s.ApproveTargetKey(f.admin(), resp.TargetID, KeyApprovalInput{HostKeyID: resp.HostKeyID, Reason: "The fingerprint matches the host console"}))
	f.profile("dev", false)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	if jobs := h.poll(); len(jobs) != 1 || jobs[0].LaunchID != l.ID {
		t.Fatalf("the re-enrolled host gets its launch job: %d", len(jobs))
	}
}

// ApproveTargetKey refuses a target bound to a key that is not the active
// one, whatever its state says.
func TestApproveKeyRefusesATargetBoundToARetiredJobKey(t *testing.T) {
	f := newProv(t)
	value := must(f.s.CreateTarget(f.admin(), TargetInput{Name: "local", Reason: "Enroll the synthetic host"}))
	token := value.(map[string]any)["enrollment"].(map[string]any)["token"].(string)
	h := newHost(f)
	resp := must(h.enroll(token))
	if _, err := f.s.DB.Exec("UPDATE targets SET job_key_id=? WHERE id=?", "ed25519:"+"0123456789abcdef0123456789abcdef", resp.TargetID); err != nil {
		t.Fatal(err)
	}
	_, err := f.s.ApproveTargetKey(f.admin(), resp.TargetID, KeyApprovalInput{HostKeyID: resp.HostKeyID, Reason: "The fingerprint matches the host console"})
	if errCode(err) != "rekey_required" {
		t.Fatalf("%v", err)
	}
	if tg := must(f.s.TargetDetail("local")); tg.State != "awaiting_key_approval" {
		t.Fatalf("state %s", tg.State)
	}
}

// pollWork never cancels a job silently: a job signed with another key than
// the host enrolled with is cancelled with an audit row naming the reason, and
// the launch queued for it fails instead of waiting for its lifetime.
func TestPollAuditsEveryJobItCancels(t *testing.T) {
	f := newProv(t)
	h, tg := f.enrolledTarget()
	f.profile("dev", false)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	var raw string
	f.s.DB.QueryRow("SELECT envelope FROM jobs WHERE launch_id=? AND type='launch'", l.ID).Scan(&raw)
	var env hostproto.Envelope
	json.Unmarshal([]byte(raw), &env)
	env.KeyID = "ed25519:" + "fedcba9876543210fedcba9876543210"
	if _, err := f.s.DB.Exec("UPDATE jobs SET envelope=? WHERE launch_id=? AND type='launch'", jsonText(env), l.ID); err != nil {
		t.Fatal(err)
	}
	if jobs := h.poll(); len(jobs) != 0 {
		t.Fatalf("delivered %d jobs signed with another key", len(jobs))
	}
	var state string
	f.s.DB.QueryRow("SELECT state FROM jobs WHERE launch_id=? AND type='launch'", l.ID).Scan(&state)
	var audited int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='job.cancelled' AND run=? AND after_json LIKE '%job_key_mismatch%'", l.ID).Scan(&audited)
	if state != "cancelled" || audited != 1 {
		t.Fatalf("job %s, cancellation audit rows %d", state, audited)
	}
	if got := f.state(l.ID); got.State != StateFailed || got.EvidenceMissing != MissingNotStarted {
		t.Fatalf("launch %s %s on target %s", got.State, got.EvidenceMissing, tg.Name)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/pocpolicy"
	"alloyium.local/kernel-poc/internal/secretseal"
)

func TestLaunchEndToEndWithReceipt(t *testing.T) {
	f := newProv(t)
	h, target := f.enrolledTarget()
	if target.State != "active" || target.KernelVerified {
		t.Fatal("target not active or claims kernel verification")
	}
	f.profile("dev", false)
	l, plan := f.launch(f.launcher(), specMap("dev"))
	if l.State != StateQueued || plan.Approval != "auto" || plan.SpecDigest != l.SpecDigest || plan.PolicyDigest != l.PolicyDigest || plan.KernelVerified {
		t.Fatalf("unexpected launch %+v plan %+v", l, plan)
	}
	if l.ExpiresAt == "" || plan.Permissions.Network != "deny" {
		t.Fatal("plan lacks expiry or permissions")
	}
	jobs := h.poll()
	if len(jobs) != 1 || jobs[0].Type != hostproto.JobLaunch || jobs[0].LaunchID != l.ID {
		t.Fatalf("expected one launch job, got %+v", jobs)
	}
	var payload hostproto.LaunchPayload
	json.Unmarshal(jobs[0].Payload, &payload)
	doc, err := pocpolicy.Parse(payload.Policy)
	if err != nil || doc.Digest() != l.PolicyDigest || doc.Mode != "session" || doc.DurationSeconds != 3600 {
		t.Fatal("the launch policy does not carry the launch lifetime or digest", err)
	}
	if again := h.poll(); len(again) != 0 {
		t.Fatal("a delivered job was delivered again immediately")
	}
	job := jobs[0]
	e1 := ev(1, f, hostproto.EventState)
	e1.State = "running"
	e2 := ev(2, f, hostproto.EventLog)
	e2.Stream, e2.Message = "stdout", "tests pass"
	must(h.events(job.ID, e1, e2))
	if f.state(l.ID).State != StateRunning {
		t.Fatal("host running state not applied")
	}
	e3 := ev(3, f, hostproto.EventResult)
	e3.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "exited", Receipt: h.receipt(job, true)}
	resp := must(h.events(job.ID, e3))
	if !resp.Completed || resp.AcceptedThrough != 3 {
		t.Fatalf("result not acknowledged: %+v", resp)
	}
	final := f.state(l.ID)
	if final.State != StateStopped || len(final.Receipt) == 0 || final.KernelVerified {
		t.Fatalf("launch did not stop with its receipt: %+v", final)
	}
	logs := must(f.s.LaunchLogs(l.ID, 0, 10))
	if items := logs["items"].([]LogLine); len(items) != 1 || items[0].Text != "tests pass" {
		t.Fatal("log line missing")
	}
	events := must(f.s.LaunchEvents(l.ID, 0, 100))
	want := []string{StateRequested, StateApproved, StateQueued, StateProvisioning, StateRunning, StateStopping, StateStopped}
	got := []string{}
	for i, e := range events {
		if e.Seq != i+1 {
			t.Fatal("launch events are not contiguous")
		}
		if e.Kind == "state" {
			got = append(got, e.To)
		}
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("transitions %v", got)
	}
	var audited int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='launch.state.changed' AND run=? AND after_json LIKE ?", l.ID, "%"+l.PolicyDigest+"%").Scan(&audited)
	if audited != len(want)-1 {
		t.Fatalf("each transition must be audited with its digests: %d", audited)
	}
}

func TestEnrollmentTokenIsSingleUseExpiresAndNeedsKeyApproval(t *testing.T) {
	f := newProv(t)
	value := must(f.s.CreateTarget(f.admin(), TargetInput{Name: "local", Reason: "Enroll the synthetic host"}))
	token := value.(map[string]any)["enrollment"].(map[string]any)["token"].(string)
	var stored int
	f.s.DB.QueryRow("SELECT count(*) FROM enrollment_tokens WHERE token_hash=?", token).Scan(&stored)
	if stored != 0 {
		t.Fatal("the enrollment token is stored in clear")
	}
	var audit string
	f.s.DB.QueryRow("SELECT group_concat(after_json) FROM audit").Scan(&audit)
	if strings.Contains(audit, token) {
		t.Fatal("the enrollment token reached the audit log")
	}
	h := newHost(f)
	resp, err := h.enroll(token)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.s.HostPoll(h.pollRaw(), newID()); errCode(err) != "key_approval_pending" {
		t.Fatalf("an unapproved key polled: %v", err)
	}
	if _, err = newHost(f).enroll(token); errCode(err) != "invalid_token" {
		t.Fatalf("a used token enrolled again: %v", err)
	}
	if _, err = f.s.ApproveTargetKey(f.admin(), resp.TargetID, KeyApprovalInput{HostKeyID: "ed25519:" + strings.Repeat("0", 32), Reason: "Typed the wrong fingerprint"}); errCode(err) != "fingerprint_mismatch" {
		t.Fatalf("a mismatched fingerprint activated the host: %v", err)
	}
	if _, err = f.s.ApproveTargetKey(f.editor(), resp.TargetID, KeyApprovalInput{HostKeyID: resp.HostKeyID, Reason: "Editors cannot approve keys"}); errCode(err) != "forbidden" {
		t.Fatalf("a non-admin approved a key: %v", err)
	}
	must(f.s.ApproveTargetKey(f.admin(), resp.TargetID, KeyApprovalInput{HostKeyID: resp.HostKeyID, Reason: "The fingerprint matches the console"}))
	h.poll()
	value = must(f.s.IssueEnrollment(f.admin(), "local", ReasonInput{Reason: "Reinstall the host"}))
	later := value.(map[string]any)["enrollment"].(map[string]any)["token"].(string)
	f.advance(16 * time.Minute)
	if _, err = newHost(f).enroll(later); errCode(err) != "invalid_token" {
		t.Fatalf("an expired token enrolled: %v", err)
	}
	if _, err = newHost(f).enroll("agtenr_" + strings.Repeat("Z", 43)); errCode(err) != "invalid_token" {
		t.Fatal("an unknown token enrolled")
	}
}

func TestHostRequestsRejectReplayTamperStaleAndForeignKeys(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	raw := h.pollRaw()
	must(f.s.HostPoll(raw, newID()))
	if _, err := f.s.HostPoll(raw, newID()); errCode(err) != "replayed_request" {
		t.Fatalf("a replayed poll was accepted: %v", err)
	}
	h.seq = 0
	_, err := f.s.HostPoll(h.pollRaw(), newID())
	var hf *hostFailure
	if errCode(err) != "sequence_replayed" || !errorsAs(err, &hf) || hf.lastSequence != 1 {
		t.Fatalf("a lower sequence was accepted or lacked the resync hint: %v", err)
	}
	h.seq = 1
	env, _ := hostproto.DecodeEnvelope(h.pollRaw())
	payload, _ := b64.DecodeString(env.Payload)
	env.Payload = b64.EncodeToString([]byte(strings.Replace(string(payload), `"max_jobs":16`, `"max_jobs":15`, 1)))
	tampered, _ := json.Marshal(env)
	if _, err = f.s.HostPoll(tampered, newID()); errCode(err) != "invalid_signature" {
		t.Fatalf("a tampered poll was accepted: %v", err)
	}
	stranger := newHost(f)
	stranger.id, stranger.seq = h.id, 50
	if _, err = f.s.HostPoll(stranger.pollRaw(), newID()); errCode(err) != "invalid_signature" {
		t.Fatalf("a foreign key was accepted: %v", err)
	}
	f.advance(-2 * time.Minute)
	stale := h.pollRaw()
	f.advance(2 * time.Minute)
	if _, err = f.s.HostPoll(stale, newID()); errCode(err) != "stale_request" {
		t.Fatalf("a stale poll was accepted: %v", err)
	}
	unknown := newHost(f)
	unknown.id = newID()
	if _, err = f.s.HostPoll(unknown.pollRaw(), newID()); errCode(err) != "unknown_host" {
		t.Fatal("an unknown host polled")
	}
	// A gap is allowed; a signed resync recovers a lost counter.
	h.seq += 10
	h.poll()
	rs := hostproto.ResyncRequest{HostID: h.id, Nonce: nonce(), TimestampMS: f.now().UnixMilli(), Reason: "counter-lost"}
	resync := h.seal(hostproto.DomainResync, rs)
	must(f.s.HostResync(resync, newID()))
	if _, err = f.s.HostResync(resync, newID()); errCode(err) != "replayed_request" {
		t.Fatal("a replayed resync was accepted")
	}
	h.seq = 0
	h.poll()
	var denied int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action LIKE 'hostd.%denied' AND result='denied'").Scan(&denied)
	if denied < 5 {
		t.Fatalf("host denials were not audited: %d", denied)
	}
}

func errorsAs(err error, target **hostFailure) bool {
	for err != nil {
		if h, ok := err.(*hostFailure); ok {
			*target = h
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestApprovalRulesAndSelfApproval(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	f.profile("dev", false)
	f.profileFrom("web", "python-dev", false)
	f.profile("reviewed", true)
	m := specMap("web")
	l, plan := f.launch(f.launcher(), m)
	if l.State != StateApprovalPending || plan.Approval != "required" {
		t.Fatal("public web launched without approval")
	}
	m = specMap("reviewed")
	l2, _ := f.launch(f.launcher(), m)
	if l2.State != StateApprovalPending {
		t.Fatal("a profile requiring approval launched automatically")
	}
	m = specMap("dev")
	m["mounts"] = []any{map[string]any{"name": "repo", "source": "/srv/repos/app", "mode": "read-only"}}
	if _, err := f.s.CreateLaunch(f.launcher(), specBytes(t, m)); errCode(err) != "mount_root_not_allowed" {
		t.Fatalf("a mount outside the target's mount roots: %v", err)
	}
	f.mountRoots("local", "/srv/repos")
	l3, plan3 := f.launch(f.launcher(), m)
	if l3.State != StateApprovalPending || len(plan3.Mounts) != 1 {
		t.Fatal("a live mount launched without approval")
	}
	m["mounts"] = []any{map[string]any{"name": "repo", "source": "/srv/repos/app", "mode": "snapshot"}}
	l4, plan4 := f.launch(f.launcher(), m)
	if l4.State != StateApprovalPending || !hasReason(plan4, "snapshot of host folder repo (/srv/repos/app)") {
		t.Fatalf("a snapshot of a host folder launched without approval: %s %v", l4.State, plan4.ApprovalReasons)
	}
	m = specMap("dev")
	full, _ := access.FullExample()
	m["access"] = map[string]any{"inline": full}
	l5, _ := f.launch(f.launcher(), m)
	if l5.State != StateApprovalPending {
		t.Fatal("an inline document launched without approval")
	}
	launcher := f.launcher()
	if _, err := f.s.DecideLaunch(launcher, l.ID, true, DecisionInput{Reason: "Approve my own launch"}); errCode(err) != "forbidden" {
		t.Fatalf("a launcher approved: %v", err)
	}
	selfAdmin := f.admin()
	own, _ := f.launch(selfAdmin, specMap("web"))
	if _, err := f.s.DecideLaunch(f.admin(), own.ID, true, DecisionInput{Reason: "Approve my own launch"}); errCode(err) != "self_approval" {
		t.Fatalf("an admin approved their own launch: %v", err)
	}
	tok := f.token(f.admin(), "admin")
	resp, _ := f.apiRequest("POST", "/api/v1/launches/"+own.ID+"/approve", tok, []byte(`{"reason":"Approve with my token"}`))
	if resp.StatusCode != 403 {
		t.Fatalf("an API token of the requester approved: %d", resp.StatusCode)
	}
	if _, err := f.s.DecideLaunch(f.viewer(), l.ID, true, DecisionInput{Reason: "Viewers cannot approve"}); errCode(err) != "forbidden" {
		t.Fatal("a viewer approved")
	}
	approved := must(f.s.DecideLaunch(f.approver(), l.ID, true, DecisionInput{Reason: "Reviewed the plan"})).(launchRow)
	if approved.State != StateQueued || approved.DecidedBy != "oidc:app" || approved.ExpiresAt == "" {
		t.Fatalf("approval did not queue: %+v", approved.Launch)
	}
	if _, err := f.s.DecideLaunch(f.approver(), l.ID, true, DecisionInput{Reason: "Approve again"}); errCode(err) != "not_pending" {
		t.Fatal("a launch was approved twice")
	}
	rejected := must(f.s.DecideLaunch(f.approver(), l2.ID, false, DecisionInput{Reason: "Too broad"})).(launchRow)
	if rejected.State != StateRejected || rejected.EvidenceMissing != MissingNotStarted {
		t.Fatal("rejection lacks its evidence reason")
	}
	f.advance(25 * time.Hour)
	must(f.s.Sweep())
	if f.state(l3.ID).State != StateCancelled {
		t.Fatal("an approval timeout did not cancel the launch")
	}
}

func TestIllegalTransitionsAreImpossible(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	f.profile("dev", false)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	tx, _ := f.s.DB.Begin()
	row := must(launchFrom(tx, l.ID))
	for _, to := range []string{StateRunning, StateStopped, StateApproved, StateRequested, "bogus"} {
		if err := f.s.transitionLaunch(tx, &row, transition{To: to, Reason: "illegal"}); errCode(err) != "illegal_transition" {
			t.Fatalf("queued -> %s: %v", to, err)
		}
	}
	if err := f.s.transitionLaunch(tx, &row, transition{To: StateFailed, Reason: "no evidence"}); errCode(err) != "evidence_required" {
		t.Fatal("a terminal state was reached without evidence")
	}
	row.State = StateStopping
	if err := f.s.transitionLaunch(tx, &row, transition{To: StateStopped, Reason: "unconfirmed", EvidenceMissing: "x"}); errCode(err) != "cleanup_unconfirmed" {
		t.Fatal("stopped without a confirmed cleanup")
	}
	tx.Rollback()
	tx, _ = f.s.DB.Begin()
	row = must(launchFrom(tx, l.ID))
	stale := row
	if err := f.s.transitionLaunch(tx, &row, transition{To: StateFailed, Reason: "test", EvidenceMissing: "test"}); err != nil {
		t.Fatal(err)
	}
	stale.State = StateQueued
	if err := f.s.transitionLaunch(tx, &stale, transition{To: StateProvisioning, Reason: "stale"}); errCode(err) != "launch_changed" {
		t.Fatal("a stale revision changed the state")
	}
	tx.Commit()
	if _, err := f.s.DB.Exec("UPDATE launches SET state='running' WHERE id=?", l.ID); err == nil {
		t.Fatal("the database let a terminal launch change")
	}
	if _, err := f.s.DB.Exec("UPDATE launches SET policy_digest='x' WHERE id=?", l.ID); err == nil {
		t.Fatal("the database let a launch binding change")
	}
	if _, err := f.s.DB.Exec("DELETE FROM launch_events WHERE launch_id=?", l.ID); err == nil {
		t.Fatal("launch events are deletable")
	}
}

func TestStopIsIdempotentAndCancelsUndeliveredWork(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	f.profile("dev", false)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	stopped := must(f.s.StopLaunch(f.launcher(), l.ID, DecisionInput{Reason: "Changed my mind"})).(launchRow)
	if stopped.State != StateCancelled || stopped.EvidenceMissing != MissingNotStarted {
		t.Fatalf("an undelivered launch was not cancelled: %+v", stopped.Launch)
	}
	if len(h.poll()) != 0 {
		t.Fatal("a cancelled launch's job was delivered")
	}
	again := must(f.s.StopLaunch(f.launcher(), l.ID, DecisionInput{Reason: "Stop again"})).(launchRow)
	if again.State != StateCancelled || again.Revision != stopped.Revision {
		t.Fatal("a repeated stop changed the launch")
	}
	m := specMap("dev")
	m["name"] = "second"
	l2, _ := f.launch(f.launcher(), m)
	job := h.poll()[0]
	e := ev(1, f, hostproto.EventState)
	e.State = "running"
	must(h.events(job.ID, e))
	s1 := must(f.s.StopLaunch(f.launcher(), l2.ID, DecisionInput{Reason: "Done"})).(launchRow)
	s2 := must(f.s.StopLaunch(f.launcher(), l2.ID, DecisionInput{Reason: "Done again"})).(launchRow)
	if s1.State != StateStopping || s2.Revision != s1.Revision {
		t.Fatal("stop was not idempotent while stopping")
	}
	stops := h.poll()
	if len(stops) != 1 || stops[0].Type != hostproto.JobStop {
		t.Fatalf("expected exactly one stop job, got %d", len(stops))
	}
	r := ev(1, f, hostproto.EventResult)
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stopped", Receipt: h.receipt(stops[0], false)}
	must(h.events(stops[0].ID, r))
	if got := f.state(l2.ID); got.State != StateFailed || got.TerminalReason != "cleanup_incomplete" {
		t.Fatalf("an unconfirmed cleanup was marked stopped: %+v", got)
	}
	if retry := h.poll(); len(retry) != 1 || retry[0].Type != hostproto.JobStop {
		t.Fatal("an incomplete cleanup did not queue another stop")
	}
}

func TestHeartbeatLossFailsLaunchAndQueuesStop(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	f.profile("dev", false)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	job := h.poll()[0]
	e := ev(1, f, hostproto.EventState)
	e.State = "running"
	must(h.events(job.ID, e))
	f.advance(20 * time.Second)
	must(f.s.Sweep())
	if f.state(l.ID).State != StateRunning {
		t.Fatal("a live host was treated as lost")
	}
	f.advance(20 * time.Second)
	result := must(f.s.Sweep())
	got := f.state(l.ID)
	if result.LostHost != 1 || got.State != StateFailed || got.EvidenceMissing != MissingLostHost {
		t.Fatalf("heartbeat loss not applied: %+v %+v", result, got)
	}
	stops := h.poll(l.ID)
	if len(stops) != 1 || stops[0].Type != hostproto.JobStop {
		t.Fatal("the returning host did not receive the stop job")
	}
	r := ev(1, f, hostproto.EventResult)
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stopped", Receipt: h.receipt(stops[0], true)}
	must(h.events(stops[0].ID, r))
	if late := f.state(l.ID); late.State != StateFailed || len(late.Receipt) == 0 {
		t.Fatal("a late receipt was not attached to the failed launch")
	}
}

func TestLaunchExpiryStopsAtLifetime(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	f.profile("dev", false)
	m := specMap("dev")
	m["lifetime_seconds"] = 60
	l, _ := f.launch(f.launcher(), m)
	job := h.poll()[0]
	e := ev(1, f, hostproto.EventState)
	e.State = "running"
	must(h.events(job.ID, e))
	for i := 0; i < 7; i++ {
		f.advance(10 * time.Second)
		h.poll(l.ID)
	}
	must(f.s.Sweep())
	if f.state(l.ID).State != StateStopping {
		t.Fatal("an expired launch did not move to stopping")
	}
	stop := h.poll(l.ID)[0]
	r := ev(1, f, hostproto.EventResult)
	rec := h.receipt(stop, true)
	rec.Reason = "expired"
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "expired", Receipt: rec}
	must(h.events(stop.ID, r))
	if f.state(l.ID).State != StateExpired {
		t.Fatal("the launch did not end expired")
	}
}

func TestEventsAreOrderedIdempotentAndBounded(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	f.profile("dev", false)
	f.launch(f.launcher(), specMap("dev"))
	job := h.poll()[0]
	p := ev(1, f, hostproto.EventProgress)
	p.Message = "pulling"
	must(h.events(job.ID, p))
	must(h.events(job.ID, p))
	p.Message = "different"
	if _, err := h.events(job.ID, p); errCode(err) != "event_conflict" {
		t.Fatalf("a changed event was accepted: %v", err)
	}
	gap := ev(5, f, hostproto.EventProgress)
	if _, err := h.events(job.ID, gap); errCode(err) != "event_gap" {
		t.Fatal("a sequence gap was accepted")
	}
	big := ev(2, f, hostproto.EventProgress)
	big.Message = strings.Repeat("x", hostproto.MaxEventMessage+1)
	if _, err := h.events(job.ID, big); errCode(err) != "invalid_events" {
		t.Fatal("an oversize event was accepted")
	}
	claim := ev(2, f, hostproto.EventResult)
	rec := h.receipt(job, true)
	rec.KernelVerified = true
	claim.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "exited", Receipt: rec}
	if _, err := h.events(job.ID, claim); errCode(err) != "invalid_receipt" {
		t.Fatal("a receipt asserting kernel verification was accepted")
	}
	other := newID()
	if _, err := h.events(other); err == nil {
		t.Fatal("events for an unknown job were accepted")
	}
	raw := make([]byte, hostproto.MaxEnvelopeBytes+10)
	rand.Read(raw)
	if _, err := f.s.HostPoll(raw, newID()); err == nil {
		t.Fatal("an oversize envelope was accepted")
	}
}

func TestPolicyEditsNeverChangeALaunch(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	p := f.profile("dev", false)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	job := h.poll()[0]
	res := must(f.s.ApplyGrants(f.editor(), p.Name, "1", GrantInput{Edits: []access.Edit{{Action: "read", Values: []string{"/srv/data"}}}, Reason: "Widen the profile"})).(map[string]any)
	if res["changed"] != true || res["version"].(ProfileVersion).Number != 2 {
		t.Fatal("the grant did not create version two")
	}
	if got := f.state(l.ID); got.PolicyDigest != l.PolicyDigest {
		t.Fatal("a profile edit changed a launch")
	}
	if _, err := f.s.ApplyGrants(f.editor(), p.Name, "1", GrantInput{Edits: []access.Edit{{Action: "read", Values: []string{"/srv/x"}}}, Reason: "Stale parent"}); errCode(err) != "stale_parent" {
		t.Fatal("a grant applied to a stale version")
	}
	if _, err := f.s.ApplyGrants(f.editor(), p.Name, "2", GrantInput{Edits: []access.Edit{{Action: "exec", Values: []string{"/var/lib/agentgate/workspace/bin"}}}, Reason: "Writable and executable"}); errCode(err) != "grant_conflict" {
		t.Fatal("a writable tree became executable")
	}
	noop := must(f.s.ApplyGrants(f.editor(), p.Name, "2", GrantInput{Edits: []access.Edit{{Action: "read", Values: []string{"/srv/data"}}}, Reason: "Repeat the grant"})).(map[string]any)
	if noop["changed"] != false {
		t.Fatal("an idempotent grant created a version")
	}
	if _, err := f.s.ApplyGrants(f.launcher(), p.Name, "2", GrantInput{Edits: []access.Edit{{Action: "read", Values: []string{"/srv/y"}}}, Reason: "Launchers cannot edit"}); errCode(err) != "forbidden" {
		t.Fatal("a launcher edited a profile")
	}
	if _, err := f.s.DB.Exec("UPDATE profile_versions SET document='{}'"); err == nil {
		t.Fatal("a profile version is mutable")
	}
	var payload hostproto.LaunchPayload
	json.Unmarshal(job.Payload, &payload)
	if digest(payload.Policy) != l.PolicyDigest {
		t.Fatal("the delivered job policy differs from the launch")
	}
}

func TestConcurrentStateChangesStayConsistent(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	f.profile("reviewed", true)
	l, _ := f.launch(f.launcher(), specMap("reviewed"))
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	approver, launcher := f.approver(), f.launcher()
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := f.s.DecideLaunch(approver, l.ID, true, DecisionInput{Reason: "Concurrent approval"})
			errs <- err
		}()
		go func() {
			defer wg.Done()
			_, err := f.s.StopLaunch(launcher, l.ID, DecisionInput{Reason: "Concurrent stop"})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil && errCode(err) != "not_pending" {
			t.Fatalf("unexpected error %v", err)
		}
	}
	got := f.state(l.ID)
	if got.State != StateCancelled {
		t.Fatalf("final state %s", got.State)
	}
	events := must(f.s.LaunchEvents(l.ID, 0, 100))
	seen := map[string]int{}
	for i, e := range events {
		if e.Seq != i+1 {
			t.Fatal("events not contiguous")
		}
		seen[e.To]++
	}
	if seen[StateCancelled] != 1 || seen[StateApproved] > 1 {
		t.Fatalf("duplicate transitions %v", seen)
	}
	var jobs int
	f.s.DB.QueryRow("SELECT count(*) FROM jobs WHERE launch_id=? AND state IN ('queued','delivered')", l.ID).Scan(&jobs)
	if jobs != 0 {
		t.Fatal("a cancelled launch left live jobs")
	}
}

// sealFor is what a client does: fetch the published seal key, verify it
// against the host key fingerprint pinned out of band, and seal.
func (f *provFixture) sealFor(h *fakeHost, name, value string) *secretseal.Sealed {
	f.t.Helper()
	published := must(f.s.TargetSealKey("local"))
	rec, err := secretseal.ParseSignedKeyRecord(published["record"].(json.RawMessage))
	if err != nil {
		f.t.Fatal(err)
	}
	hostPub := h.key.Public().(ed25519.PublicKey)
	known, err := secretseal.LoadKnownTargets(filepath.Join(f.t.TempDir(), "known.json"))
	if err != nil {
		f.t.Fatal(err)
	}
	if err = known.Pin(h.id, secretseal.HostKeyFingerprint(hostPub)); err != nil {
		f.t.Fatal(err)
	}
	sealed, _, err := secretseal.SealForTarget(known, false, rec, hostPub, h.id, name, defaultPolicyDigest(), []byte(value), f.now())
	if err != nil {
		f.t.Fatal(err)
	}
	return sealed
}

func secretInput(name string, sealed *secretseal.Sealed, profile string) SecretInput {
	in := SecretInput{Name: name, Target: "local", Upstreams: []string{"api.model.example"}, Header: "x-api-key",
		Rules:           []SecretRuleInput{{Methods: []string{"POST"}, Path: "/v1/messages", Match: "exact"}, {Methods: []string{"GET"}, Path: "/v1/models", Match: "prefix"}},
		AllowedProfiles: []string{profile}, AllowedLaunchers: []string{"oidc:lin"}, Reason: "Store the model API key"}
	if sealed != nil {
		in.Ciphertext = sealed.Envelope.Encode()
	}
	return in
}

// inputPolicyDigest is what a client computes before it seals: the digest of
// the injection policy the settings of in make (the wildcard rule expanded,
// as the service stores it).
func inputPolicyDigest(t testing.TB, in SecretInput) string {
	t.Helper()
	digest, err := policyDigestOf(in)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func policyDigestOf(in SecretInput) (string, error) {
	rules := []hostproto.BrokerRule{}
	wild := len(in.Rules) == 1 && len(in.Rules[0].Methods) == 1 && in.Rules[0].Methods[0] == "*"
	if wild {
		rules = append(rules, hostproto.BrokerRule{Methods: hostproto.BrokerMethods, Path: "/", Match: "prefix"})
	}
	for _, r := range in.Rules {
		if !wild {
			rules = append(rules, hostproto.BrokerRule{Methods: r.Methods, Path: r.Path, Match: r.Match})
		}
	}
	p, err := hostproto.NewSecretPolicy(in.Upstreams, in.Header, in.Scheme, in.Username, rules, in.ExtraHeaders, in.ForwardHeaders, wild)
	return p.Digest(), err
}

// defaultPolicyDigest is the policy of secretInput's settings.
func defaultPolicyDigest() string {
	digest, err := policyDigestOf(secretInput("x", nil, "dev"))
	if err != nil {
		panic(err)
	}
	return digest
}

// sealInput seals value for in's name, target and settings and returns in
// with the envelope, as a client does once the operator chose the settings.
func (f *provFixture) sealInput(h *fakeHost, in SecretInput, value string) SecretInput {
	f.t.Helper()
	published := must(f.s.TargetSealKey(in.Target))
	rec := must(secretseal.ParseSignedKeyRecord(published["record"].(json.RawMessage)))
	pub := h.key.Public().(ed25519.PublicKey)
	known := must(secretseal.LoadKnownTargets(filepath.Join(f.t.TempDir(), "known.json")))
	if err := known.Pin(h.id, secretseal.HostKeyFingerprint(pub)); err != nil {
		f.t.Fatal(err)
	}
	sealed, _, err := secretseal.SealForTarget(known, false, rec, pub, h.id, in.Name, inputPolicyDigest(f.t, in), []byte(value), f.now())
	if err != nil {
		f.t.Fatal(err)
	}
	in.Ciphertext = sealed.Envelope.Encode()
	return in
}

// hostStore opens a host-side secretseal store for the fake host.
func (h *fakeHost) hostStore() *secretseal.Store {
	h.f.t.Helper()
	dir := filepath.Join(h.f.t.TempDir(), "secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		h.f.t.Fatal(err)
	}
	store, err := secretseal.OpenStore(dir)
	if err != nil {
		h.f.t.Fatal(err)
	}
	return store
}

func TestSecretsKeepOnlyMetadataAndAreScoped(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	p := f.profile("dev", false)
	if _, err := f.s.TargetSealKey("local"); errCode(err) != "seal_key_unavailable" {
		t.Fatalf("a seal key was served before the host published one: %v", err)
	}
	h.poll() // the heartbeat publishes the signed seal key
	value := "synthetic-credential-value-0123456789"
	sealed := f.sealFor(h, "model-api", value)
	in := secretInput("model-api", sealed, p.Name)
	if _, err := f.s.CreateSecret(f.editor(), in); errCode(err) != "forbidden" {
		t.Fatal("a non-admin stored a secret")
	}
	sec := must(f.s.CreateSecret(f.admin(), in)).(Secret)
	if sec.Envelope == nil || sec.Envelope.Version != sealed.Envelope.Version || sec.Envelope.KeyID != sealed.Envelope.KeyID || len(sec.Rules) != 2 || sec.Wildcard {
		t.Fatalf("secret metadata %+v", sec)
	}
	put := h.poll()[0]
	var payload hostproto.SecretPutPayload
	json.Unmarshal(put.Payload, &payload)
	if payload.Ciphertext != in.Ciphertext {
		t.Fatal("the relayed envelope differs from the client's")
	}
	env, err := secretseal.DecodeEnvelope(payload.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	store := h.hostStore()
	receipt, err := store.Accept(h.sealKey, env, f.now())
	if err != nil {
		t.Fatalf("the host could not open its sealed secret: %v", err)
	}
	if _, ok, _ := store.Stored("model-api"); !ok {
		t.Fatal("the value was not stored")
	}
	if _, err := f.s.SecretReceipt(sec.ID); errCode(err) != "receipt_unavailable" {
		t.Fatal("a receipt was served before the host returned one")
	}
	r := ev(1, f, hostproto.EventResult)
	hr := hostproto.SecretReceipt(*receipt)
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stored", SecretReceipt: &hr}
	must(h.events(put.ID, r))
	relayed := must(f.s.SecretReceipt(sec.ID))
	got, err := secretseal.ParseReceipt(relayed["receipt"].(json.RawMessage))
	if err != nil {
		t.Fatal(err)
	}
	if fp, err := sealed.VerifyReceipt(got); err != nil || fp != relayed["value_fingerprint"] {
		t.Fatalf("the client could not verify the relayed receipt: %v", err)
	}
	var envelope string
	f.s.DB.QueryRow("SELECT envelope FROM jobs WHERE id=?", put.ID).Scan(&envelope)
	if envelope != "" {
		t.Fatal("the ciphertext outlived its delivery")
	}
	dump := ""
	for _, table := range []string{"audit", "jobs", "secrets", "idempotency", "job_events", "targets"} {
		rows, _ := f.s.DB.Query("SELECT * FROM " + table)
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			rows.Scan(ptrs...)
			dump += jsonText(vals)
		}
		rows.Close()
	}
	if strings.Contains(dump, value) || strings.Contains(dump, payload.Ciphertext) || strings.Contains(dump, sealed.Envelope.Sealed) {
		t.Fatal("a secret value or its ciphertext persisted")
	}
	m := specMap("dev")
	m["secrets"] = []any{map[string]any{"ref": "model-api", "expose": map[string]any{"env": "MODEL_API_BASE_URL"}}}
	l, plan := f.launch(f.launcher(), m)
	if l.State != StateApprovalPending || len(plan.Secrets) != 1 || plan.Secrets[0].SecretID != sec.ID || plan.Broker == nil ||
		plan.Secrets[0].BaseURL != "http://"+plan.Broker.Address+":8443/model-api" || len(plan.Secrets[0].Rules) != 2 {
		t.Fatalf("a brokered secret launched without approval or lost its binding: %+v", plan)
	}
	if plan.Permissions.Broker != plan.Broker.Address+":8443" || plan.Permissions.Taskboard != "" {
		t.Fatalf("permissions %+v", plan.Permissions)
	}
	if _, err = f.s.CreateLaunch(f.human("oidc:other", "launchers"), specBytes(t, m)); errCode(err) != "secret_scope" {
		t.Fatalf("a launcher outside the secret scope referenced it: %v", err)
	}
	other := f.profile("other", false)
	m["access"] = map[string]any{"profile": other.Name, "version": 1}
	if _, err = f.s.CreateLaunch(f.launcher(), specBytes(t, m)); errCode(err) != "secret_scope" {
		t.Fatal("a profile outside the secret scope referenced it")
	}
	if _, err = f.s.DeleteSecret(f.admin(), sec.ID, ReasonInput{Reason: "Rotate"}); errCode(err) != "secret_in_use" {
		t.Fatal("a secret used by a live launch was deleted")
	}
}

func TestAPITokensAreScopedHashedAndRevocable(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	launcher := f.launcher()
	if _, err := f.s.CreateAPIToken(launcher, APITokenInput{Name: "cli", Roles: []string{"admin"}, ExpiresInSeconds: 86400, Reason: "Escalate"}); errCode(err) != "role_not_held" {
		t.Fatal("a token carried a role its holder lacks")
	}
	tok := f.token(launcher, "launcher")
	var clear int
	f.s.DB.QueryRow("SELECT count(*) FROM api_tokens WHERE token_hash=? OR actor LIKE ?", tok, "%"+tok+"%").Scan(&clear)
	if clear != 0 {
		t.Fatal("the token is stored in clear")
	}
	resp, body := f.apiRequest("GET", "/api/v1/launches", tok, nil)
	if resp.StatusCode != 200 || body["items"] == nil {
		t.Fatalf("token read failed: %d %v", resp.StatusCode, body)
	}
	if resp, _ = f.apiRequest("GET", "/api/v1/users", tok, nil); resp.StatusCode != 403 {
		t.Fatalf("a token reached user administration: %d", resp.StatusCode)
	}
	if resp, _ = f.apiRequest("POST", "/api/v1/api-tokens", tok, []byte(`{"name":"x","roles":["launcher"],"expires_in_seconds":3600,"reason":"Mint from a token"}`)); resp.StatusCode != 403 {
		t.Fatalf("a token minted a token: %d", resp.StatusCode)
	}
	if resp, _ = f.apiRequest("POST", "/api/v1/targets", tok, []byte(`{"name":"x","reason":"Launchers cannot add targets"}`)); resp.StatusCode != 403 {
		t.Fatal("a launcher token created a target")
	}
	if resp, _ = f.apiRequest("GET", "/api/v1/launches", "agt_"+strings.Repeat("A", 43), nil); resp.StatusCode != 401 {
		t.Fatal("an unknown token was accepted")
	}
	list := must(f.s.APITokens(launcher.Actor))
	must(f.s.RevokeAPIToken(f.launcher(), list[0].ID, ReasonInput{Reason: "Lost laptop"}))
	if resp, _ = f.apiRequest("GET", "/api/v1/launches", tok, nil); resp.StatusCode != 401 {
		t.Fatal("a revoked token was accepted")
	}
	tok2 := f.token(f.launcher(), "launcher")
	f.advance(25 * time.Hour)
	if resp, _ = f.apiRequest("GET", "/api/v1/launches", tok2, nil); resp.StatusCode != 401 {
		t.Fatal("an expired token was accepted")
	}
}

func TestHTTPLaunchFlowWithTokenAndHostEndpoints(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	f.profile("dev", false)
	tok := f.token(f.launcher(), "launcher")
	resp, body := f.apiRequest("GET", "/api/v1/launch-spec-schema", tok, nil)
	if resp.StatusCode != 200 || body["title"] != "agentgate.launch.v1" {
		t.Fatal("schema endpoint failed")
	}
	resp, body = f.apiRequest("POST", "/api/v1/launch-plans", tok, specBytes(t, specMap("dev")))
	if resp.StatusCode != 200 || body["dry_run"] != true {
		t.Fatalf("plan failed: %d %v", resp.StatusCode, body)
	}
	var count int
	f.s.DB.QueryRow("SELECT count(*) FROM launches").Scan(&count)
	if count != 0 {
		t.Fatal("a dry run created a launch")
	}
	resp, body = f.apiRequest("POST", "/api/v1/launches", tok, specBytes(t, specMap("dev")))
	if resp.StatusCode != 200 {
		t.Fatalf("launch failed: %d %v", resp.StatusCode, body)
	}
	id := body["launch"].(map[string]any)["id"].(string)
	raw := h.pollRaw()
	r, err := httpPost(f, "/api/v1/hostd/poll", raw)
	if err != nil || r["jobs"] == nil || len(r["jobs"].([]any)) != 1 {
		t.Fatalf("HTTP poll failed: %v %v", r, err)
	}
	r, _ = httpPost(f, "/api/v1/hostd/poll", raw)
	if r["error"].(map[string]any)["code"] != "replayed_request" || r["last_accepted_sequence"] == nil {
		t.Fatalf("HTTP replay response %v", r)
	}
	resp, body = f.apiRequest("GET", "/api/v1/launches/"+id+"/events", tok, nil)
	if resp.StatusCode != 200 || len(body["items"].([]any)) < 3 {
		t.Fatal("events listing failed")
	}
	resp, _ = f.apiRequest("POST", "/api/v1/launches/"+id+"/stop", tok, []byte(`{"reason":"Stop over HTTP"}`))
	if resp.StatusCode != 200 || f.state(id).State != StateStopping {
		t.Fatal("HTTP stop failed")
	}
	resp, body = f.apiRequest("GET", "/api/v1/openapi.json", tok, nil)
	paths := body["paths"].(map[string]any)
	for _, p := range []string{"/api/v1/launches", "/api/v1/hostd/poll", "/api/v1/profiles/{id}/versions/{n}/grants", "/api/v1/targets/{id}/approve-key"} {
		if paths[p] == nil {
			t.Fatalf("OpenAPI lacks %s", p)
		}
	}
}

func httpPost(f *provFixture, path string, body []byte) (map[string]any, error) {
	resp, err := f.http.Client().Post(f.http.URL+path, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out map[string]any
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

func TestRolesAndScopes(t *testing.T) {
	cases := []struct {
		role, scope string
		ok          bool
	}{
		{"launcher", "launch:write", true}, {"launcher", "launch:approve", false}, {"launcher", "policy:write", false},
		{"approver", "launch:approve", true}, {"approver", "launch:write", false},
		{"editor", "policy:write", true}, {"editor", "launch:write", false}, {"editor", "profiles:admin", false},
		{"viewer", "launch:read", true}, {"viewer", "secrets:admin", false}, {"viewer", "targets:admin", false},
		{"admin", "secrets:admin", true}, {"admin", "targets:admin", true},
	}
	for _, c := range cases {
		if (Actor{Kind: "human", Roles: []string{c.role}}).Can(c.scope) != c.ok {
			t.Fatalf("%s %s", c.role, c.scope)
		}
	}
	if err := validLocalUser(UserInput{Username: "lina", Name: "Lina", Roles: []string{"launcher"}, Reason: "Add a launcher"}); err != nil {
		t.Fatal("launcher is not a valid local role")
	}
}

func TestMigrationIsIdempotentOnAnExistingDatabase(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	f.profile("dev", false)
	f.s.DB.Exec("PRAGMA user_version=4")
	f.http.Close()
	f.s.DB.Close()
	s, err := OpenStore(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	var version, targets, migrations int
	s.DB.QueryRow("PRAGMA user_version").Scan(&version)
	s.DB.QueryRow("SELECT count(*) FROM targets").Scan(&targets)
	s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='schema.migrated' AND request_id='migration-5'").Scan(&migrations)
	if version != SchemaVersion || targets != 1 || migrations != 2 {
		t.Fatalf("version %d targets %d migrations %d", version, targets, migrations)
	}
	s.DB.Close()
	s, err = OpenStore(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	s.DB.QueryRow("SELECT count(*) FROM audit WHERE request_id='migration-5'").Scan(&migrations)
	if migrations != 2 {
		t.Fatal("a current database migrated again")
	}
}

func TestJobKeyRotationRequiresReenrollment(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	old := f.s.JobKeyID()
	if info, err := os.Stat(filepath.Join(f.dir, JobKeyFile)); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("job key file missing or not private")
	}
	f.profile("dev", false)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	if _, err := f.s.RotateJobKey(f.dir, "Rotate the job key"); errCode(err) != "launches_active" {
		t.Fatal("rotation ran with a live launch")
	}
	must(f.s.StopLaunch(f.launcher(), l.ID, DecisionInput{Reason: "Stop before rotating"}))
	must(f.s.RotateJobKey(f.dir, "Rotate the job key"))
	if f.s.JobKeyID() == old {
		t.Fatal("the key did not change")
	}
	if _, err := f.s.HostPoll(h.pollRaw(), newID()); errCode(err) != "rekey_required" {
		t.Fatal("a host enrolled with the old key still polls")
	}
	if _, err := f.s.CreateLaunch(f.launcher(), specBytes(t, specMap("dev"))); errCode(err) != "target_unavailable" {
		t.Fatal("a launch was queued for a host that cannot verify it")
	}
}

func TestLaunchSpecValidation(t *testing.T) {
	good := specMap("dev")
	if _, _, _, err := ValidateLaunchSpec(specBytes(t, good)); err != nil {
		t.Fatal(err)
	}
	mutate := map[string]func(m map[string]any){
		"name":          func(m map[string]any) { m["name"] = "Repo_Fixer" },
		"long name":     func(m map[string]any) { m["name"] = strings.Repeat("a", 41) },
		"mode":          func(m map[string]any) { m["mode"] = "daemon" },
		"session short": func(m map[string]any) { m["lifetime_seconds"] = 59 },
		"session long":  func(m map[string]any) { m["lifetime_seconds"] = 86401 },
		"oneshot long":  func(m map[string]any) { m["mode"] = "oneshot"; m["lifetime_seconds"] = 3601 },
		"oneshot zero":  func(m map[string]any) { m["mode"] = "oneshot"; m["lifetime_seconds"] = 0 },
		"tag image":     func(m map[string]any) { m["agent"].(map[string]any)["image"] = "agentgate-coding:latest" },
		"secret env":    func(m map[string]any) { m["agent"].(map[string]any)["env"] = map[string]string{"OPENAI_API_KEY": "x"} },
		"token env":     func(m map[string]any) { m["agent"].(map[string]any)["env"] = map[string]string{"GH_TOKEN": "x"} },
		"password env": func(m map[string]any) {
			m["agent"].(map[string]any)["env"] = map[string]string{"DB_PASSWORD_FILE": "x"}
		},
		"preload env":   func(m map[string]any) { m["agent"].(map[string]any)["env"] = map[string]string{"LD_PRELOAD": "/x.so"} },
		"workdir":       func(m map[string]any) { m["agent"].(map[string]any)["workdir"] = "/etc" },
		"both access":   func(m map[string]any) { m["access"].(map[string]any)["inline"] = map[string]any{} },
		"no version":    func(m map[string]any) { delete(m["access"].(map[string]any), "version") },
		"approval":      func(m map[string]any) { m["approval"] = "skip" },
		"unknown field": func(m map[string]any) { m["privileged"] = true },
		"secret value": func(m map[string]any) {
			m["secrets"] = []any{map[string]any{"ref": "k", "value": "v", "expose": map[string]any{"env": "K_URL"}}}
		},
		"protected mount": func(m map[string]any) {
			m["mounts"] = []any{map[string]any{"name": "etc", "source": "/etc", "mode": "read-only"}}
		},
		"ssh mount": func(m map[string]any) {
			m["mounts"] = []any{map[string]any{"name": "s", "source": "/home/a/.ssh", "mode": "read-only"}}
		},
		"home mount": func(m map[string]any) {
			m["mounts"] = []any{map[string]any{"name": "h", "source": "/home/a", "mode": "snapshot"}}
		},
		"mount mode": func(m map[string]any) {
			m["mounts"] = []any{map[string]any{"name": "r", "source": "/srv/r", "mode": "exec"}}
		},
		"overlapping mount": func(m map[string]any) {
			m["mounts"] = []any{map[string]any{"name": "a", "source": "/srv/r", "mode": "snapshot"}, map[string]any{"name": "b", "source": "/srv/r/x", "mode": "snapshot"}}
		},
		"dup secret env": func(m map[string]any) {
			m["secrets"] = []any{map[string]any{"ref": "k", "expose": map[string]any{"env": "EDITOR"}}}
		},
		"version": func(m map[string]any) { m["version"] = "agentgate.launch.v2" },
	}
	for name, fn := range mutate {
		raw, _ := json.Marshal(good)
		var m map[string]any
		json.Unmarshal(raw, &m)
		fn(m)
		if _, _, _, err := ValidateLaunchSpec(specBytes(t, m)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	for _, raw := range []string{`{"version":"agentgate.launch.v1","version":"agentgate.launch.v1"}`, strings.Repeat(" ", MaxLaunchSpecBytes+1), `{} {}`} {
		if _, _, _, err := ValidateLaunchSpec([]byte(raw)); err == nil {
			t.Fatalf("accepted %.40q", raw)
		}
	}
	a, _, d1, _ := ValidateLaunchSpec(specBytes(t, good))
	reordered := []byte(`{"approval":"auto","secrets":[],"mounts":[],"access":{"version":1,"profile":"dev"},"agent":{"workdir":"/var/lib/agentgate/workspace","env":{"EDITOR":"vi"},"command":["agent","--print","fix the failing tests"],"image":"` + a.Agent.Image + `"},"lifetime_seconds":3600,"mode":"session","target":"local","name":"repo-fixer","version":"agentgate.launch.v1"}`)
	if _, _, d2, err := ValidateLaunchSpec(reordered); err != nil || d1 != d2 {
		t.Fatal("the canonical digest depends on key order", err)
	}
}

// TestAuditCatalogCoversEmittedActions scans the provisioning sources for
// audit action names and requires each one in AuditCatalog.
func TestAuditCatalogCoversEmittedActions(t *testing.T) {
	known := map[string]bool{}
	for _, a := range AuditCatalog {
		known[a.Action] = true
	}
	files, _ := filepath.Glob("prov_*.go")
	files = append(files, "store.go")
	pattern := regexp.MustCompile(`(?:Action: |op\.Action, [^=]*= |op\.Action = )"([a-z][a-z.]+[a-z])"`)
	found := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		raw, _ := os.ReadFile(name)
		for _, m := range pattern.FindAllStringSubmatch(string(raw), -1) {
			found++
			action := strings.TrimSuffix(m[1], ".denied")
			if !known[action] && !known[m[1]] {
				t.Fatalf("%s emits %q, which is missing from AuditCatalog", name, m[1])
			}
		}
	}
	if found < 20 {
		t.Fatalf("the scan found only %d actions", found)
	}
}

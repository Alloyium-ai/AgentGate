// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/secretseal"
)

// keepingHost is a fake host that keeps its secret store across jobs, so a
// test can see a value stored and then removed.
type keepingHost struct {
	*fakeHost
	dir   string
	store *secretseal.Store
}

func keeping(t *testing.T, h *fakeHost) *keepingHost {
	dir := filepath.Join(t.TempDir(), "secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := secretseal.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return &keepingHost{fakeHost: h, dir: dir, store: store}
}

// store creates a secret and has the host accept it.
func (k *keepingHost) storeSecret(f *provFixture, name string) Secret {
	f.t.Helper()
	in := secretInput(name, f.sealTo(k.fakeHost, "local", name, "synthetic-credential-0123456789"), "dev")
	sec := must(f.s.CreateSecret(f.admin(), in)).(Secret)
	put := k.poll()[0]
	var payload hostproto.SecretPutPayload
	json.Unmarshal(put.Payload, &payload)
	env, err := secretseal.DecodeEnvelope(payload.Ciphertext)
	if err != nil {
		f.t.Fatal(err)
	}
	receipt, err := k.store.Accept(k.sealKey, env, f.now())
	if err != nil {
		f.t.Fatal(err)
	}
	r := ev(1, f, hostproto.EventResult)
	hr := hostproto.SecretReceipt(*receipt)
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stored", SecretReceipt: &hr}
	must(k.events(put.ID, r))
	return must(scanSecret(f.s.DB.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", sec.ID)))
}

// answerDeletes polls once and answers every secret-delete job: removed when
// ok, failed otherwise. It returns the job types it received.
func (k *keepingHost) answerDeletes(f *provFixture, ok bool) []string {
	f.t.Helper()
	types := []string{}
	for _, job := range k.poll() {
		types = append(types, job.Type)
		if job.Type != hostproto.JobSecretDelete {
			continue
		}
		var p hostproto.SecretDeletePayload
		json.Unmarshal(job.Payload, &p)
		r := ev(1, f, hostproto.EventResult)
		if ok {
			if err := k.store.Delete(p.Name, f.now()); err != nil {
				f.t.Fatal(err)
			}
			r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "deleted"}
		} else {
			r.Result = &hostproto.JobResult{Status: hostproto.ResultFailed, Reason: "store_unavailable"}
		}
		must(k.events(job.ID, r))
	}
	return types
}

func committedCount(f *provFixture, action string) int {
	var n int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action=? AND result='committed'", action).Scan(&n)
	return n
}

func secretState(f *provFixture, id string) Secret {
	return must(scanSecret(f.s.DB.QueryRow("SELECT "+secretColumns+" FROM secrets WHERE id=?", id)))
}

func deleteJobs(f *provFixture, secretID string) int {
	var n int
	f.s.DB.QueryRow("SELECT count(*) FROM jobs WHERE secret_id=? AND type='secret-delete'", secretID).Scan(&n)
	return n
}

func TestRetiringATargetRemovesItsSecretsFromTheHostFirst(t *testing.T) {
	f := newProv(t)
	base, target := f.enrolledTarget()
	base.poll()
	h := keeping(t, base)
	f.profile("dev", false)
	model := h.storeSecret(f, "model-api")
	if _, ok, err := h.store.Stored("model-api"); err != nil || !ok {
		t.Fatal("the host does not hold the value")
	}
	// A secret whose secret-put never reached the host has nothing to remove.
	late := must(f.s.CreateSecret(f.admin(), secretInput("late-key", f.sealTo(base, "local", "late-key", "synthetic-credential-0123456789"), "dev"))).(Secret)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	if _, err := f.s.RetireTarget(f.admin(), "local", TargetRetireInput{Reason: "Decommission the host"}); errCode(err) != "launches_active" {
		t.Fatalf("retired with a live launch: %v", err)
	}
	if _, err := f.s.RetireTarget(f.admin(), "local", TargetRetireInput{Reason: "Decommission the host", Force: true}); errCode(err) != "launches_active" {
		t.Fatal("force retired a target with a live launch")
	}
	must(f.s.StopLaunch(f.launcher(), l.ID, DecisionInput{Reason: "Not needed"}))
	newKey := secretInput("new-key", f.sealTo(base, "local", "new-key", "synthetic-credential-0123456789"), "dev")

	got := must(f.s.RetireTarget(f.admin(), "local", TargetRetireInput{Reason: "Decommission the host"})).(Target)
	if got.State != TargetRetiring || got.RetiringSince == "" {
		t.Fatalf("target %s %q", got.State, got.RetiringSince)
	}
	if s := secretState(f, model.ID); s.State != "deleting" || deleteJobs(f, model.ID) != 1 {
		t.Fatalf("model-api %s with %d delete jobs", s.State, deleteJobs(f, model.ID))
	}
	if s := secretState(f, late.ID); s.State != "deleted" || deleteJobs(f, late.ID) != 0 {
		t.Fatalf("a never delivered secret is %s with %d delete jobs", s.State, deleteJobs(f, late.ID))
	}
	if committedCount(f, "target.retirement.started") != 1 || committedCount(f, "target.retired") != 0 {
		t.Fatal("the retirement start was not audited as such")
	}
	// Retiring again changes nothing and queues nothing more.
	again := must(f.s.RetireTarget(f.admin(), target.ID, TargetRetireInput{Reason: "Again"})).(Target)
	if again.State != TargetRetiring || deleteJobs(f, model.ID) != 1 {
		t.Fatal("a repeated retirement was not idempotent")
	}
	// Nothing new can use a retiring target.
	if _, err := f.s.CreateLaunch(f.launcher(), specBytes(t, specMap("dev"))); errCode(err) != "target_unavailable" {
		t.Fatalf("a launch on a retiring target: %v", err)
	}
	if _, err := f.s.CreateSecret(f.admin(), newKey); errCode(err) != "target_unavailable" {
		t.Fatal("a secret was stored on a retiring target")
	}
	for name, fn := range map[string]func() error{
		"enrollment": func() error {
			_, err := f.s.IssueEnrollment(f.admin(), "local", ReasonInput{Reason: "Reinstall"})
			return err
		},
		"rename": func() error {
			_, err := f.s.RenameTarget(f.admin(), "local", TargetInput{Name: "elsewhere", Reason: "Rename"})
			return err
		},
		"seal key": func() error { _, err := f.s.TargetSealKey("local"); return err },
	} {
		if err := fn(); err == nil {
			t.Fatalf("%s on a retiring target", name)
		}
	}
	// The host polls, gets only the removal, removes the value and confirms.
	if types := h.answerDeletes(f, true); len(types) != 1 || types[0] != hostproto.JobSecretDelete {
		t.Fatalf("a retiring host received %v", types)
	}
	if _, ok, err := h.store.Stored("model-api"); err != nil || ok {
		t.Fatal("the value is still on the host")
	}
	if s := secretState(f, model.ID); s.State != "deleted" || s.Removal != "" {
		t.Fatalf("model-api %s %q", s.State, s.Removal)
	}
	done := must(f.s.TargetDetail(target.ID))
	if done.State != "retired" || committedCount(f, "secret.deleted") != 1 || committedCount(f, "target.retired") != 1 {
		t.Fatalf("target %s after the last confirmation", done.State)
	}
	var actor string
	f.s.DB.QueryRow("SELECT actor FROM audit WHERE action='target.retired' AND result='committed'").Scan(&actor)
	if actor != "target:"+target.ID {
		t.Fatalf("the retirement was attributed to %q", actor)
	}
	if _, err := h.f.s.HostPoll(h.pollRaw(), newID()); errCode(err) != "unknown_host" {
		t.Fatalf("a retired host can still poll: %v", err)
	}
}

func TestARetiringHostThatFailsRemovalsIsRetriedThenForced(t *testing.T) {
	f := newProv(t)
	base, target := f.enrolledTarget()
	base.poll()
	h := keeping(t, base)
	f.profile("dev", false)
	sec := h.storeSecret(f, "model-api")
	must(f.s.RetireTarget(f.admin(), "local", TargetRetireInput{Reason: "Decommission the host"}))
	for i := 0; i < maxSecretDeleteAttempts+2; i++ {
		h.answerDeletes(f, false)
	}
	if s := secretState(f, sec.ID); s.State != "deleting" || deleteJobs(f, sec.ID) != maxSecretDeleteAttempts {
		t.Fatalf("after failed removals: %s with %d jobs", s.State, deleteJobs(f, sec.ID))
	}
	if must(f.s.TargetDetail(target.ID)).State != TargetRetiring {
		t.Fatal("a failed removal retired the target")
	}
	var failed int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='secret.deletion.failed' AND result='denied'").Scan(&failed)
	if failed != maxSecretDeleteAttempts {
		t.Fatalf("%d failed removals audited", failed)
	}
	done := must(f.s.RetireTarget(f.admin(), "local", TargetRetireInput{Reason: "The host is gone", Force: true})).(Target)
	if done.State != "retired" {
		t.Fatalf("force left the target %s", done.State)
	}
	if s := secretState(f, sec.ID); s.State != "deleted" || s.Removal != "unconfirmed" {
		t.Fatalf("a forced secret is %s %q", s.State, s.Removal)
	}
	if auditCount(f, "secret.removal.unconfirmed") != 1 {
		t.Fatal("the unconfirmed removal was not audited")
	}
	// The listing says the value may remain on the host.
	for _, s := range must(f.s.Secrets()) {
		if s.ID == sec.ID && s.Removal != "unconfirmed" {
			t.Fatal("the secret list hides the unconfirmed removal")
		}
	}
}

func TestReenrollingATargetRemovesTheOldSecretsAndAHostThatCannotPollNeedsForce(t *testing.T) {
	f := newProv(t)
	base, target := f.enrolledTarget()
	base.poll()
	h := keeping(t, base)
	f.profile("dev", false)
	sec := h.storeSecret(f, "model-api")
	token := must(f.s.IssueEnrollment(f.admin(), "local", ReasonInput{Reason: "Reinstall the host"})).(map[string]any)["enrollment"].(map[string]any)["token"].(string)
	if s := secretState(f, sec.ID); s.State != "stored" {
		t.Fatal("issuing a token alone removed a secret")
	}
	next := newHost(f)
	resp := must(next.enroll(token))
	if s := secretState(f, sec.ID); s.State != "deleting" || deleteJobs(f, sec.ID) != 1 {
		t.Fatalf("after re-enrollment: %s with %d jobs", s.State, deleteJobs(f, sec.ID))
	}
	var by string
	f.s.DB.QueryRow("SELECT actor FROM audit WHERE action='secret.deletion.requested'").Scan(&by)
	if by != "target:"+target.ID {
		t.Fatalf("the re-enrollment removal was attributed to %q", by)
	}
	// The new key is not approved: the host cannot collect the removal, so
	// retiring now refuses unless forced.
	if _, err := f.s.RetireTarget(f.admin(), "local", TargetRetireInput{Reason: "Decommission"}); errCode(err) != "secrets_on_host" {
		t.Fatalf("retired while the host cannot remove its secrets: %v", err)
	}
	must(f.s.ApproveTargetKey(f.admin(), resp.TargetID, KeyApprovalInput{HostKeyID: resp.HostKeyID, Reason: "The fingerprint matches the host console"}))
	jobs := next.poll()
	if len(jobs) != 1 || jobs[0].Type != hostproto.JobSecretDelete {
		t.Fatalf("the re-enrolled host received %+v", jobs)
	}
	r := ev(1, f, hostproto.EventResult)
	r.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "not_held"}
	must(next.events(jobs[0].ID, r))
	if s := secretState(f, sec.ID); s.State != "deleted" {
		t.Fatalf("the re-enrolled host's answer left the secret %s", s.State)
	}
	if must(f.s.TargetDetail(target.ID)).State != "active" {
		t.Fatal("a re-enrolled target changed state when its old secrets were removed")
	}
}

func TestRetireOverHTTPChecksRoleAndBody(t *testing.T) {
	f := newProv(t)
	_, target := f.enrolledTarget()
	admin, launcher := f.token(f.admin(), "admin"), f.token(f.launcher(), "launcher")
	path := "/api/v1/targets/" + target.ID
	for _, c := range []struct {
		name, token, path string
		body              []byte
		status            int
	}{
		{"no credential", "", path, []byte(`{"reason":"Retire"}`), 401},
		{"launcher", launcher, path, []byte(`{"reason":"Retire"}`), 403},
		{"malformed force", admin, path, []byte(`{"reason":"Retire","force":"yes"}`), 422},
		{"unknown field", admin, path, []byte(`{"reason":"Retire","wipe":true}`), 422},
		{"oversize", admin, path, append(append([]byte(`{"reason":"`), bytes.Repeat([]byte("a"), 4<<20)...), '"', '}'), 413},
		{"unknown target", admin, "/api/v1/targets/" + strings.Repeat("0", 32), []byte(`{"reason":"Retire"}`), 404},
	} {
		if resp, out := f.apiRequest("DELETE", c.path, c.token, c.body); resp.StatusCode != c.status {
			t.Fatalf("%s: %d %v", c.name, resp.StatusCode, out)
		}
	}
	resp, out := f.apiRequest("DELETE", path, admin, []byte(`{"reason":"Retire the empty host"}`))
	if resp.StatusCode != 200 || out["state"] != "retired" {
		t.Fatalf("a target without secrets retires at once: %d %v", resp.StatusCode, out)
	}
}

func TestSchemaSevenMigratesAVersionSixDatabase(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	for _, stmt := range []string{"ALTER TABLE targets DROP COLUMN retiring", "ALTER TABLE secrets DROP COLUMN removal", "PRAGMA user_version=6"} {
		if _, err := f.s.DB.Exec(stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	f.http.Close()
	f.s.DB.Close()
	s, err := OpenStore(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	var version, six, seven, targets int
	s.DB.QueryRow("PRAGMA user_version").Scan(&version)
	s.DB.QueryRow("SELECT count(*) FROM audit WHERE request_id='migration-6'").Scan(&six)
	s.DB.QueryRow("SELECT count(*) FROM audit WHERE request_id='migration-7'").Scan(&seven)
	s.DB.QueryRow("SELECT count(*) FROM targets WHERE retiring=''").Scan(&targets)
	if version != SchemaVersion || six != 1 || seven != 2 || targets != 1 {
		t.Fatalf("version %d, migration six %d and seven %d times, %d targets", version, six, seven, targets)
	}
	if _, err := s.TargetDetail("local"); err != nil {
		t.Fatal(err)
	}
}

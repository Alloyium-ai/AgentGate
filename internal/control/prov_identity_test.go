// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"encoding/json"
	"strings"
	"testing"
)

func linkIn(reason string, subjects ...string) IdentityLinkInput {
	return IdentityLinkInput{Subjects: subjects, Reason: reason}
}

// A person with two accounts can never decide a launch either account
// requested, once an administrator links them; the link changes nothing else.
func TestLinkedSubjectsCannotApproveEachOthersLaunches(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	f.profile("web", true)
	// oidc:lin launches; oidc:lin.alt is the same person's second account, an approver.
	lin, linApprover := f.launcher(), f.human("oidc:lin.alt", "approvers")
	l, _ := f.launch(lin, specMap("web"))
	if l.State != StateApprovalPending {
		t.Fatalf("state %s", l.State)
	}
	// Unlinked, the other account of the same person can approve: the documented gap.
	summary := must(f.s.LaunchSummary(linApprover.Actor))
	if summary["awaiting_your_decision"].(map[string]any)["count"].(int) != 1 {
		t.Fatalf("summary before the link %v", summary["awaiting_your_decision"])
	}
	link := must(f.s.LinkIdentities(f.admin(), linkIn("Lin has a second SSO account", "oidc:lin", "oidc:lin.alt"))).(IdentityLink)
	if strings.Join(link.Subjects, ",") != "oidc:lin,oidc:lin.alt" || link.LinkedBy != "oidc:ada" || len(link.Person) != 32 {
		t.Fatalf("link %+v", link)
	}
	for _, approve := range []bool{true, false} {
		_, err := f.s.DecideLaunch(f.human("oidc:lin.alt", "approvers"), l.ID, approve, DecisionInput{Reason: "Decide my own launch with my other account"})
		if errCode(err) != "self_approval" || !strings.Contains(err.Error(), "linked to its requester oidc:lin") {
			t.Fatalf("approve=%t by a linked subject: %v", approve, err)
		}
	}
	summary = must(f.s.LaunchSummary(f.human("oidc:lin.alt", "approvers").Actor))
	if summary["awaiting_your_decision"].(map[string]any)["count"].(int) != 0 {
		t.Fatalf("a linked subject is asked to decide: %v", summary["awaiting_your_decision"])
	}
	if summary = must(f.s.LaunchSummary(f.approver().Actor)); summary["awaiting_your_decision"].(map[string]any)["count"].(int) != 1 {
		t.Fatalf("another approver: %v", summary["awaiting_your_decision"])
	}
	// The link grants nothing: oidc:lin.alt still has only its own roles.
	if _, err := f.s.CreateLaunch(f.human("oidc:lin.alt", "approvers"), specBytes(t, specMap("web"))); errCode(err) != "forbidden" {
		t.Fatalf("a link widened a role: %v", err)
	}
	// Another human decides it.
	if got := must(f.s.DecideLaunch(f.approver(), l.ID, true, DecisionInput{Reason: "Reviewed the plan"})).(launchRow); got.DecidedBy != "oidc:app" {
		t.Fatalf("decided by %s", got.DecidedBy)
	}
	// A third account joins; a group holding another link merges into one person.
	must(f.s.LinkIdentities(f.admin(), linkIn("Bob's two accounts", "local:bob", "oidc:bob")))
	merged := must(f.s.LinkIdentities(f.admin(), linkIn("Bob and Lin are the same contractor", "oidc:bob", "oidc:lin.alt"))).(IdentityLink)
	if strings.Join(merged.Subjects, ",") != "local:bob,oidc:bob,oidc:lin,oidc:lin.alt" {
		t.Fatalf("merged %+v", merged)
	}
	list := must(f.s.IdentityLinks())
	if len(list) != 1 || len(list[0].Subjects) != 4 {
		t.Fatalf("list %+v", list)
	}
	other, _ := f.launch(lin, specMap("web"))
	if _, err := f.s.DecideLaunch(f.human("oidc:bob", "approvers"), other.ID, true, DecisionInput{Reason: "Approve a linked launch"}); errCode(err) != "self_approval" {
		t.Fatalf("a merged subject approved: %v", err)
	}
	// Unlinking: never by an administrator in the group, else the refusal ends for that subject.
	must(f.s.LinkIdentities(f.admin(), linkIn("Ada also has a local account", "oidc:ada", "local:ada")))
	if _, err := f.s.UnlinkIdentity(f.admin(), IdentityUnlinkInput{Subject: "local:ada", Reason: "Unlink myself"}); errCode(err) != "self_unlink" {
		t.Fatalf("an administrator unlinked their own group: %v", err)
	}
	second := f.human("oidc:root", "admins")
	if _, err := f.s.UnlinkIdentity(second, IdentityUnlinkInput{Subject: "local:nobody", Reason: "Unlink an unknown subject"}); errCode(err) != "not_found" {
		t.Fatalf("unknown subject: %v", err)
	}
	out := must(f.s.UnlinkIdentity(second, IdentityUnlinkInput{Subject: "oidc:bob", Reason: "Bob left the contractor"})).(map[string]any)
	if strings.Join(out["subjects"].([]string), ",") != "local:bob,oidc:lin,oidc:lin.alt" {
		t.Fatalf("unlink %v", out)
	}
	if got := must(f.s.DecideLaunch(f.human("oidc:bob", "approvers"), other.ID, true, DecisionInput{Reason: "Reviewed the plan"})).(launchRow); got.State != StateQueued {
		t.Fatalf("an unlinked subject could not approve: %s", got.State)
	}
	// A group left with one subject is removed with it.
	must(f.s.UnlinkIdentity(second, IdentityUnlinkInput{Subject: "local:ada", Reason: "Ada closed her local account"}))
	for _, p := range must(f.s.IdentityLinks()) {
		for _, subject := range p.Subjects {
			if subject == "oidc:ada" || subject == "local:ada" {
				t.Fatalf("a group of one remains: %+v", p)
			}
		}
	}
	// Each change is audited with what it linked.
	var linked, unlinked int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='identity.linked' AND result='committed'").Scan(&linked)
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='identity.unlinked' AND result='committed'").Scan(&unlinked)
	if linked != 4 || unlinked != 2 {
		t.Fatalf("audited links %d unlinks %d", linked, unlinked)
	}
	var after string
	f.s.DB.QueryRow("SELECT after_json FROM audit WHERE action='identity.linked' ORDER BY id LIMIT 1").Scan(&after)
	if !strings.Contains(after, "oidc:lin.alt") || !strings.Contains(after, `"oidc:lin"`) {
		t.Fatalf("audit after %s", after)
	}
}

func TestIdentityLinksAreAdministeredAndValidated(t *testing.T) {
	f := newProv(t)
	for _, op := range []Operation{f.editor(), f.launcher(), f.approver(), f.viewer()} {
		if _, err := f.s.LinkIdentities(op, linkIn("Link without the role", "local:a1", "oidc:a1")); errCode(err) != "forbidden" {
			t.Errorf("%s linked: %v", op.Actor.Subject, err)
		}
		if _, err := f.s.UnlinkIdentity(op, IdentityUnlinkInput{Subject: "local:a1", Reason: "Unlink without the role"}); errCode(err) != "forbidden" {
			t.Errorf("%s unlinked: %v", op.Actor.Subject, err)
		}
	}
	nine := []string{}
	for i := 0; i < 9; i++ {
		nine = append(nine, "local:user"+string(rune('a'+i)))
	}
	bad := map[string]IdentityLinkInput{
		"one subject":     linkIn("Link one", "local:a1"),
		"nine subjects":   linkIn("Link nine", nine...),
		"twice":           linkIn("Link twice", "local:a1", "local:a1"),
		"no scheme":       linkIn("No scheme", "alice", "local:a1"),
		"other scheme":    linkIn("Other scheme", "ldap:alice", "local:a1"),
		"empty subject":   linkIn("Empty", "local:", "local:a1"),
		"control char":    linkIn("Control", "oidc:a\nb", "local:a1"),
		"space":           linkIn("Space", "oidc:a b", "local:a1"),
		"short reason":    linkIn("x", "local:a1", "oidc:a1"),
		"too long":        linkIn("Too long", "oidc:"+strings.Repeat("x", 256), "local:a1"),
		"no subjects":     {Reason: "No subjects"},
		"non-ascii":       linkIn("Non-ASCII", "oidc:é", "local:a1"),
		"group too large": linkIn("Grow beyond eight", "local:a1", "oidc:a1"),
	}
	for i := 0; i < 7; i++ {
		must(f.s.LinkIdentities(f.admin(), linkIn("Seven accounts of one person", "local:big", "oidc:big"+string(rune('a'+i)))))
	}
	bad["group too large"] = linkIn("Grow beyond eight", "local:big", "oidc:other", "oidc:another")
	for name, in := range bad {
		if _, err := f.s.LinkIdentities(f.admin(), in); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := f.s.UnlinkIdentity(f.admin(), IdentityUnlinkInput{Subject: "nonsense", Reason: "Unlink nonsense"}); errCode(err) != "invalid_identity_link" {
		t.Fatalf("unlink nonsense: %v", err)
	}
	// Every refusal is audited as a denial.
	var denied int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action LIKE 'identity.%' AND result='denied'").Scan(&denied)
	if denied < len(bad)+8 {
		t.Fatalf("denials audited: %d", denied)
	}
	// Over HTTP: an admin token lists, links and unlinks; other roles get 403.
	admin := f.token(f.admin(), "admin")
	viewer := f.token(f.viewer(), "viewer")
	if resp, _ := f.apiRequest("GET", "/api/v1/identity-links", viewer, nil); resp.StatusCode != 403 {
		t.Fatalf("a viewer listed links: %d", resp.StatusCode)
	}
	resp, body := f.apiRequest("POST", "/api/v1/identity-links", admin, []byte(`{"subjects":["local:cara","oidc:cara"],"reason":"Cara signs in two ways"}`))
	if resp.StatusCode != 200 || body["person"] == nil {
		t.Fatalf("link over HTTP: %d %v", resp.StatusCode, body)
	}
	resp, body = f.apiRequest("GET", "/api/v1/identity-links", admin, nil)
	raw, _ := json.Marshal(body)
	if resp.StatusCode != 200 || !strings.Contains(string(raw), `"local:cara"`) {
		t.Fatalf("list over HTTP: %d %s", resp.StatusCode, raw)
	}
	if resp, _ = f.apiRequest("POST", "/api/v1/identity-links", admin, []byte(`{"subjects":["local:cara","oidc:cara"],"reason":"Extra","extra":1}`)); resp.StatusCode != 422 {
		t.Fatalf("an unknown field: %d", resp.StatusCode)
	}
	if resp, _ = f.apiRequest("DELETE", "/api/v1/identity-links", viewer, []byte(`{"subject":"oidc:cara","reason":"Unlink as a viewer"}`)); resp.StatusCode != 403 {
		t.Fatalf("a viewer unlinked: %d", resp.StatusCode)
	}
	if resp, body = f.apiRequest("DELETE", "/api/v1/identity-links", admin, []byte(`{"subject":"oidc:cara","reason":"Cara closed her SSO account"}`)); resp.StatusCode != 200 {
		t.Fatalf("unlink over HTTP: %d %v", resp.StatusCode, body)
	}
}

// Schema 11 adds the table to an existing database, and a repeated migration
// changes nothing.
func TestIdentityLinkMigrationIsForwardOnlyAndIdempotent(t *testing.T) {
	f := newProv(t)
	must(f.s.LinkIdentities(f.admin(), linkIn("Before the reopen", "local:dee", "oidc:dee")))
	f.http.Close()
	if _, err := f.s.DB.Exec("PRAGMA user_version=10"); err != nil {
		t.Fatal(err)
	}
	f.s.DB.Close()
	s, err := OpenStore(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	var version, links int
	s.DB.QueryRow("PRAGMA user_version").Scan(&version)
	s.DB.QueryRow("SELECT count(*) FROM identity_links").Scan(&links)
	if version != SchemaVersion || links != 2 {
		t.Fatalf("version %d links %d", version, links)
	}
	if _, err = s.DB.Exec("DROP TABLE identity_links; PRAGMA user_version=10"); err != nil {
		t.Fatal(err)
	}
	s.DB.Close()
	if s, err = OpenStore(f.dir); err != nil {
		t.Fatal(err)
	}
	defer s.DB.Close()
	var migrated int
	s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='schema.migrated' AND request_id='migration-11'").Scan(&migrated)
	s.DB.QueryRow("SELECT count(*) FROM identity_links").Scan(&links)
	if migrated != 3 || links != 0 {
		t.Fatalf("migrations %d links %d", migrated, links)
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"testing"
	"time"
)

// localOp seeds a browser session for a local account, as a sign-in would.
func (f *provFixture) localOp(subject string) Operation {
	f.t.Helper()
	actor, err := localActor(f.s.DB, subject)
	if err != nil {
		f.t.Fatal(err)
	}
	sid := "session-" + subject + newID()
	if _, err := f.s.DB.Exec("INSERT OR REPLACE INTO sessions VALUES(?,?,?,?)", digest([]byte(sid)), jsonText(sessionActor{actor, f.s.LoginAuthority}), "csrf", time.Now().Add(48*time.Hour).Unix()); err != nil {
		f.t.Fatal(err)
	}
	return Operation{SessionHash: digest([]byte(sid)), Actor: actor, RequestID: newID(), BodyDigest: "fixture-" + newID()}
}

// Regression for the review repro TestReviewPasswordResetKeepsTokens: a
// password reset (the answer to a stolen session) expired sessions but left
// every API token working, and disabling then enabling an account brought
// the old tokens back.
func TestPasswordResetAndDisableRevokeAPITokens(t *testing.T) {
	f := newProv(t)
	if err := f.s.BootstrapAdmin("root-admin", "Root", "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	must(f.s.PutUser(f.localOp("local:root-admin"), UserInput{Username: "bob", Name: "Bob", Roles: []string{"launcher"}, Enabled: true, Password: "bobs first password!!", Reason: "Create bob"}))
	must(f.s.PutUser(f.localOp("local:root-admin"), UserInput{Username: "carol", Name: "Carol", Roles: []string{"launcher"}, Enabled: true, Password: "carols first password!", Reason: "Create carol"}))
	stolen := f.token(f.localOp("local:bob"), "launcher")
	bystander := f.token(f.localOp("local:carol"), "launcher")
	alive := func(tok string) bool {
		resp, _ := f.apiRequest("GET", "/api/v1/launches", tok, nil)
		return resp.StatusCode == 200
	}
	if !alive(stolen) || !alive(bystander) {
		t.Fatal("fresh tokens do not work")
	}
	// A role change keeps the token (its roles are intersected at use).
	must(f.s.PutUser(f.localOp("local:root-admin"), UserInput{Username: "bob", Name: "Bob B", Roles: []string{"launcher", "viewer"}, Enabled: true, Parent: 1, Reason: "Rename bob"}))
	if !alive(stolen) {
		t.Fatal("a change without a password or status change revoked the token")
	}
	must(f.s.PutUser(f.localOp("local:root-admin"), UserInput{Username: "bob", Name: "Bob B", Roles: []string{"launcher"}, Enabled: true, Password: "a brand new password", Parent: 2, Reason: "Reset after compromise"}))
	if alive(stolen) {
		t.Fatal("the token minted before the password reset still works")
	}
	var revoked int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='apitoken.revoked' AND after_json LIKE '%password_reset%' AND after_json LIKE '%local:bob%'").Scan(&revoked)
	if revoked != 1 {
		t.Fatalf("revocation audit rows %d", revoked)
	}
	if !alive(bystander) {
		t.Fatal("another user's token was revoked")
	}

	// Disable, then enable again: a token minted before the disable stays dead.
	fresh := f.token(f.localOp("local:bob"), "launcher")
	must(f.s.PutUser(f.localOp("local:root-admin"), UserInput{Username: "bob", Name: "Bob B", Roles: []string{"launcher"}, Enabled: false, Parent: 3, Reason: "Disable"}))
	if alive(fresh) {
		t.Fatal("a disabled account's token works")
	}
	must(f.s.PutUser(f.localOp("local:root-admin"), UserInput{Username: "bob", Name: "Bob B", Roles: []string{"launcher"}, Enabled: true, Parent: 4, Reason: "Re-enable"}))
	if alive(fresh) {
		t.Fatal("re-enabling the account resurrected a token minted before the disable")
	}
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='apitoken.revoked' AND after_json LIKE '%account_disabled%'").Scan(&revoked)
	if revoked != 1 {
		t.Fatalf("disable revocation audit rows %d", revoked)
	}
	// A token minted after the account is enabled again works.
	if !alive(f.token(f.localOp("local:bob"), "launcher")) {
		t.Fatal("a new token does not work")
	}
}

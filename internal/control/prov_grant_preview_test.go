// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bytes"
	"strings"
	"testing"

	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/pocpolicy"
)

func versionCount(f *provFixture, profileID string) int {
	var n int
	f.s.DB.QueryRow("SELECT count(*) FROM profile_versions WHERE profile_id=?", profileID).Scan(&n)
	return n
}

func TestGrantDryRunStoresNothingAndAnswersLikeTheGrant(t *testing.T) {
	f := newProv(t)
	p := f.profileFrom("dev", "python-dev", true)
	parent := must(f.s.ProfileVersionDetail(p.ID, "1"))
	edits := []access.Edit{{Action: "read", Values: []string{"/srv/data"}}, {Action: "deny-web", Values: []string{"http"}}}
	dry := must(f.s.ApplyGrants(f.editor(), p.Name, "1", GrantInput{Edits: edits, Reason: "Preview the data set", DryRun: true})).(map[string]any)
	if dry["dry_run"] != true || dry["changed"] != true || dry["from_digest"] != parent.Digest || dry["from_version"] != 1 || dry["version"] != nil {
		t.Fatalf("dry run %v", dry)
	}
	doc := dry["document"].(pocpolicy.Document)
	if dry["digest"] != doc.Digest() || doc.Digest() == parent.Digest {
		t.Fatal("the dry run digest is not the resulting document's")
	}
	if versionCount(f, p.ID) != 1 || auditCount(f, "profile.grants.applied") != 0 || auditCount(f, "profile.grant.previewed") != 1 {
		t.Fatal("a dry run stored a version or was audited as a grant")
	}
	changes := dry["changes"].([]PolicyChange)
	want := []PolicyChange{{Area: "Network", Field: "public web", Change: "removed", Before: "HTTP (TCP 80)"}, {Area: "Files", Field: "read", Change: "added", After: "/srv/data"}}
	if len(changes) != len(want) {
		t.Fatalf("changes %+v", changes)
	}
	for i := range want {
		if changes[i] != want[i] {
			t.Fatalf("change %d: %+v, want %+v", i, changes[i], want[i])
		}
	}
	// Applying the same edits gives the same document, digest and changes.
	applied := must(f.s.ApplyGrants(f.editor(), p.Name, "1", GrantInput{Edits: edits, Reason: "Read the data set"})).(map[string]any)
	v := applied["version"].(ProfileVersion)
	if v.Number != 2 || v.Digest != dry["digest"] || applied["digest"] != v.Digest || applied["from_digest"] != parent.Digest || len(applied["changes"].([]PolicyChange)) != 2 {
		t.Fatalf("applied %v", applied)
	}
	// A dry run of an edit that changes nothing says so.
	noop := must(f.s.ApplyGrants(f.editor(), p.Name, "2", GrantInput{Edits: edits[:1], Reason: "Repeat it", DryRun: true})).(map[string]any)
	if noop["changed"] != false || len(noop["changes"].([]PolicyChange)) != 0 || noop["digest"] != v.Digest {
		t.Fatalf("no-op dry run %v", noop)
	}
	// Every refusal of the grant is a refusal of its preview, and stores nothing.
	cases := []struct {
		op   Operation
		n    string
		in   GrantInput
		code string
	}{
		{f.editor(), "1", GrantInput{Edits: edits, Reason: "Stale parent", DryRun: true}, "stale_parent"},
		{f.editor(), "2", GrantInput{Edits: []access.Edit{{Action: "exec", Values: []string{"/var/lib/agentgate/workspace/bin"}}}, Reason: "Overlap", DryRun: true}, "grant_conflict"},
		{f.editor(), "2", GrantInput{Edits: make([]access.Edit, 17), Reason: "Too many", DryRun: true}, "invalid_edits"},
		{f.editor(), "2", GrantInput{Edits: edits, Reason: "x", DryRun: true}, "invalid_reason"},
		{f.launcher(), "2", GrantInput{Edits: edits, Reason: "Not an editor", DryRun: true}, "forbidden"},
		{f.viewer(), "2", GrantInput{Edits: edits, Reason: "Not an editor", DryRun: true}, "forbidden"},
	}
	for _, c := range cases {
		_, err := f.s.ApplyGrants(c.op, p.Name, c.n, c.in)
		if code := errCode(err); code != c.code && !(c.code == "invalid_reason" && code != "") {
			t.Fatalf("%s: got %q (%v)", c.in.Reason, code, err)
		}
	}
	if _, err := f.s.ApplyGrants(f.editor(), "missing", "1", GrantInput{Edits: edits, Reason: "Another profile", DryRun: true}); errCode(err) != "not_found" {
		t.Fatal("a dry run of a missing profile")
	}
	if versionCount(f, p.ID) != 2 {
		t.Fatal("a refused dry run stored a version")
	}
	var denied int
	f.s.DB.QueryRow("SELECT count(*) FROM audit WHERE action='profile.grant.previewed' AND result='denied'").Scan(&denied)
	if denied < len(cases) {
		t.Fatalf("%d of %d refused previews are audited", denied, len(cases))
	}
}

func TestGrantDryRunOverHTTP(t *testing.T) {
	f := newProv(t)
	p := f.profileFrom("dev", "python-dev", true)
	editor, viewer := f.token(f.editor(), "editor"), f.token(f.viewer(), "viewer")
	path := "/api/v1/profiles/" + p.ID + "/versions/1/grants"
	body := []byte(`{"edits":[{"action":"read","values":["/srv/data"]}],"reason":"Preview","dry_run":true}`)
	resp, out := f.apiRequest("POST", path, editor, body)
	if resp.StatusCode != 200 || out["dry_run"] != true || out["document"] == nil || len(out["changes"].([]any)) != 1 {
		t.Fatalf("dry run %d %v", resp.StatusCode, out)
	}
	change := out["changes"].([]any)[0].(map[string]any)
	if change["area"] != "Files" || change["field"] != "read" || change["change"] != "added" || change["after"] != "/srv/data" || change["before"] != nil {
		t.Fatalf("change %v", change)
	}
	for _, c := range []struct {
		name, token string
		body        []byte
		status      int
	}{
		{"no credential", "", body, 401},
		{"viewer", viewer, body, 403},
		{"malformed flag", editor, []byte(`{"edits":[{"action":"read","values":["/srv/data"]}],"reason":"Preview","dry_run":"yes"}`), 422},
		{"unknown field", editor, []byte(`{"edits":[{"action":"read","values":["/srv/data"]}],"reason":"Preview","dry_run":true,"apply":true}`), 422},
		{"not JSON", editor, []byte(`{"edits":`), 422},
		{"oversize", editor, append(append([]byte(`{"edits":[],"reason":"`), bytes.Repeat([]byte("a"), 4<<20)...), []byte(`","dry_run":true}`)...), 413},
	} {
		resp, out := f.apiRequest("POST", path, c.token, c.body)
		if resp.StatusCode != c.status {
			t.Fatalf("%s: %d %v", c.name, resp.StatusCode, out)
		}
	}
	resp, _ = f.apiRequest("POST", "/api/v1/profiles/"+strings.Repeat("0", 32)+"/versions/1/grants", editor, body)
	if resp.StatusCode != 404 {
		t.Fatalf("a dry run of another profile id: %d", resp.StatusCode)
	}
	if versionCount(f, p.ID) != 1 {
		t.Fatal("an HTTP dry run stored a version")
	}
}

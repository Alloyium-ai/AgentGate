// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func listLaunches(t *testing.T, f *provFixture, token string, q url.Values) ([]map[string]any, string) {
	t.Helper()
	resp, body := f.apiRequest("GET", "/api/v1/launches?"+q.Encode(), token, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("GET /launches?%s: %d %v", q.Encode(), resp.StatusCode, body)
	}
	items := []map[string]any{}
	for _, item := range body["items"].([]any) {
		items = append(items, item.(map[string]any))
	}
	next, _ := body["next_cursor"].(string)
	return items, next
}

// allPages follows next_cursor and checks that pages never repeat a launch.
func allPages(t *testing.T, f *provFixture, token string, q url.Values) []map[string]any {
	t.Helper()
	out, seen := []map[string]any{}, map[string]bool{}
	for page := 0; page < 100; page++ {
		items, next := listLaunches(t, f, token, q)
		for _, l := range items {
			id := l["id"].(string)
			if seen[id] {
				t.Fatalf("launch %s appears on two pages", id)
			}
			seen[id] = true
			if l["plan"] != nil || l["receipt"] != nil {
				t.Fatal("a list item carries its plan or receipt")
			}
		}
		out = append(out, items...)
		if next == "" {
			return out
		}
		q.Set("cursor", next)
	}
	t.Fatal("the pages never end")
	return nil
}

func TestLaunchListFiltersPagesAndCounts(t *testing.T) {
	f := newProv(t)
	f.enrolledTarget()
	f.secondTarget("other")
	f.profile("dev", false)
	f.profile("reviewed", true)
	lin, ada := f.launcher(), f.admin()
	want := map[string]int{}
	ids := map[string]string{}
	for i := 0; i < 23; i++ {
		m := specMap("dev")
		m["name"] = fmt.Sprintf("job-%02d", i)
		op := lin
		switch {
		case i%5 == 0:
			m["target"] = "other"
		case i%7 == 0:
			op = ada
			m["name"] = fmt.Sprintf("fix-tests-%02d", i)
		}
		if i%4 == 0 {
			m["access"] = map[string]any{"profile": "reviewed", "version": 1}
		}
		l, _ := f.launch(op, m)
		ids[l.Name] = l.ID
		if i%6 == 0 && l.State == StateQueued {
			must(f.s.StopLaunch(lin, l.ID, DecisionInput{Reason: "Not needed"}))
		}
		want[f.state(l.ID).State]++
	}
	viewer, launcher, approver := f.token(f.viewer(), "viewer"), f.token(lin, "launcher"), f.token(f.approver(), "approver")

	// Every launch, newest first, in pages of 7 without repeats or gaps.
	all := allPages(t, f, viewer, url.Values{"limit": {"7"}})
	if len(all) != 23 {
		t.Fatalf("%d launches over all pages", len(all))
	}
	for i := 1; i < len(all); i++ {
		a, b := all[i-1], all[i]
		if a["created_at"].(string) < b["created_at"].(string) || (a["created_at"] == b["created_at"] && a["id"].(string) < b["id"].(string)) {
			t.Fatal("pages are not newest first by (created, id)")
		}
	}
	// A launch created between two pages never shifts the next page.
	first, next := listLaunches(t, f, viewer, url.Values{"limit": {"5"}})
	f.launch(lin, specMap("dev"))
	rest := allPages(t, f, viewer, url.Values{"limit": {"5"}, "cursor": {next}})
	if len(first)+len(rest) != 23 || rest[0]["id"] == first[len(first)-1]["id"] {
		t.Fatalf("a concurrent insert shifted the pages: %d + %d", len(first), len(rest))
	}

	count := func(q url.Values, ok func(map[string]any) bool) {
		t.Helper()
		got := allPages(t, f, launcher, q)
		n := 0
		for _, l := range allPages(t, f, viewer, url.Values{}) {
			if ok(l) {
				n++
			}
		}
		if len(got) != n || n == 0 {
			t.Fatalf("%s: %d launches, want %d", q.Encode(), len(got), n)
		}
		for _, l := range got {
			if !ok(l) {
				t.Fatalf("%s returned %v", q.Encode(), l)
			}
		}
	}
	other := must(f.s.TargetDetail("other"))
	count(url.Values{"state": {"approval_pending"}, "limit": {"3"}}, func(l map[string]any) bool { return l["state"] == "approval_pending" })
	count(url.Values{"state": {"active"}}, func(l map[string]any) bool { return !TerminalState(l["state"].(string)) })
	count(url.Values{"state": {"ended"}}, func(l map[string]any) bool { return TerminalState(l["state"].(string)) })
	count(url.Values{"target": {"other"}, "limit": {"2"}}, func(l map[string]any) bool { return l["target_id"] == other.ID })
	count(url.Values{"target": {other.ID}}, func(l map[string]any) bool { return l["target_id"] == other.ID })
	count(url.Values{"name": {"fix"}}, func(l map[string]any) bool { return strings.Contains(l["name"].(string), "fix") })
	count(url.Values{"requester": {"oidc:ada"}}, func(l map[string]any) bool { return l["requested_by"] == "oidc:ada" })
	count(url.Values{"mine": {"true"}, "state": {"active"}, "target": {"local"}}, func(l map[string]any) bool {
		return l["requested_by"] == "oidc:lin" && !TerminalState(l["state"].(string)) && l["target_id"] != other.ID
	})

	// A cursor answers only the filters it was issued for and only as issued.
	_, cursor := listLaunches(t, f, viewer, url.Values{"state": {"active"}, "limit": {"2"}})
	raw, _ := base64.RawURLEncoding.DecodeString(cursor)
	var c map[string]any
	json.Unmarshal(raw, &c)
	c["v"] = 2
	forged, _ := json.Marshal(c)
	for name, q := range map[string]url.Values{
		"other filters":    {"cursor": {cursor}},
		"other version":    {"state": {"active"}, "cursor": {base64.RawURLEncoding.EncodeToString(forged)}},
		"not canonical":    {"state": {"active"}, "cursor": {base64.RawURLEncoding.EncodeToString(append(raw, ' '))}},
		"garbage":          {"cursor": {"not-a-cursor"}},
		"oversize cursor":  {"cursor": {strings.Repeat("A", 600)}},
		"unknown filter":   {"owner": {"x"}},
		"bad state":        {"state": {"sleeping"}},
		"limit zero":       {"limit": {"0"}},
		"limit too large":  {"limit": {"201"}},
		"limit not number": {"limit": {"ten"}},
		"bad name":         {"name": {"Fix Tests"}},
		"bad requester":    {"requester": {"a b"}},
		"bad mine":         {"mine": {"maybe"}},
		"mine and other":   {"mine": {"1"}, "requester": {"oidc:ada"}},
		"repeated":         {"state": {"running", "queued"}},
		"bad target":       {"target": {"Not A Target"}},
		"oversize query":   {"name": {"job"}, "pad": {strings.Repeat("x", 1100)}},
	} {
		resp, body := f.apiRequest("GET", "/api/v1/launches?"+q.Encode(), viewer, nil)
		if resp.StatusCode != 422 {
			t.Fatalf("%s: %d %v", name, resp.StatusCode, body)
		}
	}
	if resp, _ := f.apiRequest("GET", "/api/v1/launches?target="+strings.Repeat("0", 32), viewer, nil); resp.StatusCode != 404 {
		t.Fatalf("an unknown target filter: %d", resp.StatusCode)
	}
	if resp, _ := f.apiRequest("GET", "/api/v1/launches", "", nil); resp.StatusCode != 401 {
		t.Fatal("an anonymous list")
	}

	// The summary counts every launch by state.
	resp, sum := f.apiRequest("GET", "/api/v1/launches/summary", approver, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %v", resp.StatusCode, sum)
	}
	want[StateQueued]++ // the launch created between pages
	counts := sum["counts"].(map[string]any)
	total, active := 0, 0
	for state, n := range counts {
		if int(n.(float64)) != want[state] {
			t.Fatalf("summary %s = %v, want %d", state, n, want[state])
		}
		total += int(n.(float64))
		if !TerminalState(state) {
			active += int(n.(float64))
		}
	}
	if len(counts) != 12 || sum["total"] != float64(total) || sum["active"] != float64(active) || total != 24 {
		t.Fatalf("summary %v", sum)
	}
	awaiting := sum["awaiting_your_decision"].(map[string]any)
	if awaiting["count"] != float64(want[StateApprovalPending]) || len(awaiting["items"].([]any)) == 0 {
		t.Fatalf("awaiting %v", awaiting)
	}
	// A launcher decides nothing; the requester's own launches never wait for them.
	_, sum = f.apiRequest("GET", "/api/v1/launches/summary", launcher, nil)
	if sum["awaiting_your_decision"].(map[string]any)["count"] != float64(0) {
		t.Fatal("a launcher sees launches waiting for their decision")
	}
	adminTok := f.token(ada, "admin")
	_, sum = f.apiRequest("GET", "/api/v1/launches/summary", adminTok, nil)
	adaPending := 0
	for _, l := range allPages(t, f, viewer, url.Values{"state": {"approval_pending"}, "requester": {"oidc:ada"}}) {
		_ = l
		adaPending++
	}
	if sum["awaiting_your_decision"].(map[string]any)["count"] != float64(want[StateApprovalPending]-adaPending) {
		t.Fatal("the summary counts the administrator's own launches as waiting for them")
	}
	if sum["expiring_soon"].(map[string]any)["count"] != float64(0) {
		t.Fatal("nothing expires soon yet")
	}
	f.advance(40 * time.Minute)
	_, sum = f.apiRequest("GET", "/api/v1/launches/summary", viewer, nil)
	soon := sum["expiring_soon"].(map[string]any)
	if soon["count"] != float64(want[StateQueued]) || soon["window_seconds"] != float64(1800) {
		t.Fatalf("expiring %v", soon)
	}
	if resp, _ := f.apiRequest("GET", "/api/v1/launches/summary?state=running", viewer, nil); resp.StatusCode != 422 {
		t.Fatal("the summary took a filter")
	}
	if resp, _ := f.apiRequest("GET", "/api/v1/launches/summary", "", nil); resp.StatusCode != 401 {
		t.Fatal("an anonymous summary")
	}
	_ = ids
}

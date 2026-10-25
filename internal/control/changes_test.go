// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bufio"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// recordChanges keeps every change the store announces, still passing each
// one to the server's streams.
func recordChanges(f *provFixture) func() []Change {
	var mu sync.Mutex
	var got []Change
	next := f.s.Changed
	f.s.Changed = func(c Change) {
		mu.Lock()
		got = append(got, c)
		mu.Unlock()
		next(c)
	}
	return func() []Change {
		mu.Lock()
		defer mu.Unlock()
		out := got
		got = nil
		return out
	}
}

type changedEvent struct {
	ID        int64    `json:"id"`
	Resources []string `json:"resources"`
	all       bool
	at        time.Time
}

// openChanges follows GET /api/v1/events as subject's browser session and
// returns the changed events as they arrive.
func openChanges(t *testing.T, f *provFixture, subject string) <-chan changedEvent {
	t.Helper()
	req, _ := http.NewRequest("GET", f.http.URL+"/api/v1/events", nil)
	req.Header.Set("Cookie", "__Host-enforcer-session=session-"+subject)
	resp, err := f.http.Client().Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("the change stream: %v %v", err, resp)
	}
	t.Cleanup(func() { resp.Body.Close() })
	out := make(chan changedEvent, 256)
	reader := &sseReader{r: bufio.NewReader(resp.Body)}
	ready := make(chan struct{})
	go func() {
		defer close(out)
		first := true
		for {
			m, err := reader.next(t)
			if err != nil {
				return
			}
			if first && m.event == "ready" {
				first = false
				close(ready)
				continue
			}
			if m.event != "changed" {
				continue
			}
			var e changedEvent
			raw := map[string]json.RawMessage{}
			json.Unmarshal([]byte(m.data), &raw)
			json.Unmarshal([]byte(m.data), &e)
			_, e.all = raw["resources"]
			e.all, e.at = !e.all, time.Now()
			out <- e
		}
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("the change stream never became ready")
	}
	return out
}

// drain collects the events that arrive within d.
func drain(events <-chan changedEvent, d time.Duration) []changedEvent {
	var out []changedEvent
	deadline := time.After(d)
	for {
		select {
		case e, ok := <-events:
			if !ok {
				return out
			}
			out = append(out, e)
		case <-deadline:
			return out
		}
	}
}

func has(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// Regression for the second review's finding that every host request,
// heartbeats included, made every open browser tab reload everything: a
// heartbeat-only poll now announces nothing, a state change exactly one
// change naming the launch, and log lines only the launch's own streams.
func TestHeartbeatsAnnounceNothingAndAStateChangeOnce(t *testing.T) {
	saved := changeInterval
	changeInterval = 200 * time.Millisecond
	t.Cleanup(func() { changeInterval = saved })
	f := newProv(t)
	h, target := f.enrolledTarget()
	f.profile("dev", false)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	f.admin()
	f.viewer()
	stream := openChanges(t, f, "oidc:ada")
	viewer := openChanges(t, f, "oidc:vic")
	changes := recordChanges(f)
	jobs := h.poll()
	if len(jobs) != 1 {
		t.Fatalf("jobs %d", len(jobs))
	}
	if got := changes(); len(got) != 1 || !got[0].touches("launch:"+l.ID) {
		t.Fatalf("delivering the launch job announced %+v", got)
	}
	drain(stream, 400*time.Millisecond)
	drain(viewer, 50*time.Millisecond)
	// Thirty heartbeats, over the real HTTP route as the host sends them.
	for i := 0; i < 30; i++ {
		if code := f.send("POST", "/api/v1/hostd/poll", "", h.pollRaw()); code != 200 {
			t.Fatalf("poll %d: HTTP %d", i, code)
		}
	}
	if got := changes(); len(got) != 0 {
		t.Fatalf("heartbeat-only polls announced %+v", got)
	}
	if got := drain(stream, 500*time.Millisecond); len(got) != 0 {
		t.Fatalf("heartbeat-only polls sent %d changed events: %+v", len(got), got)
	}
	// One state change: exactly one change, one event, naming the launch.
	e1 := ev(1, f, hostproto.EventState)
	e1.State = StateRunning
	must(h.events(jobs[0].ID, e1))
	got := changes()
	if len(got) != 1 || !got[0].touches("launch:"+l.ID) || got[0].All {
		t.Fatalf("a state change announced %+v", got)
	}
	sent := drain(stream, 500*time.Millisecond)
	if len(sent) != 1 || sent[0].all || !has(sent[0].Resources, "launch:"+l.ID) || !has(sent[0].Resources, "audit") || has(sent[0].Resources, "target:"+target.ID) {
		t.Fatalf("the state change sent %+v", sent)
	}
	for _, r := range sent[0].Resources {
		if strings.HasPrefix(r, "launch-log:") {
			t.Fatal("a launch log marker reached the change stream")
		}
	}
	// The viewer's stream names what a viewer reads, nothing more.
	readsAudit := require(f.viewer().Actor, "audit:read", false) == nil
	if v := drain(viewer, 300*time.Millisecond); len(v) != 1 || !has(v[0].Resources, "launch:"+l.ID) || has(v[0].Resources, "audit") != readsAudit {
		t.Fatalf("the viewer's stream sent %+v", v)
	}
	// Log lines wake only the launch's own streams: no changed event.
	for seq := uint32(2); seq < 12; seq++ {
		must(h.events(jobs[0].ID, logEvent(seq, f, "line")))
	}
	if got := changes(); len(got) != 10 || !got[0].touches("launch-log:"+l.ID) || got[0].touches("launch:"+l.ID) {
		t.Fatalf("log lines announced %+v", got)
	}
	if sent := drain(stream, 500*time.Millisecond); len(sent) != 0 {
		t.Fatalf("log lines sent %d changed events", len(sent))
	}
}

// A burst of changes is merged: at most one changed event per interval,
// naming every resource of the burst.
func TestChangedEventsAreMergedAndPaced(t *testing.T) {
	saved := changeInterval
	changeInterval = 300 * time.Millisecond
	t.Cleanup(func() { changeInterval = saved })
	f := newProv(t)
	f.enrolledTarget()
	f.profile("dev", false)
	f.admin()
	stream := openChanges(t, f, "oidc:ada")
	start := time.Now()
	var ids []string
	for i := 0; i < 12; i++ {
		spec := specMap("dev")
		spec["name"] = "burst-" + string(rune('a'+i))
		l, _ := f.launch(f.launcher(), spec)
		ids = append(ids, l.ID)
	}
	sent := drain(stream, time.Since(start)+800*time.Millisecond)
	elapsed := time.Since(start)
	if len(sent) == 0 || len(sent) > int(elapsed/changeInterval)+2 {
		t.Fatalf("%d events in %s for 12 launches", len(sent), elapsed)
	}
	for i := 1; i < len(sent); i++ {
		if sent[i].at.Sub(sent[i-1].at) < changeInterval-50*time.Millisecond {
			t.Fatalf("events %d and %d came %s apart", i-1, i, sent[i].at.Sub(sent[i-1].at))
		}
	}
	named := map[string]bool{}
	for _, e := range sent {
		for _, r := range e.Resources {
			named[r] = true
		}
	}
	for _, id := range ids {
		if !named["launch:"+id] {
			t.Fatalf("launch %s was never named", id)
		}
	}
}

func TestChangeStreamNamesOnlyWhatTheActorReads(t *testing.T) {
	f := newProv(t)
	admin, viewer := f.admin().Actor, f.viewer().Actor
	c := Change{ID: 9, Resources: []string{"launch:l1", "launch-log:l1", "secret:s1", "target:t1", "policy-7", "api", admin.Subject}}
	got, all, send := visibleChange(admin, c)
	if all || !send || strings.Join(got, ",") != "audit,launch:l1,other,secret:s1,self,target:t1" {
		t.Fatalf("admin sees %v", got)
	}
	if require(viewer, "secrets:admin", false) == nil {
		t.Fatal("the fixture's viewer administers secrets")
	}
	got, _, send = visibleChange(viewer, c)
	if !send || has(got, "secret:s1") || has(got, "self") || has(got, "launch-log:l1") || !has(got, "launch:l1") ||
		has(got, "audit") != (require(viewer, "audit:read", false) == nil) {
		t.Fatalf("viewer sees %v", got)
	}
	// Only a launch log marker, or only an API denial: nothing for a viewer.
	if _, _, send = visibleChange(viewer, Change{ID: 10, Resources: []string{"launch-log:l1"}}); send {
		t.Fatal("a log marker was sent")
	}
	// An API denial changes only the audit log.
	if got, _, send = visibleChange(viewer, Change{ID: 11, Resources: []string{"api"}}); send != (require(viewer, "audit:read", false) == nil) || (send && strings.Join(got, ",") != "audit") {
		t.Fatalf("an API denial was sent to a viewer as %v", got)
	}
	if _, all, send = visibleChange(viewer, Change{ID: 12, All: true}); !all || !send {
		t.Fatal("an unknown change was not sent as everything")
	}
}

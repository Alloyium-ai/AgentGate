// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/control"
)

func stateEvent(seq int, from, to, reason string) control.LaunchEvent {
	return control.LaunchEvent{Seq: seq, Time: "2026-10-24T12:00:0" + fmt.Sprint(seq%10) + "Z", Kind: "state", From: from, To: to, Actor: "agentgate-scheduler", Reason: reason, Data: json.RawMessage(`{}`)}
}

// sseScript serves one scripted batch of events per connection and records
// each connection's Last-Event-ID.
type sseScript struct {
	mu      sync.Mutex
	batches [][]control.LaunchEvent
	hold    bool // keep the last connection open with keepalives
	lastIDs []string
	fail    int // answer this many connections with 503 first
	conns   atomic.Int32
}

func (s *sseScript) handler(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		writeJSON(w, 200, map[string]any{"items": []any{}})
		return
	}
	s.conns.Add(1)
	s.mu.Lock()
	s.lastIDs = append(s.lastIDs, r.Header.Get("Last-Event-ID"))
	if s.fail > 0 {
		s.fail--
		s.mu.Unlock()
		http.Error(w, "stream capacity reached", 503)
		return
	}
	var batch []control.LaunchEvent
	last := len(s.batches) <= 1
	if len(s.batches) > 0 {
		batch = s.batches[0]
		s.batches = s.batches[1:]
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(200)
	f := w.(http.Flusher)
	fmt.Fprint(w, "event: ready\ndata: {}\n\n")
	for _, e := range batch {
		raw, _ := json.Marshal(e)
		fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", e.Seq, e.Kind, raw)
	}
	f.Flush()
	if last && s.hold {
		for {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Millisecond):
				fmt.Fprint(w, ": keepalive\n\n")
				f.Flush()
			}
		}
	}
}

func TestEventsFollowResumesWithLastEventID(t *testing.T) {
	h := newHarness(t)
	h.login("local:vic", "viewer")
	id := sampleLaunch("queued").ID
	script := &sseScript{fail: 1, batches: [][]control.LaunchEvent{
		{stateEvent(1, "", "requested", "Launch requested"), stateEvent(2, "requested", "approved", "Automatic approval")},
		{stateEvent(2, "requested", "approved", "Automatic approval"), stateEvent(3, "approved", "queued", "Queued for the target"), {Seq: 4, Time: "2026-10-24T12:00:04Z", Kind: "progress", Reason: "pulling image", Data: json.RawMessage(`{}`)}},
		{stateEvent(5, "queued", "provisioning", ""), stateEvent(6, "provisioning", "running", ""), stateEvent(7, "running", "stopping", "Done"), stateEvent(8, "stopping", "stopped", "Done")},
	}}
	h.api.handle("GET /api/v1/launches/{id}/events", script.handler)
	r := h.run("", "events", id, "-f")
	if r.code != 0 {
		t.Fatalf("%v", r)
	}
	for i := 1; i <= 8; i++ {
		if strings.Count(r.stdout, fmt.Sprintf("12:00:0%d", i)) != 1 {
			t.Errorf("event %d was not printed exactly once:\n%s", i, r.stdout)
		}
	}
	if got := strings.Join(script.lastIDs, ","); got != ",,2,4" {
		t.Fatalf("Last-Event-ID per connection: %q (want a retry after the 503, then resumes after 2 and 4)", got)
	}
	h.api.handle("GET /api/v1/launches/{id}/events", (&sseScript{batches: [][]control.LaunchEvent{{stateEvent(1, "", "requested", ""), stateEvent(2, "requested", "cancelled", "Stopped")}}}).handler)
	r = h.run("", "events", id, "-f", "--json")
	lines := strings.Split(strings.TrimSpace(r.stdout), "\n")
	var last control.LaunchEvent
	if r.code != 0 || len(lines) != 2 || json.Unmarshal([]byte(lines[1]), &last) != nil || last.To != "cancelled" {
		t.Fatalf("--json -f prints one event per line: %v", r)
	}
}

func TestEventStreamFailuresAreBounded(t *testing.T) {
	h := newHarness(t)
	h.login("local:vic", "viewer")
	script := &sseScript{fail: 1000}
	h.api.handle("GET /api/v1/launches/{id}/events", script.handler)
	r := h.run("", "events", "x1", "-f")
	if r.code != ExitServer || !strings.Contains(r.stderr, "failed 9 times in a row") || script.conns.Load() != maxStreamFailures+1 {
		t.Fatalf("conns %d: %v", script.conns.Load(), r)
	}
	h.api.handle("GET /api/v1/launches/{id}/events", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		apiError(w, 404, "not_found", "The launch does not exist.")
	})
	if r = h.run("", "events", "x1", "-f"); r.code != ExitNotFound {
		t.Fatalf("a 404 is not retried: %v", r)
	}
}

func TestLaunchWaitFollowsThroughApproval(t *testing.T) {
	h := newHarness(t)
	h.login("local:lin", "launcher")
	pending := sampleLaunch("approval_pending")
	h.api.reply("POST /api/v1/launches", 200, map[string]any{"launch": pending, "plan": samplePlan()})
	script := &sseScript{batches: [][]control.LaunchEvent{
		{stateEvent(1, "", "requested", "Launch requested"), stateEvent(2, "requested", "approval_pending", "Approval required")},
		{stateEvent(3, "approval_pending", "approved", "Reviewed the plan"), stateEvent(4, "approved", "queued", "Queued"), stateEvent(5, "queued", "provisioning", ""), stateEvent(6, "provisioning", "running", "")},
	}}
	h.api.handle("GET /api/v1/launches/{id}/events", script.handler)
	running := pending
	running.State = "running"
	h.api.reply("GET /api/v1/launches/{id}", 200, map[string]any{"launch": running, "jobs": []any{}})
	r := h.run("", "launch", "--profile", "python-dev@3", "--image", imageRef, "--mode", "session", "--wait")
	if r.code != 0 || strings.Count(r.stdout, "Waiting for approval") != 1 || !strings.Contains(r.stdout, "agentgate approve "+pending.ID) || !strings.Contains(r.stdout, "-> running") {
		t.Fatalf("%v", r)
	}
	golden(t, h, "launch-wait", r.stdout)
}

func TestLaunchWaitTimeoutAndInterrupt(t *testing.T) {
	h := newHarness(t)
	h.login("local:lin", "launcher")
	pending := sampleLaunch("approval_pending")
	h.api.reply("POST /api/v1/launches", 200, map[string]any{"launch": pending, "plan": samplePlan()})
	h.api.reply("GET /api/v1/launches/{id}", 200, map[string]any{"launch": pending, "jobs": []any{}})
	script := &sseScript{hold: true, batches: [][]control.LaunchEvent{{stateEvent(1, "", "requested", ""), stateEvent(2, "requested", "approval_pending", "Approval required")}}}
	h.api.handle("GET /api/v1/launches/{id}/events", script.handler)
	r := h.run("", "launch", "--profile", "p@1", "--image", imageRef, "--wait", "--wait-timeout", "300ms", "--", "true")
	if r.code != ExitApprovalPending || !strings.Contains(r.stderr, "still waits for approval") {
		t.Fatalf("%v", r)
	}
	if len(h.api.requestsTo("POST /api/v1/launches/{id}/stop")) != 0 {
		t.Fatal("waiting must never stop the launch")
	}

	script2 := &sseScript{hold: true, batches: [][]control.LaunchEvent{{stateEvent(1, "", "requested", ""), stateEvent(2, "requested", "approval_pending", "")}}}
	h.api.handle("GET /api/v1/launches/{id}/events", script2.handler)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for script2.conns.Load() == 0 {
			time.Sleep(5 * time.Millisecond)
		}
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	r = h.runCtx(ctx, "", "launch", "--profile", "p@1", "--image", imageRef, "--wait", "--", "true")
	if r.code != ExitInterrupted || !strings.Contains(r.stderr, "keeps going") || !strings.Contains(r.stderr, pending.ID) {
		t.Fatalf("an interrupted wait says the launch continues and names it: %v", r)
	}
	if len(h.api.requestsTo("POST /api/v1/launches/{id}/stop")) != 0 {
		t.Fatal("an interrupted wait stopped the launch")
	}
}

func TestLaunchWaitEndsWithLaunchFailed(t *testing.T) {
	h := newHarness(t)
	h.login("local:lin", "launcher")
	queued := sampleLaunch("queued")
	h.api.reply("POST /api/v1/launches", 200, map[string]any{"launch": queued, "plan": samplePlan()})
	failed := queued
	failed.State, failed.TerminalReason, failed.EvidenceMissing = "failed", "The host lost contact", "lost_host"
	h.api.reply("GET /api/v1/launches/{id}", 200, map[string]any{"launch": failed, "jobs": []any{}})
	script := &sseScript{batches: [][]control.LaunchEvent{{stateEvent(4, "queued", "provisioning", ""), stateEvent(5, "provisioning", "failed", "The host lost contact")}}}
	h.api.handle("GET /api/v1/launches/{id}/events", script.handler)
	r := h.run("", "launch", "--profile", "p@1", "--image", imageRef, "--wait", "--", "true")
	if r.code != ExitLaunchFailed || !strings.Contains(r.stderr, "lost_host") {
		t.Fatalf("%v", r)
	}
}

func TestLogsFollowPollsUntilTheLaunchEnds(t *testing.T) {
	h := newHarness(t)
	h.login("local:vic", "viewer")
	var polls atomic.Int32
	h.api.handle("GET /api/v1/launches/{id}/logs", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		after := r.URL.Query().Get("after")
		items := []control.LogLine{}
		switch after {
		case "0":
			items = append(items, control.LogLine{Seq: 1, Stream: "stdout", Text: "one"})
		case "1":
			if polls.Add(1) > 2 {
				items = append(items, control.LogLine{Seq: 2, Stream: "stdout", Text: "two"})
			}
		}
		writeJSON(w, 200, map[string]any{"items": items, "bytes": 6, "limit_bytes": 1 << 20, "truncated": false})
	})
	var gets atomic.Int32
	h.api.handle("GET /api/v1/launches/{id}", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		l := sampleLaunch("running")
		if gets.Add(1) > 4 {
			l.State = "stopped"
		}
		writeJSON(w, 200, map[string]any{"launch": l, "jobs": []any{}})
	})
	r := h.run("", "logs", "x1", "-f")
	if r.code != 0 || r.stdout != "one\ntwo\n" || !strings.Contains(r.stderr, "stopped") {
		t.Fatalf("%v", r)
	}
}

func TestLogsFollowStreamsAndResumesWithLastEventID(t *testing.T) {
	h := newHarness(t)
	h.login("local:vic", "viewer")
	var conns atomic.Int32
	lastIDs := make(chan string, 4)
	line := func(w http.ResponseWriter, seq int, text string) {
		raw, _ := json.Marshal(control.LogLine{Seq: seq, Time: "2026-10-24T12:00:00Z", Stream: "stdout", Text: text})
		fmt.Fprintf(w, "id: %d\nevent: log\ndata: %s\n\n", seq, raw)
	}
	h.api.handle("GET /api/v1/launches/{id}/logs", func(w http.ResponseWriter, r *http.Request, _ []byte, _ []string) {
		if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			t.Error("logs -f polled although the service streams")
			writeJSON(w, 200, map[string]any{"items": []any{}})
			return
		}
		lastIDs <- r.Header.Get("Last-Event-ID")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		fmt.Fprint(w, "event: ready\ndata: {\"after\":0}\n\n")
		if conns.Add(1) == 1 {
			// The first connection drops after two lines.
			line(w, 1, "one")
			line(w, 2, "two\x1b[31m")
			return
		}
		line(w, 2, "two again")
		line(w, 3, "three")
		fmt.Fprint(w, ": keepalive\n\nevent: end\ndata: {\"state\":\"stopped\",\"last_seq\":3,\"truncated\":true}\n\n")
	})
	r := h.run("", "logs", "x1", "-f")
	if r.code != 0 || r.stdout != "one\ntwo[31m\nthree\n" || !strings.Contains(r.stderr, "Launch x1 stopped") || !strings.Contains(r.stderr, "1 MiB") {
		t.Fatalf("%v", r)
	}
	if first, second := <-lastIDs, <-lastIDs; first != "" || second != "2" {
		t.Fatalf("Last-Event-ID %q then %q", first, second)
	}
	if len(h.api.requestsTo("GET /api/v1/launches/{id}")) != 0 {
		t.Fatal("a streamed follow polled the launch")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

type sseMessage struct {
	id, event, data string
	comment         bool
}

// sseReader reads Server-Sent Events from a stream, one message at a time.
type sseReader struct {
	r *bufio.Reader
}

func (s *sseReader) next(t *testing.T) (sseMessage, error) {
	t.Helper()
	var m sseMessage
	data := []string{}
	for {
		line, err := s.r.ReadString('\n')
		if err != nil {
			return m, err
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case line == "":
			if m.event != "" || len(data) > 0 || m.comment {
				m.data = strings.Join(data, "\n")
				return m, nil
			}
		case strings.HasPrefix(line, ":"):
			m.comment = true
		case strings.HasPrefix(line, "id: "):
			m.id = strings.TrimPrefix(line, "id: ")
		case strings.HasPrefix(line, "event: "):
			m.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			data = append(data, strings.TrimPrefix(line, "data: "))
		case strings.HasPrefix(line, "retry: "):
		default:
			t.Fatalf("an unexpected stream line %q", line)
		}
	}
}

func openLogStream(t *testing.T, f *provFixture, base, path, token, lastID string) (*http.Response, *sseReader) {
	t.Helper()
	req, _ := http.NewRequest("GET", base+path, nil)
	req.Header.Set("Accept", "text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := f.http.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp, &sseReader{r: bufio.NewReader(resp.Body)}
}

func logEvent(seq uint32, f *provFixture, text string) hostproto.Event {
	e := ev(seq, f, hostproto.EventLog)
	e.Stream, e.Message = "stdout", text
	return e
}

func streamCount(f *provFixture) int {
	f.srv.mu.Lock()
	defer f.srv.mu.Unlock()
	return len(f.srv.clients)
}

func TestLogStreamResumesEscapesFollowsAndEnds(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	f.profile("dev", false)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	job := h.poll()[0]
	running := ev(1, f, hostproto.EventState)
	running.State = StateRunning
	hostile := "line two\n\nevent: forged\ndata: {\"seq\":99}\r\x1b[31m end"
	must(h.events(job.ID, running, logEvent(2, f, "line one"), logEvent(3, f, hostile), logEvent(4, f, "line three")))
	viewer := f.token(f.viewer(), "viewer")
	path := "/api/v1/launches/" + l.ID + "/logs"

	resp, s := openLogStream(t, f, f.http.URL, path, viewer, "")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if m, err := s.next(t); err != nil || m.event != "ready" {
		t.Fatalf("first message %+v %v", m, err)
	}
	texts := []string{}
	for i := 1; i <= 3; i++ {
		m, err := s.next(t)
		if err != nil || m.event != "log" || m.id != fmt.Sprint(i) || strings.Contains(m.data, "\n") {
			t.Fatalf("log %d: %+v %v", i, m, err)
		}
		var line LogLine
		if err = json.Unmarshal([]byte(m.data), &line); err != nil || line.Seq != i || line.Stream != "stdout" {
			t.Fatalf("log %d data %q: %v", i, m.data, err)
		}
		texts = append(texts, line.Text)
	}
	if texts[1] != hostile {
		t.Fatalf("the hostile line changed: %q", texts[1])
	}
	// More output reaches the open stream.
	must(h.events(job.ID, logEvent(5, f, "line four")))
	if m, err := s.next(t); err != nil || m.id != "4" || !strings.Contains(m.data, "line four") {
		t.Fatalf("live line %+v %v", m, err)
	}
	resp.Body.Close()

	// Resume after a disconnect: Last-Event-ID, and ?after= which wins.
	for _, c := range []struct{ query, lastID, first string }{{"", "2", "3"}, {"?after=1", "3", "2"}} {
		_, s := openLogStream(t, f, f.http.URL, path+c.query, viewer, c.lastID)
		s.next(t)
		if m, err := s.next(t); err != nil || m.id != c.first {
			t.Fatalf("resume %+v: %+v %v", c, m, err)
		}
	}
	// Keepalives while nothing happens.
	f.srv.StreamHeartbeat = 30 * time.Millisecond
	_, s = openLogStream(t, f, f.http.URL, path, viewer, "4")
	s.next(t)
	if m, err := s.next(t); err != nil || !m.comment {
		t.Fatalf("keepalive %+v %v", m, err)
	}
	// The launch ends: the stream sends the rest, an end event, and closes.
	must(f.s.StopLaunch(f.launcher(), l.ID, DecisionInput{Reason: "Done"}))
	stop := h.poll(l.ID)[0]
	result := ev(1, f, hostproto.EventResult)
	result.Result = &hostproto.JobResult{Status: hostproto.ResultSucceeded, Reason: "stopped", Receipt: h.receipt(stop, true)}
	must(h.events(stop.ID, result))
	var end sseMessage
	for {
		m, err := s.next(t)
		if err != nil {
			t.Fatalf("the stream ended without an end event: %v", err)
		}
		if m.event == "end" {
			end = m
			break
		}
	}
	if !strings.Contains(end.data, `"state":"stopped"`) || !strings.Contains(end.data, `"last_seq":4`) {
		t.Fatalf("end %+v", end)
	}
	if _, err := s.next(t); err != io.EOF {
		t.Fatalf("the stream stayed open after the end event: %v", err)
	}
	// A stream of an ended launch sends its lines and ends at once.
	_, s = openLogStream(t, f, f.http.URL, path, viewer, "")
	got := 0
	for {
		m, err := s.next(t)
		if err != nil {
			t.Fatal(err)
		}
		if m.event == "log" {
			got++
		}
		if m.event == "end" {
			break
		}
	}
	if got != 4 {
		t.Fatalf("%d lines from an ended launch", got)
	}
	// Refusals come back as JSON errors before any stream starts.
	for _, c := range []struct {
		name, path, token, lastID string
		status                    int
	}{
		{"no credential", path, "", "", 401},
		{"unknown launch", "/api/v1/launches/" + strings.Repeat("0", 32) + "/logs", viewer, "", 404},
		{"malformed resume", path, viewer, "seven", 422},
		{"negative resume", path + "?after=-1", viewer, "", 422},
		{"huge resume", path, viewer, "99999999999", 422},
	} {
		resp, _ := openLogStream(t, f, f.http.URL, c.path, c.token, c.lastID)
		if resp.StatusCode != c.status || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			t.Fatalf("%s: %d %s", c.name, resp.StatusCode, resp.Header.Get("Content-Type"))
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for streamCount(f) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := streamCount(f); n != 0 {
		t.Fatalf("%d streams stayed registered", n)
	}
}

// smallBuffers gives every accepted connection a tiny send buffer, so a
// client that stops reading blocks the server's writes almost at once.
type smallBuffers struct{ net.Listener }

func (l smallBuffers) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if tc, ok := c.(*net.TCPConn); ok {
		tc.SetWriteBuffer(4096)
	}
	return c, err
}

func TestLogStreamToASlowClientStaysBoundedAndEnds(t *testing.T) {
	f := newProv(t)
	h, _ := f.enrolledTarget()
	f.profile("dev", false)
	l, _ := f.launch(f.launcher(), specMap("dev"))
	job := h.poll()[0]
	running := ev(1, f, hostproto.EventState)
	running.State = StateRunning
	must(h.events(job.ID, running))
	// The service's log bound: about 1 MiB in 5000 lines.
	const lines = 5000
	tx, _ := f.s.DB.Begin()
	text := strings.Repeat("x", 200)
	for i := 1; i <= lines; i++ {
		if _, err := tx.Exec("INSERT INTO launch_logs VALUES(?,?,?,?,?)", l.ID, i, time.Now().UnixMilli(), "stdout", text); err != nil {
			t.Fatal(err)
		}
	}
	tx.Exec("UPDATE launches SET log_seq=?,log_bytes=? WHERE id=?", lines, lines*200, l.ID)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	f.srv.StreamWriteTimeout = 300 * time.Millisecond
	srv := httptest.NewUnstartedServer(f.srv.Handler())
	srv.Listener = smallBuffers{srv.Listener}
	srv.Start()
	defer srv.Close()
	viewer := f.token(f.viewer(), "viewer")
	conn, err := net.Dial("tcp", srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.(*net.TCPConn).SetReadBuffer(4096)
	fmt.Fprintf(conn, "GET /api/v1/launches/%s/logs HTTP/1.1\r\nHost: test\r\nAccept: text/event-stream\r\nAuthorization: Bearer %s\r\n\r\n", l.ID, viewer)
	// Read the headers and a little output, then stop reading.
	head := make([]byte, 2048)
	if _, err = io.ReadFull(conn, head); err != nil || !strings.Contains(string(head), "200 OK") {
		t.Fatalf("%q %v", head, err)
	}
	started := time.Now()
	for streamCount(f) != 0 && time.Since(started) < 10*time.Second {
		time.Sleep(20 * time.Millisecond)
	}
	if streamCount(f) != 0 {
		t.Fatal("the stream to a client that stopped reading never ended")
	}
	fetched, delivered := f.srv.logLinesFetched.Load(), f.srv.logLinesDelivered.Load()
	t.Logf("a stalled client: %d lines fetched, %d written, stream ended after %v", fetched, delivered, time.Since(started).Round(time.Millisecond))
	if fetched-delivered > logStreamBatch || fetched >= lines {
		t.Fatalf("the stream read ahead of the client: %d fetched, %d written of %d", fetched, delivered, lines)
	}
	// What the client receives when it drains is a clean prefix of the output.
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	rest, _ := io.ReadAll(conn)
	all := string(head) + string(rest)
	if strings.Contains(all, fmt.Sprintf("id: %d\n", lines)) {
		t.Fatal("a stalled client received every line")
	}
	if !strings.Contains(all, "event: ready") || !strings.Contains(all, "id: 1\nevent: log") {
		t.Fatalf("the prefix is not the stream: %.200q", all)
	}
	// A normal client reading the same output gets every line.
	f.srv.StreamWriteTimeout = 0
	_, s := openLogStream(t, f, f.http.URL, "/api/v1/launches/"+l.ID+"/logs", viewer, "")
	s.next(t)
	for i := 1; i <= lines; i++ {
		m, err := s.next(t)
		if err != nil || m.id != fmt.Sprint(i) {
			t.Fatalf("line %d: %+v %v", i, m, err)
		}
	}
}

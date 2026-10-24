// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func readStatsFile(t *testing.T, path string) *StatsDocument {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := ParseStats(raw)
	if err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	return doc
}

func TestStatsFileIsWrittenWhenServingAndIsPrivate(t *testing.T) {
	e := newEnv(t)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(e.cfg.StatsPath); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no stats file")
		}
		time.Sleep(20 * time.Millisecond)
	}
	doc := readStatsFile(t, e.cfg.StatsPath)
	if doc.State != "running" || doc.LaunchID != "lch-0001" || doc.TargetID != "local" || len(doc.ConfigSHA256) != 64 ||
		doc.Listen != "tcp:10.99.0.2:8443" {
		t.Fatalf("%+v", doc)
	}
	fi, _ := os.Stat(e.cfg.StatsPath)
	if fi.Mode().Perm() != 0o600 {
		t.Fatal(fi.Mode())
	}
}

func TestBrokerExitsAtTheDeadline(t *testing.T) {
	e := newEnv(t, withDeadline(2500*time.Millisecond))
	e.setHandler(func(w http.ResponseWriter, r *http.Request) {
		for {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
				io.WriteString(w, "data: tick\n\n")
				w.(http.Flusher).Flush()
			}
		}
	})
	resp := e.do("POST", "/anthropic/v1/messages", strings.NewReader("{}"))
	_, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == nil {
		t.Fatal("a stream open at the deadline must be cut, not completed")
	}
	select {
	case <-e.done:
	case <-time.After(5 * time.Second):
		t.Fatal("broker kept running past its deadline")
	}
	if e.reason != StopDeadline || e.serveErr != nil {
		t.Fatal(e.reason, e.serveErr)
	}
	doc := readStatsFile(t, e.cfg.StatsPath)
	if doc.State != "stopped" || doc.StopReason != StopDeadline || !doc.Complete {
		t.Fatalf("%+v", doc)
	}
	if c, err := net.DialTimeout("tcp", e.addr, time.Second); err == nil {
		c.Close()
		t.Fatal("listener still accepts after the deadline")
	}
	// The secret arena is wiped once the broker stops.
	if e.srv.routes["anthropic"].cred.value != "" {
		t.Fatal("credential not cleared")
	}
}

func TestStopSignalLetsInFlightRequestsFinish(t *testing.T) {
	e := newEnv(t)
	entered := make(chan struct{})
	e.setHandler(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		time.Sleep(300 * time.Millisecond)
		io.WriteString(w, "done")
	})
	result := make(chan string, 1)
	go func() {
		resp := e.do("POST", "/anthropic/v1/messages", strings.NewReader("{}"))
		result <- e.text(resp)
	}()
	<-entered
	e.cancel()
	if got := <-result; got != "done" {
		t.Fatal(got)
	}
	<-e.done
	if e.reason != StopSignal || e.serveErr != nil {
		t.Fatal(e.reason, e.serveErr)
	}
	doc := readStatsFile(t, e.cfg.StatsPath)
	if doc.State != "stopped" || doc.StopReason != StopSignal || !doc.Complete || doc.Routes["anthropic"].Status["2xx"] != 1 {
		t.Fatalf("%+v", doc)
	}
}

func TestConcurrentRequests(t *testing.T) {
	e := newEnv(t, withLimits(map[string]any{"max_connections": 64, "max_concurrent_requests": 64, "requests_per_minute": 60000,
		"burst": 1000, "max_upstream_connections": 32}), withSecondRoute())
	e.setHandler(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(10 * time.Millisecond)
		io.WriteString(w, r.Host)
	})
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path, want := "/anthropic/v1/models", "api.example.test"
			if i%2 == 1 {
				path, want = "/beta/x", "beta.example.test"
			}
			resp := e.do("GET", path, nil)
			if body := e.text(resp); resp.StatusCode != 200 || body != want {
				errs <- body
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	st := e.stats()
	if st.Routes["anthropic"].Forwarded != 32 || st.Routes["beta"].Forwarded != 32 || st.Requests.Total != 64 {
		t.Fatalf("%+v", st.Requests)
	}
}

func TestDenialRecordsAreBounded(t *testing.T) {
	e := newEnv(t, withLimits(map[string]any{"max_denial_records": 3}))
	for i := 0; i < 5; i++ {
		e.text(e.do("POST", "/anthropic/v1/files/secret-name?token=abc", nil))
	}
	st := e.stats()
	if len(st.Denials) != 3 || !st.DenialsTruncated || st.Denied[reasonPathNotAllowed] != 5 {
		t.Fatalf("%+v", st)
	}
	if st.Denials[0].Path != "/anthropic/v1" || st.Denials[0].Method != "POST" || st.Denials[0].Host != "10.99.0.2:8443" {
		t.Fatalf("%+v", st.Denials[0])
	}
	raw, _ := e.srv.Snapshot()
	if strings.Contains(string(raw), "token=abc") || strings.Contains(string(raw), "secret-name") {
		t.Fatal("denial records hold query or deep path data")
	}
}

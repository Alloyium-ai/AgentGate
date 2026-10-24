// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package broker

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestInjectsCredentialAndStripsAgentHeaders(t *testing.T) {
	e := newEnv(t)
	resp := e.do("POST", "/anthropic/v1/messages", strings.NewReader(`{"model":"m"}`),
		"Authorization", "Bearer agent-supplied-token", "X-Api-Key", "agent-key", "Cookie", "session=agent",
		"Proxy-Authorization", "Basic agent", "X-Forwarded-For", "10.0.0.9", "Forwarded", "for=10.0.0.9",
		"Anthropic-Version", "client-chosen", "Anthropic-Beta", "tools-2024", "Content-Type", "application/json",
		"Te", "trailers", "Connection", "X-Drop-Me", "X-Drop-Me", "1")
	body := e.text(resp)
	if resp.StatusCode != 200 || body != "ok" {
		t.Fatalf("%d %q", resp.StatusCode, body)
	}
	mustNotContainSecret(t, "response body", body)
	got := e.requests()
	if len(got) != 1 {
		t.Fatalf("%d upstream requests", len(got))
	}
	r := got[0]
	if r.Method != "POST" || r.Path != "/v1/messages" || r.Host != "api.example.test" || r.SNI != "api.example.test" {
		t.Fatalf("upstream saw %+v", r)
	}
	if v := r.Header.Values("X-Api-Key"); len(v) != 1 || v[0] != testSecret {
		t.Fatalf("injected credential missing or duplicated (%d values)", len(v))
	}
	if v := r.Header.Values("Anthropic-Version"); len(v) != 1 || v[0] != "2023-06-01" {
		t.Fatalf("extra header %v", v)
	}
	for _, h := range []string{"Authorization", "Cookie", "Proxy-Authorization", "X-Forwarded-For", "Forwarded", "Te", "X-Drop-Me", "Via", "X-Real-Ip"} {
		if r.Header.Get(h) != "" {
			t.Errorf("upstream received %s", h)
		}
	}
	if r.Header.Get("Anthropic-Beta") != "tools-2024" || r.Header.Get("Content-Type") != "application/json" ||
		r.Header.Get("Accept-Encoding") != "identity" {
		t.Fatalf("passthrough headers: %v", r.Header)
	}
	if string(r.Body) != `{"model":"m"}` || r.ContentLength != 13 || len(r.TransferEncoding) != 0 {
		t.Fatalf("framing: cl=%d te=%v", r.ContentLength, r.TransferEncoding)
	}
	if !resp.Close {
		t.Fatal("broker must serve one request per connection")
	}
	st := e.stats()
	rs := st.Routes["anthropic"]
	if rs.Requests != 1 || rs.Forwarded != 1 || rs.Status["2xx"] != 1 || rs.BytesIn != 13 || rs.BytesOut != 2 || rs.Upstream != "api.example.test:443" {
		t.Fatalf("stats %+v", rs)
	}
}

func TestBearerAndBasicSchemes(t *testing.T) {
	e := newEnv(t, withCredential(map[string]any{"header": "authorization", "scheme": "Bearer"}))
	e.text(e.do("POST", "/anthropic/v1/messages", strings.NewReader("{}"), "Authorization", "Bearer agent"))
	if got := e.requests()[0].Header.Values("Authorization"); len(got) != 1 || got[0] != "Bearer "+testSecret {
		t.Fatal("bearer injection")
	}
	b := newEnv(t, withCredential(map[string]any{"header": "authorization", "scheme": "Basic", "username": "x-access-token",
		"extra_headers": map[string]any{"x-github-api-version": "2022-11-28"}}))
	b.text(b.do("POST", "/anthropic/v1/messages", strings.NewReader("{}")))
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+testSecret))
	r := b.requests()[0]
	if got := r.Header.Values("Authorization"); len(got) != 1 || got[0] != want || r.Header.Get("X-Github-Api-Version") != "2022-11-28" {
		t.Fatal("basic injection")
	}
}

func TestPolicyDenialsNeverReachTheUpstream(t *testing.T) {
	e := newEnv(t)
	cases := []struct {
		method, path string
		status       int
		reason       string
		headers      []string
	}{
		{"GET", "/anthropic/v1/messages", 405, reasonMethodNotAllowed, nil},
		{"POST", "/anthropic/v1/files", 403, reasonPathNotAllowed, nil},
		{"POST", "/anthropic/v1/messages/batches", 403, reasonPathNotAllowed, nil},
		{"GET", "/anthropic/v1/modelsx", 403, reasonPathNotAllowed, nil},
		{"GET", "/other/v1/models", 404, reasonRouteUnknown, nil},
		{"GET", "/", 404, reasonRouteUnknown, nil},
		{"GET", "/anthropic/v1/models/%2e%2e/admin", 400, reasonPathInvalid, nil},
		{"GET", "/anthropic/v1/models%2fadmin", 400, reasonPathInvalid, nil},
		{"GET", "/anthropic//v1/models", 400, reasonPathInvalid, nil},
		{"GET", "/anthropic/v1/models", 400, reasonUpgrade, []string{"Connection", "Upgrade", "Upgrade", "websocket", "Sec-Websocket-Key", "x"}},
		{"GET", "/anthropic/v1/models", 400, reasonUpgrade, []string{"Upgrade", "h2c", "Http2-Settings", "AAMAAABkAAQAAP__"}},
	}
	for _, c := range cases {
		resp := e.do(c.method, c.path, nil, c.headers...)
		body := e.text(resp)
		if resp.StatusCode != c.status || !strings.Contains(body, `"reason":"`+c.reason+`"`) {
			t.Errorf("%s %s: %d %s", c.method, c.path, resp.StatusCode, body)
		}
	}
	// Host mismatch: a client that treats the broker as a general proxy.
	req, _ := http.NewRequest("GET", "http://"+e.addr+"/anthropic/v1/models", nil)
	req.Host = "api.example.test"
	resp, err := e.client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if body := e.text(resp); resp.StatusCode != http.StatusMisdirectedRequest || !strings.Contains(body, reasonHostMismatch) {
		t.Fatalf("host mismatch: %d", resp.StatusCode)
	}
	for _, raw := range []struct{ payload, reason string }{
		{"CONNECT api.example.test:443 HTTP/1.1\r\nHost: api.example.test:443\r\n\r\n", reasonConnect},
		{"GET http://evil.example/anthropic/v1/models HTTP/1.1\r\nHost: " + e.authority + "\r\n\r\n", reasonAbsoluteForm},
		{"GET https://api.example.test/anthropic/v1/models HTTP/1.1\r\nHost: " + e.authority + "\r\n\r\n", reasonAbsoluteForm},
		{"OPTIONS * HTTP/1.1\r\nHost: " + e.authority + "\r\n\r\n", reasonAbsoluteForm},
		{"TRACE /anthropic/v1/models HTTP/1.1\r\nHost: " + e.authority + "\r\n\r\n", reasonMethodNotAllowed},
		{"GET /anthropic/v1/models?x=1#frag HTTP/1.1\r\nHost: " + e.authority + "\r\n\r\n", ""},
	} {
		out := e.raw(raw.payload)
		if !strings.HasPrefix(out, "HTTP/1.1 4") || (raw.reason != "" && !strings.Contains(out, raw.reason)) {
			t.Errorf("%q: %q", raw.payload, out)
		}
	}
	if n := len(e.requests()); n != 0 {
		t.Fatalf("%d denied requests reached the upstream", n)
	}
	st := e.stats()
	if st.Denied[reasonPathNotAllowed] != 3 || st.Denied[reasonUpgrade] != 2 || st.Denied[reasonHostMismatch] != 1 || st.Requests.Forwarded != 0 {
		t.Fatalf("denials %v", st.Denied)
	}
	for _, d := range st.Denials {
		if strings.ContainsAny(d.Path, "?#%") || len(d.Path) > 64 || strings.Count(d.Path, "/") > 2 {
			t.Fatalf("denial record holds more than a path prefix: %+v", d)
		}
	}
}

func TestSmugglingShapesOverTheWire(t *testing.T) {
	e := newEnv(t)
	head := "POST /anthropic/v1/messages HTTP/1.1\r\nHost: " + e.authority + "\r\n"
	shapes := []string{
		head + "Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
		head + "Content-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
		head + "Transfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
		head + "Transfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n",
		head + "Transfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n0\r\n\r\n",
		head + "Content-Length: 2\r\nX-A: b\r\n c\r\n\r\n{}",
		head + "Content-Length: 2\n\n{}",
		head + "Content-Length: 2\r\nX-A: b\rc\r\n\r\n{}",
		head + "Content-Length: 2, 2\r\n\r\n{}",
		head + "Content-Length: 2\r\nHost: other\r\n\r\n{}",
		head + "Content-Length: 2\r\nX-A: \x00\r\n\r\n{}",
		strings.Replace(head, "HTTP/1.1", "HTTP/1.0", 1) + "Content-Length: 2\r\n\r\n{}",
		head + "Transfer-Encoding: chunked\r\n\r\nzz\r\n{}\r\n0\r\n\r\n",
		head + "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n",
		head + "Transfer-Encoding: chunked\r\n\r\n2;" + strings.Repeat("x", 8192) + "\r\n{}\r\n0\r\n\r\n",
		head + "Content-Length: 10\r\n\r\n{}",
		head + "Transfer-Encoding: chunked\r\nTrailer: X-Smuggled\r\n\r\n2\r\n{}\r\n0\r\nX-Smuggled: 1\r\n\r\n",
		head + strings.Repeat("X-Many: a\r\n", 80) + "Content-Length: 2\r\n\r\n{}",
	}
	for _, s := range shapes {
		out := e.raw(s)
		if !strings.HasPrefix(out, "HTTP/1.1 4") && !strings.HasPrefix(out, "HTTP/1.0 4") && !strings.HasPrefix(out, "HTTP/1.1 5") {
			t.Errorf("%q: %q", s, out)
		}
	}
	if n := len(e.requests()); n != 0 {
		t.Fatalf("%d malformed requests reached the upstream", n)
	}
	// A pipelined second request after a valid one is never processed.
	out := e.rawConn(head+"Content-Length: 2\r\n\r\n{}"+"GET /anthropic/v1/models HTTP/1.1\r\nHost: "+e.authority+"\r\n\r\n", false)
	if !strings.HasPrefix(out, "HTTP/1.1 200") || strings.Count(out, "HTTP/1.1 ") != 1 {
		t.Fatalf("pipelining: %q", out)
	}
	if got := e.requests(); len(got) != 1 || got[0].Path != "/v1/messages" {
		t.Fatalf("pipelined request reached the upstream: %+v", got)
	}
	// A valid chunked body is buffered and re-framed with an exact length.
	out = e.rawConn(head+"Transfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n", false)
	if !strings.HasPrefix(out, "HTTP/1.1 200") {
		t.Fatalf("chunked: %q", out)
	}
	last := e.requests()[1]
	if string(last.Body) != "{}" || last.ContentLength != 2 || len(last.TransferEncoding) != 0 {
		t.Fatalf("re-framing: %+v", last)
	}
}

func TestStreamsServerSentEventsPromptly(t *testing.T) {
	e := newEnv(t)
	release := make(chan struct{})
	e.setHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		io.WriteString(w, "event: message_start\ndata: {}\n\n")
		fl.Flush()
		<-release
		io.WriteString(w, "event: delta\ndata: {\"text\":\"echo "+testSecret+"\"}\n\n")
		fl.Flush()
		io.WriteString(w, "event: message_stop\ndata: {}\n\n")
	})
	resp := e.do("POST", "/anthropic/v1/messages", strings.NewReader("{}"))
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal(resp.Header)
	}
	first := make([]byte, len("event: message_start\ndata: {}\n\n"))
	done := make(chan error, 1)
	go func() { _, err := io.ReadFull(resp.Body, first); done <- err }()
	select {
	case err := <-done:
		if err != nil || string(first) != "event: message_start\ndata: {}\n\n" {
			t.Fatalf("%v %q", err, first)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("first event was not flushed before the upstream finished")
	}
	close(release)
	rest := e.text(resp)
	if !strings.Contains(rest, "event: message_stop") || !strings.Contains(rest, "echo ****") {
		t.Fatalf("%q", rest)
	}
	mustNotContainSecret(t, "stream", rest)
	if e.stats().Routes["anthropic"].Redactions != 1 {
		t.Fatal("redaction not counted")
	}
}

func TestStreamIdleTimeoutAbortsTheResponse(t *testing.T) {
	e := newEnv(t, withLimits(map[string]any{"stream_idle_timeout_seconds": 1}))
	e.setHandler(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "data: 1\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	start := time.Now()
	resp := e.do("POST", "/anthropic/v1/messages", strings.NewReader("{}"))
	_, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == nil {
		t.Fatal("an idle stream must end with a connection error, not a clean end")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("idle timeout did not fire")
	}
	if e.stats().Routes["anthropic"].Errors[errKindStreamIdle] != 1 {
		t.Fatal(e.stats().Routes["anthropic"].Errors)
	}
}

func TestUpstreamTimeouts(t *testing.T) {
	e := newEnv(t, withLimits(map[string]any{"upstream_header_timeout_seconds": 1}))
	e.setHandler(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	resp := e.do("POST", "/anthropic/v1/messages", strings.NewReader("{}"))
	if body := e.text(resp); resp.StatusCode != http.StatusGatewayTimeout || !strings.Contains(body, "upstream_timeout") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	r := newEnv(t, withLimits(map[string]any{"request_timeout_seconds": 1}))
	r.setHandler(func(w http.ResponseWriter, req *http.Request) {
		io.WriteString(w, "data: 1\n\n")
		w.(http.Flusher).Flush()
		for i := 0; i < 50; i++ {
			select {
			case <-req.Context().Done():
				return
			case <-time.After(100 * time.Millisecond):
				io.WriteString(w, "data: tick\n\n")
				w.(http.Flusher).Flush()
			}
		}
	})
	start := time.Now()
	resp = r.do("POST", "/anthropic/v1/messages", strings.NewReader("{}"))
	_, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == nil || time.Since(start) > 4*time.Second {
		t.Fatalf("total request timeout: %v after %v", err, time.Since(start))
	}
	if r.stats().Routes["anthropic"].Errors[errKindTimeout] != 1 {
		t.Fatal(r.stats().Routes["anthropic"].Errors)
	}
}

func TestResponseAndRequestSizeLimits(t *testing.T) {
	e := newEnv(t, withLimits(map[string]any{"max_response_bytes": 1024, "max_request_bytes": 1024}))
	e.setHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/messages" {
			w.Header().Set("Content-Length", "4096")
			w.Write([]byte(strings.Repeat("a", 4096)))
			return
		}
		for i := 0; i < 8; i++ {
			w.Write([]byte(strings.Repeat("b", 512)))
			w.(http.Flusher).Flush()
		}
	})
	resp := e.do("POST", "/anthropic/v1/messages", strings.NewReader("{}"))
	if body := e.text(resp); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, errKindTooLarge) {
		t.Fatalf("declared oversize: %d", resp.StatusCode)
	}
	resp = e.do("GET", "/anthropic/v1/models", nil)
	got, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err == nil || len(got) > 1024 {
		t.Fatalf("streamed oversize: %d bytes, %v", len(got), err)
	}
	before := len(e.requests())
	resp = e.do("POST", "/anthropic/v1/messages", strings.NewReader(strings.Repeat("x", 2048)))
	if e.text(resp); resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatal(resp.StatusCode)
	}
	out := e.raw("POST /anthropic/v1/messages HTTP/1.1\r\nHost: " + e.authority + "\r\nTransfer-Encoding: chunked\r\n\r\n800\r\n" +
		strings.Repeat("y", 2048) + "\r\n0\r\n\r\n")
	if !strings.HasPrefix(out, "HTTP/1.1 413") {
		t.Fatalf("chunked oversize: %q", out)
	}
	if len(e.requests()) != before {
		t.Fatal("an oversized request reached the upstream")
	}
	if e.stats().Routes["anthropic"].Errors[errKindTooLarge] != 2 {
		t.Fatal(e.stats().Routes["anthropic"].Errors)
	}
}

func TestRateConcurrencyAndConnectionLimits(t *testing.T) {
	e := newEnv(t, withLimits(map[string]any{"requests_per_minute": 1, "burst": 2}))
	codes := []int{}
	for i := 0; i < 3; i++ {
		resp := e.do("GET", "/anthropic/v1/models", nil)
		e.text(resp)
		codes = append(codes, resp.StatusCode)
	}
	if fmt.Sprint(codes) != "[200 200 429]" {
		t.Fatal(codes)
	}

	c := newEnv(t, withLimits(map[string]any{"max_concurrent_requests": 1, "max_connections": 3}))
	hold := make(chan struct{})
	entered := make(chan struct{}, 1)
	c.setHandler(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-hold
	})
	first := make(chan int, 1)
	go func() {
		resp := c.do("GET", "/anthropic/v1/models", nil)
		c.text(resp)
		first <- resp.StatusCode
	}()
	<-entered
	resp := c.do("GET", "/anthropic/v1/models", nil)
	if c.text(resp); resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatal(resp.StatusCode)
	}
	close(hold)
	if code := <-first; code != 200 {
		t.Fatal(code)
	}

	l := newEnv(t, withLimits(map[string]any{"max_concurrent_requests": 1, "max_connections": 1, "header_timeout_seconds": 3}))
	idle := l.dialRaw()
	defer idle.Close()
	time.Sleep(100 * time.Millisecond)
	extra := l.dialRaw()
	extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, err := extra.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("connection over the limit was served")
	}
	extra.Close()
	if l.stats().Connections.Rejected < 1 {
		t.Fatal(l.stats().Connections)
	}
}

func TestBodyAndHeaderTimeouts(t *testing.T) {
	e := newEnv(t, withLimits(map[string]any{"body_timeout_seconds": 1, "header_timeout_seconds": 1}))
	start := time.Now()
	c := e.dialRaw()
	defer c.Close()
	io.WriteString(c, "POST /anthropic/v1/messages HTTP/1.1\r\nHost: "+e.authority+"\r\nContent-Length: 10\r\n\r\n{}")
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	out, _ := io.ReadAll(c)
	if !strings.HasPrefix(string(out), "HTTP/1.1 408") || time.Since(start) > 4*time.Second {
		t.Fatalf("body timeout: %q", out)
	}
	h := e.dialRaw()
	defer h.Close()
	io.WriteString(h, "POST /anthropic/v1/messages HTTP/1.1\r\nHost: ")
	h.SetReadDeadline(time.Now().Add(5 * time.Second))
	start = time.Now()
	io.ReadAll(h)
	if time.Since(start) > 4*time.Second {
		t.Fatal("header timeout did not close the connection")
	}
	if len(e.requests()) != 0 {
		t.Fatal("a timed-out request reached the upstream")
	}
}

func TestResponseHygiene(t *testing.T) {
	e := newEnv(t)
	b64 := base64.StdEncoding.EncodeToString([]byte(testSecret))
	e.setHandler(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Echo", "key="+testSecret)
		h.Set("X-Echo-B64", b64)
		h.Set("Set-Cookie", "upstream=1")
		h.Set("Alt-Svc", `h3=":443"`)
		h.Set("Connection", "X-Hop")
		h.Set("X-Hop", "1")
		h.Set("X-Request-Id", "req-1")
		h.Set("Content-Length", fmt.Sprint(len(testSecret)+len(b64)+1))
		io.WriteString(w, testSecret+" "+b64)
	})
	resp := e.do("GET", "/anthropic/v1/models", nil)
	body := e.text(resp)
	for _, h := range []string{"X-Echo", "X-Echo-B64", "Set-Cookie", "Alt-Svc", "X-Hop"} {
		if resp.Header.Get(h) != "" {
			t.Errorf("returned %s", h)
		}
	}
	if resp.Header.Get("X-Request-Id") != "req-1" {
		t.Fatal("ordinary header dropped")
	}
	if len(body) != len(testSecret)+len(b64)+1 || strings.Trim(strings.ReplaceAll(body, " ", ""), "*") != "" {
		t.Fatalf("body not masked to the same length: %q", body)
	}
	for k, vv := range resp.Header {
		mustNotContainSecret(t, "response header "+k, strings.Join(vv, ","))
	}
	if e.stats().Routes["anthropic"].Redactions != 4 {
		t.Fatal(e.stats().Routes["anthropic"].Redactions)
	}
	e.setHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.Write([]byte{0x1f, 0x8b})
	})
	resp = e.do("GET", "/anthropic/v1/models", nil)
	if body := e.text(resp); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, errKindEncoded) {
		t.Fatalf("encoded response: %d", resp.StatusCode)
	}
}

func TestRedirectsAreReturnedNotFollowed(t *testing.T) {
	e := newEnv(t)
	e.setHandler(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models/meta" {
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
			return
		}
		http.Redirect(w, r, "https://api.example.test/v1/models/other?page=2", http.StatusMovedPermanently)
	})
	resp := e.do("GET", "/anthropic/v1/models/meta", nil)
	e.text(resp)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "http://169.254.169.254/latest/meta-data/" {
		t.Fatalf("%d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp = e.do("GET", "/anthropic/v1/models/moved", nil)
	e.text(resp)
	if resp.Header.Get("Location") != "/anthropic/v1/models/other?page=2" {
		t.Fatal(resp.Header.Get("Location"))
	}
	if len(e.requests()) != 2 {
		t.Fatal("broker followed a redirect")
	}
	for _, a := range e.dialed {
		if a.Addr() != fakePublic {
			t.Fatalf("broker dialed %v", a)
		}
	}
}

func TestUpstreamResolvingToPrivateAddressesIsRefused(t *testing.T) {
	e := newEnv(t, withLimits(map[string]any{"dns_cache_seconds": 0}))
	e.resolver.set("api.example.test", []string{fakePublic.String()}, []string{"169.254.169.254"})
	e.setHandler(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close") // force a new upstream connection next time
		io.WriteString(w, "ok")
	})
	resp := e.do("GET", "/anthropic/v1/models", nil)
	if e.text(resp); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	resp = e.do("GET", "/anthropic/v1/models", nil)
	if body := e.text(resp); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "upstream_address_denied") {
		t.Fatalf("rebinding: %d %s", resp.StatusCode, body)
	}
	if len(e.dialed) != 1 {
		t.Fatalf("dialed %v", e.dialed)
	}
	if e.stats().Routes["anthropic"].Errors[errKindAddressDenied] != 1 {
		t.Fatal(e.stats().Routes["anthropic"].Errors)
	}
}

func TestTLSVerificationAndPinning(t *testing.T) {
	e := newEnv(t)
	wrong, _ := e.ca.leaf(t, "other.example.test")
	e.upstream.TLS.Certificates = []tls.Certificate{wrong}
	resp := e.do("GET", "/anthropic/v1/models", nil)
	if body := e.text(resp); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "upstream_tls") {
		t.Fatalf("hostname mismatch: %d %s", resp.StatusCode, body)
	}
	other := newTestCA(t)
	untrusted, _ := other.leaf(t, "api.example.test")
	e.upstream.TLS.Certificates = []tls.Certificate{untrusted}
	resp = e.do("GET", "/anthropic/v1/models", nil)
	if body := e.text(resp); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "upstream_tls") {
		t.Fatalf("untrusted CA: %d %s", resp.StatusCode, body)
	}
	if len(e.requests()) != 0 {
		t.Fatal("request sent over an unverified connection")
	}

	p := newEnv(t, withUpstream(map[string]any{"pin_spki_sha256": []any{base64.StdEncoding.EncodeToString(make([]byte, 32))}}))
	resp = p.do("GET", "/anthropic/v1/models", nil)
	if body := p.text(resp); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "upstream_tls") {
		t.Fatalf("pin mismatch: %d %s", resp.StatusCode, body)
	}
	if len(p.requests()) != 0 {
		t.Fatal("request sent despite a pin mismatch")
	}
}

func TestPinnedUpstreamAndPathForwarding(t *testing.T) {
	e := newEnv(t, withCAPin(), withUpstream(map[string]any{"base_path": "/api"}), withRules(allRule()))
	resp := e.do("GET", "/anthropic/v1/models/a%20b:list?x=1&y=%2F&z", nil)
	if e.text(resp); resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	r := e.requests()[0]
	if r.Path != "/api/v1/models/a b:list" || r.RequestURI != "/api/v1/models/a%20b:list?x=1&y=%2F&z" {
		t.Fatalf("%+v", r)
	}
	resp = e.do("POST", "/anthropic", strings.NewReader("{}"))
	if e.text(resp); resp.StatusCode != 200 || e.requests()[1].Path != "/api/" {
		t.Fatal(e.requests()[1].Path)
	}
}

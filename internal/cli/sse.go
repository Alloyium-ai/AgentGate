// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Server-Sent Events from GET /launches/{id}/events. Each event's id is its
// sequence number. The client resumes after a disconnect with Last-Event-ID
// and drops anything it already saw, so a reconnect neither loses nor
// repeats an event. Lines, events and reconnects are all bounded.
const (
	maxSSELine        = 1 << 20
	maxSSEData        = 1 << 20
	sseIdleTimeout    = 45 * time.Second // the service sends a keepalive every 15 s
	maxStreamFailures = 8
	streamBackoffCap  = 10 * time.Second
	pollFallbackAfter = 3
	minStreamLife     = 2 * time.Second
)

var errStreamIdle = errors.New("the event stream went quiet")

type sseEvent struct {
	id    string
	event string
	data  []byte
}

// stream opens one event stream and calls fn per event until the service
// closes it, it goes idle, ctx ends, or fn asks to stop.
func (c *Client) stream(ctx context.Context, path string, lastID string, idle time.Duration, fn func(sseEvent) (bool, error)) (bool, error) {
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	r := request{method: "GET", path: path, accept: "text/event-stream"}
	req, err := c.newHTTPRequest(sctx, r)
	if err != nil {
		return false, err
	}
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	headerTimer := time.AfterFunc(c.timeout, cancel)
	resp, err := c.hc.Do(req)
	headerTimer.Stop()
	if err != nil {
		return false, classifyTransport(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return false, decodeAPIError(&response{status: resp.StatusCode, header: resp.Header, body: body, requestID: resp.Header.Get("X-Request-ID")})
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		return false, &Error{Exit: ExitServer, Code: "invalid_response", Message: "The service did not answer with an event stream."}
	}
	c.logf("< 200 event stream request-id=%s", resp.Header.Get("X-Request-ID"))
	lines := make(chan []byte)
	readErr := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64<<10), maxSSELine)
		for sc.Scan() {
			line := append([]byte(nil), sc.Bytes()...)
			select {
			case lines <- line:
			case <-sctx.Done():
				return
			}
		}
		err := sc.Err()
		if err == nil {
			err = io.EOF
		}
		readErr <- err
	}()
	var ev sseEvent
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timer.C:
			return false, errStreamIdle
		case err := <-readErr:
			if errors.Is(err, io.EOF) {
				return false, nil
			}
			if ctx.Err() != nil {
				return false, ctx.Err()
			}
			return false, &Error{Exit: ExitNetwork, Code: "stream_failed", Message: "The event stream failed: " + redactText(err.Error())}
		case line := <-lines:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(idle)
			switch {
			case len(line) == 0:
				if ev.event != "" || len(ev.data) > 0 {
					stop, err := fn(ev)
					if err != nil || stop {
						return stop, err
					}
				}
				ev = sseEvent{}
			case line[0] == ':':
			default:
				field, value, _ := bytes.Cut(line, []byte(":"))
				value = bytes.TrimPrefix(value, []byte(" "))
				switch string(field) {
				case "id":
					ev.id = string(value)
				case "event":
					ev.event = string(value)
				case "data":
					if len(ev.data)+len(value)+1 > maxSSEData {
						return false, &Error{Exit: ExitServer, Code: "stream_event_too_large", Message: "An event exceeds the stream limit."}
					}
					if len(ev.data) > 0 {
						ev.data = append(ev.data, '\n')
					}
					ev.data = append(ev.data, value...)
				}
			}
		}
	}
}

// retryableStream reports whether a stream failure is worth reconnecting.
func retryableStream(err error) bool {
	if err == nil || errors.Is(err, errStreamIdle) {
		return true
	}
	var e *Error
	if errors.As(err, &e) {
		switch e.Exit {
		case ExitNetwork, ExitTimeout:
			return true
		case ExitServer:
			return e.Status == 0 || retryableStatus(e.Status)
		}
		return false
	}
	return true
}

// eventFollower delivers a launch's events in order, exactly once, across
// reconnects, with a polling fallback when the stream keeps failing.
type eventFollower struct {
	c     *Client
	id    string
	after int
	sleep func(context.Context, time.Duration) error
	// onReconnect is called before each new connection (for tests and notes).
	onReconnect func(attempt int, after int, err error)
}

// run calls handle for each event until handle returns true or an error.
func (f *eventFollower) run(ctx context.Context, handle func(LaunchEvent) (bool, error)) error {
	path := apiPrefix + "/launches/" + pathEscape(f.id) + "/events"
	deliver := func(ev LaunchEvent) (bool, error) {
		if ev.Seq <= f.after {
			return false, nil
		}
		f.after = ev.Seq
		return handle(ev)
	}
	failures := 0
	for attempt := 0; ; attempt++ {
		if attempt > 0 && f.onReconnect != nil {
			f.onReconnect(attempt, f.after, nil)
		}
		last := ""
		if f.after > 0 {
			last = strconv.Itoa(f.after)
		}
		started, delivered := time.Now(), false
		stopped, err := f.c.stream(ctx, path, last, sseIdleTimeout, func(ev sseEvent) (bool, error) {
			if ev.event == "ready" {
				return false, nil
			}
			var le LaunchEvent
			if json.Unmarshal(ev.data, &le) != nil || le.Seq <= 0 {
				return false, &Error{Exit: ExitServer, Code: "invalid_response", Message: "The event stream carried an event the CLI cannot read."}
			}
			failures, delivered = 0, true
			return deliver(le)
		})
		if stopped || (err != nil && !retryableStream(err)) {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err == nil && (delivered || time.Since(started) > minStreamLife) {
			// The service ends every stream after a few minutes; reconnect.
			continue
		}
		if err == nil {
			// A stream that closes at once without news is backed off like a
			// failure, so a misbehaving service is not hammered.
			err = &Error{Exit: ExitNetwork, Code: "stream_closed", Message: "The event stream closed without delivering events."}
		}
		failures++
		if failures > maxStreamFailures {
			e := asError(ctx, err)
			e.Message = "The event stream failed " + strconv.Itoa(failures) + " times in a row: " + e.Message
			return e
		}
		if failures >= pollFallbackAfter {
			// Poll once so a broken stream does not hide progress.
			var page items[LaunchEvent]
			if _, perr := f.c.get(ctx, path, url.Values{"after": {strconv.Itoa(f.after)}, "limit": {"500"}}, &page); perr == nil {
				for _, ev := range page.Items {
					if stop, herr := deliver(ev); herr != nil || stop {
						return herr
					}
				}
			} else if !retryableStream(perr) {
				return perr
			}
		}
		d := backoffBase << failures
		if d > streamBackoffCap || d <= 0 {
			d = streamBackoffCap
		}
		if err := f.sleep(ctx, time.Duration(float64(d)*f.c.jitter())); err != nil {
			return err
		}
	}
}

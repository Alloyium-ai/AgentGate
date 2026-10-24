// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package hostd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"alloyium.local/kernel-poc/internal/hostproto"
)

// Service is the control service as the host sees it: three outbound calls.
// Every request body is one signed envelope. Tests use a fake.
type Service interface {
	Enroll(ctx context.Context, env hostproto.Envelope) (hostproto.EnrollResponse, error)
	Poll(ctx context.Context, env hostproto.Envelope) (hostproto.PollResponse, error)
	Events(ctx context.Context, jobID string, env hostproto.Envelope) (hostproto.EventsResponse, error)
}

// maxResponseBytes bounds a reply: up to 16 job envelopes of 1 MiB each.
const maxResponseBytes = 17 << 20

// StatusError is a non-2xx reply. Body is bounded and never contains secrets
// from this host (the service never receives any).
type StatusError struct {
	Status int
	Body   string
	// LastAccepted is set when the service reported a sequence rejection.
	LastAccepted uint64
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("hostd: service replied %d: %s", e.Status, e.Body)
}

// HTTPService talks to the pinned service origin over TLS.
type HTTPService struct {
	Origin string
	Client *http.Client
}

// NewHTTPService builds a client with the system roots, or only the given CA.
func NewHTTPService(origin, caFile string) (*HTTPService, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.MaxResponseHeaderBytes = 64 << 10
	if caFile != "" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, errors.New("hostd: the CA file holds no certificate")
		}
		transport.TLSClientConfig.RootCAs = pool
	}
	return &HTTPService{Origin: origin, Client: &http.Client{Transport: transport, Timeout: 30 * time.Second,
		// The service origin is pinned: never follow a redirect elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (s *HTTPService) post(ctx context.Context, path string, env hostproto.Envelope, out any) error {
	body, err := json.Marshal(env)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Origin+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(raw) > maxResponseBytes {
		return errors.New("hostd: the service reply exceeds its bound")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return statusError(resp.StatusCode, raw)
	}
	return hostproto.DecodeStrict(raw, out)
}

func statusError(status int, raw []byte) *StatusError {
	text := strings.ToValidUTF8(string(raw), "?")
	if len(text) > 2048 {
		text = text[:2048]
	}
	out := &StatusError{Status: status, Body: text}
	out.LastAccepted = findLastAccepted(raw)
	return out
}

// findLastAccepted looks for hostproto.SequenceRejection anywhere in the
// service error body (the service wraps details in its error envelope).
func findLastAccepted(raw []byte) uint64 {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return 0
	}
	var walk func(any, int) uint64
	walk = func(v any, depth int) uint64 {
		if depth > 6 {
			return 0
		}
		switch item := v.(type) {
		case map[string]any:
			if n, ok := item["last_accepted_sequence"].(float64); ok && n > 0 && n < 1<<53 {
				return uint64(n)
			}
			for _, child := range item {
				if found := walk(child, depth+1); found != 0 {
					return found
				}
			}
		}
		return 0
	}
	return walk(value, 0)
}

func (s *HTTPService) Enroll(ctx context.Context, env hostproto.Envelope) (hostproto.EnrollResponse, error) {
	var out hostproto.EnrollResponse
	return out, s.post(ctx, hostproto.PathEnroll, env, &out)
}

func (s *HTTPService) Poll(ctx context.Context, env hostproto.Envelope) (hostproto.PollResponse, error) {
	var out hostproto.PollResponse
	return out, s.post(ctx, hostproto.PathPoll, env, &out)
}

func (s *HTTPService) Events(ctx context.Context, jobID string, env hostproto.Envelope) (hostproto.EventsResponse, error) {
	var out hostproto.EventsResponse
	if !jobIDPattern.MatchString(jobID) {
		return out, errors.New("hostd: invalid job id")
	}
	return out, s.post(ctx, strings.Replace(hostproto.PathEvents, "{id}", jobID, 1), env, &out)
}

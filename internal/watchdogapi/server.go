// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package watchdogapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodeapi"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"
)

type Server struct {
	SocketPath     string
	Core           Core
	RequestTimeout time.Duration
	StopTimeout    time.Duration
}

func reject(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "watchdog_request_rejected", status)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if recover() != nil {
			reject(w, 500)
		}
	}()
	peer, err := nodeapi.PeerFromContext(r.Context())
	if err != nil || peer.UID != 0 || peer.GID != 0 {
		reject(w, 403)
		return
	}
	if r.Method != "POST" || r.URL.RawQuery != "" || r.URL.Fragment != "" {
		reject(w, 400)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, (2<<20)+1))
	var request Request
	if err != nil || len(raw) > 2<<20 || lifecycle.DecodeTransport(bytes.NewReader(raw), &request) != nil || request.Protocol != RequestProtocol || request.Daemon.PID != int(peer.PID) {
		reject(w, 422)
		return
	}
	ticks, err := lifecycle.ProcessStartTime(int(peer.PID))
	if err != nil || ticks != request.Daemon.StartTimeTicks {
		reject(w, 403)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.RequestTimeout)
	defer cancel()
	response := Response{Protocol: ResponseProtocol, Confirmed: true}
	switch r.URL.Path {
	case "/v1/watchdog/reserve":
		if request.Binding == nil || request.Ack != nil || request.PreparationDeadlineNS == 0 || request.EffectiveDeadlineNS != 0 {
			reject(w, 422)
			return
		}
		err = s.Core.Reserve(ctx, *request.Binding, request.Daemon, request.PreparationDeadlineNS)
		if err == nil {
			ack, reservationErr := s.Core.Reservation(ctx, *request.Binding, request.Daemon)
			err = reservationErr
			response.Ack = &ack
		}
	case "/v1/watchdog/arm":
		if request.Binding == nil || request.Ack != nil || request.PreparationDeadlineNS != 0 || request.EffectiveDeadlineNS != 0 {
			reject(w, 422)
			return
		}
		ack, armErr := s.Core.Arm(ctx, *request.Binding, request.Daemon)
		err = armErr
		response.Ack = &ack
	case "/v1/watchdog/activate", "/v1/watchdog/check", "/v1/watchdog/heartbeat":
		if request.Ack == nil || request.Binding != nil || request.PreparationDeadlineNS != 0 {
			reject(w, 422)
			return
		}
		if r.URL.Path == "/v1/watchdog/activate" {
			if request.EffectiveDeadlineNS == 0 {
				reject(w, 422)
				return
			}
			err = s.Core.Activate(ctx, *request.Ack, request.Daemon, request.EffectiveDeadlineNS)
			response.State = "active"
			response.EffectiveDeadlineNS = request.EffectiveDeadlineNS
		} else if r.URL.Path == "/v1/watchdog/check" {
			if request.EffectiveDeadlineNS != 0 {
				reject(w, 422)
				return
			}
			err = s.Core.Check(ctx, *request.Ack, request.Daemon)
		} else {
			if request.EffectiveDeadlineNS != 0 {
				reject(w, 422)
				return
			}
			err = s.Core.Heartbeat(ctx, *request.Ack, request.Daemon)
		}
	default:
		reject(w, 404)
		return
	}
	if err != nil {
		reject(w, 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(response)
}
func (s *Server) Serve(ctx context.Context) error {
	if s.Core == nil || s.RequestTimeout <= 0 || s.RequestTimeout > time.Second || s.StopTimeout <= 0 || s.StopTimeout > 30*time.Second {
		return errors.New("watchdog server dependencies and bounded timeouts are required")
	}
	if err := s.Core.Recover(ctx); err != nil {
		return errors.New("watchdog recovery is unavailable")
	}
	listener, closeListener, err := nodeapi.ListenPrivate(s.SocketPath, 0)
	if err != nil {
		return err
	}
	defer closeListener()
	run, cancel := context.WithCancel(ctx)
	defer cancel()
	watchResult := make(chan error, 1)
	go func() { watchResult <- s.Core.Watch(run, 100*time.Millisecond) }()
	server := &http.Server{Handler: s, ConnContext: nodeapi.PrivateConnContext, ReadHeaderTimeout: s.RequestTimeout, ReadTimeout: s.RequestTimeout, WriteTimeout: s.RequestTimeout, MaxHeaderBytes: 8192}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	watchEnded := false
	var watchErr error
	select {
	case <-ctx.Done():
	case <-result:
	case watchErr = <-watchResult:
		watchEnded = true
	}
	cancel()
	cleanup, stop := context.WithTimeout(context.Background(), s.StopTimeout)
	defer stop()
	if server.Shutdown(cleanup) != nil {
		_ = server.Close()
	}
	if watchEnded {
		return watchErr
	}
	select {
	case err = <-watchResult:
		return err
	case <-cleanup.Done():
		return errors.New("watchdog shutdown termination is unconfirmed")
	}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package watchdogapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ClientConfig struct {
	SocketPath        string
	Daemon            lifecycle.DaemonIdentity
	PublicKey         ed25519.PublicKey
	ArtifactDigest    string
	Clock             lifecycle.Clock
	Timeout           time.Duration
	HeartbeatInterval time.Duration
}
type Client struct {
	config    ClientConfig
	http      *http.Client
	transport *http.Transport
	leases    sync.Map
	failed    atomic.Bool
	running   atomic.Bool
}

func NewClient(config ClientConfig) (*Client, error) {
	ticks, err := lifecycle.ProcessStartTime(os.Getpid())
	if os.Geteuid() != 0 || err != nil || config.Daemon.PID != os.Getpid() || config.Daemon.StartTimeTicks != ticks || config.Daemon.InstanceID == "" || len(config.PublicKey) != ed25519.PublicKeySize || len(config.ArtifactDigest) != 64 || config.Clock == nil || config.Timeout <= 0 || config.Timeout > time.Second || config.HeartbeatInterval <= 0 || config.HeartbeatInterval > 500*time.Millisecond {
		return nil, errors.New("watchdog client identity, trust and bounded timeouts are required")
	}
	config.PublicKey = append(ed25519.PublicKey{}, config.PublicKey...)
	client := &Client{config: config}
	client.transport = &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) { return client.dial(ctx) }}
	client.http = &http.Client{Transport: client.transport, Timeout: config.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("watchdog redirect rejected") }}
	return client, nil
}
func (c *Client) Ready() bool { return c.running.Load() && !c.failed.Load() }
func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	path := c.config.SocketPath
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/tmp" || strings.HasPrefix(path, "/tmp/") {
		return nil, errors.New("watchdog socket path is invalid")
	}
	parent := filepath.Dir(path)
	canonical, err := filepath.EvalSymlinks(parent)
	var directory, socket unix.Stat_t
	if err != nil || canonical != parent || unix.Stat(parent, &directory) != nil || directory.Uid != 0 || directory.Mode&0022 != 0 || unix.Lstat(path, &socket) != nil || socket.Uid != 0 || socket.Mode&unix.S_IFMT != unix.S_IFSOCK || socket.Mode&0007 != 0 {
		return nil, errors.New("watchdog socket custody is invalid")
	}
	connection, err := (&net.Dialer{Timeout: c.config.Timeout}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, errors.New("watchdog connection is unavailable")
	}
	caller, ok := connection.(*net.UnixConn)
	verified := false
	if ok {
		raw, rawErr := caller.SyscallConn()
		if rawErr == nil {
			_ = raw.Control(func(fd uintptr) {
				peer, peerErr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
				verified = peerErr == nil && peer.Uid == 0 && peer.Gid == 0
			})
		}
	}
	if !verified {
		connection.Close()
		return nil, errors.New("watchdog peer is unverified")
	}
	return connection, nil
}
func (c *Client) call(ctx context.Context, path string, request Request) (Response, error) {
	if c.failed.Load() || !c.running.Load() {
		return Response{}, errors.New("independent watchdog heartbeat is unavailable")
	}
	request.Protocol = RequestProtocol
	request.Daemon = c.config.Daemon
	raw, err := json.Marshal(request)
	if err != nil {
		return Response{}, errors.New("watchdog request is invalid")
	}
	message, err := http.NewRequestWithContext(ctx, "POST", "http://watchdog/v1/watchdog/"+path, bytes.NewReader(raw))
	if err != nil {
		return Response{}, err
	}
	result, err := c.http.Do(message)
	if err != nil {
		return Response{}, errors.New("watchdog request failed")
	}
	defer result.Body.Close()
	var response Response
	if result.StatusCode != 200 || lifecycle.DecodeTransport(io.LimitReader(result.Body, 2<<20), &response) != nil || response.Protocol != ResponseProtocol || !response.Confirmed {
		return Response{}, errors.New("watchdog custody is unconfirmed")
	}
	return response, nil
}
func (c *Client) validAck(ack *lifecycle.WatchdogAck, b lifecycle.Binding) bool {
	now, err := c.config.Clock.NowNS()
	return ack != nil && err == nil && ack.Daemon == c.config.Daemon && ack.ArtifactDigest == c.config.ArtifactDigest && lifecycle.VerifyWatchdogAck(*ack, b, c.config.PublicKey, now) == nil
}
func (c *Client) Reserve(ctx context.Context, b lifecycle.Binding, deadline uint64) error {
	response, err := c.call(ctx, "reserve", Request{Binding: &b, PreparationDeadlineNS: deadline})
	if err != nil || !c.validAck(response.Ack, b) {
		return errors.New("watchdog preparation custody is unconfirmed")
	}
	c.leases.Store(b.RunID, *response.Ack)
	return nil
}
func (c *Client) Arm(ctx context.Context, b lifecycle.Binding) (lifecycle.WatchdogAck, error) {
	response, err := c.call(ctx, "arm", Request{Binding: &b})
	if err != nil || !c.validAck(response.Ack, b) {
		return lifecycle.WatchdogAck{}, errors.New("watchdog execution custody is unconfirmed")
	}
	c.leases.Store(b.RunID, *response.Ack)
	return *response.Ack, nil
}
func (c *Client) Check(ctx context.Context, ack lifecycle.WatchdogAck) error {
	if !c.validAck(&ack, ack.Binding) {
		return errors.New("watchdog execution custody is invalid")
	}
	_, err := c.call(ctx, "check", Request{Ack: &ack})
	return err
}

// Forget ends local heartbeats when the node starts termination. The watchdog
// retains custody and retries whole-domain termination until it confirms Empty.
func (c *Client) Forget(binding lifecycle.Binding) { c.leases.Delete(binding.RunID) }
func (c *Client) heartbeat(ctx context.Context) error {
	failures := []error{}
	c.leases.Range(func(run, value any) bool {
		ack := value.(lifecycle.WatchdogAck)
		_, err := c.call(ctx, "heartbeat", Request{Ack: &ack})
		if err != nil {
			current, exists := c.leases.Load(run)
			// Arm can replace a preparation acknowledgement during an in-flight heartbeat.
			if exists && reflect.DeepEqual(current, ack) {
				failures = append(failures, err)
			}
		}
		return true
	})
	return errors.Join(failures...)
}

// Run must stay in the node daemon. Its death ends heartbeats. The independent
// watchdog then stops every leased domain. A failed heartbeat closes new release.
func (c *Client) Run(ctx context.Context) error {
	if !c.running.CompareAndSwap(false, true) {
		return errors.New("watchdog heartbeat already started")
	}
	defer c.running.Store(false)
	defer c.transport.CloseIdleConnections()
	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := c.heartbeat(ctx); err != nil {
				// Explicit shutdown can cancel an in-flight request. Run still clears
				// readiness on exit; only a live heartbeat failure latches the fault.
				if ctx.Err() != nil {
					return nil
				}
				c.failed.Store(true)
				return errors.New("independent watchdog heartbeat failed")
			}
		}
	}
}

var _ lifecycle.WatchdogGuard = (*Client)(nil)

func (c *Client) Activate(ctx context.Context, ack lifecycle.WatchdogAck, effectiveDeadline uint64) error {
	now, clockErr := c.config.Clock.NowNS()
	if !c.validAck(&ack, ack.Binding) || clockErr != nil || effectiveDeadline <= now || effectiveDeadline > ack.Binding.DeadlineNS {
		return errors.New("watchdog activation custody or cutoff is invalid")
	}
	response, err := c.call(ctx, "activate", Request{Ack: &ack, EffectiveDeadlineNS: effectiveDeadline})
	if err != nil || response.State != "active" || response.EffectiveDeadlineNS != effectiveDeadline {
		return errors.New("watchdog activation is unconfirmed")
	}
	return nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package watchdogapi connects a node daemon to an independent root watchdog.
package watchdogapi

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"time"
)

const RequestProtocol = "agentgate.watchdog.request.v1"
const ResponseProtocol = "agentgate.watchdog.response.v1"

type Request struct {
	EffectiveDeadlineNS   uint64                   `json:"effective_deadline_ns,string,omitempty"`
	Protocol              string                   `json:"protocol"`
	Daemon                lifecycle.DaemonIdentity `json:"daemon"`
	Binding               *lifecycle.Binding       `json:"binding,omitempty"`
	Ack                   *lifecycle.WatchdogAck   `json:"ack,omitempty"`
	PreparationDeadlineNS uint64                   `json:"preparation_deadline_ns,string"`
}
type Response struct {
	EffectiveDeadlineNS uint64                 `json:"effective_deadline_ns,string,omitempty"`
	Protocol            string                 `json:"protocol"`
	State               string                 `json:"state,omitempty"`
	Confirmed           bool                   `json:"confirmed"`
	Ack                 *lifecycle.WatchdogAck `json:"ack,omitempty"`
}
type Core interface {
	Recover(context.Context) error
	Reserve(context.Context, lifecycle.Binding, lifecycle.DaemonIdentity, uint64) error
	Reservation(context.Context, lifecycle.Binding, lifecycle.DaemonIdentity) (lifecycle.WatchdogAck, error)
	Arm(context.Context, lifecycle.Binding, lifecycle.DaemonIdentity) (lifecycle.WatchdogAck, error)
	Activate(context.Context, lifecycle.WatchdogAck, lifecycle.DaemonIdentity, uint64) error
	Check(context.Context, lifecycle.WatchdogAck, lifecycle.DaemonIdentity) error
	Heartbeat(context.Context, lifecycle.WatchdogAck, lifecycle.DaemonIdentity) error
	Watch(context.Context, time.Duration) error
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package lifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
)

const WatchdogAckProtocol = "agentgate.watchdog.ack.v1"

type DaemonIdentity struct {
	PID            int    `json:"pid"`
	StartTimeTicks uint64 `json:"start_time_ticks,string"`
	InstanceID     string `json:"instance_id"`
}

func (d DaemonIdentity) validate() error {
	if d.PID <= 1 || d.StartTimeTicks == 0 || !identifier.MatchString(d.InstanceID) {
		return errors.New("watchdog daemon identity is invalid")
	}
	return nil
}

type WatchdogAck struct {
	Protocol       string         `json:"protocol"`
	Binding        Binding        `json:"binding"`
	Daemon         DaemonIdentity `json:"daemon"`
	WatchdogID     string         `json:"watchdog_id"`
	ArtifactDigest string         `json:"artifact_digest"`
	IssuedNS       uint64         `json:"issued_ns,string"`
	Signature      string         `json:"signature"`
}

func watchdogAckBytes(ack WatchdogAck) []byte {
	ack.Signature = ""
	raw, _ := json.Marshal(ack)
	return append([]byte("agentgate-watchdog-custody-v1\n"), raw...)
}
func VerifyWatchdogAck(ack WatchdogAck, binding Binding, public ed25519.PublicKey, now uint64) error {
	if binding.validate(binding.CgroupID == 0) != nil || len(public) != ed25519.PublicKeySize || ack.Protocol != WatchdogAckProtocol || !ack.Binding.same(binding) || ack.Daemon.validate() != nil || !identifier.MatchString(ack.WatchdogID) || !validDigest(ack.ArtifactDigest) || binding.ArtifactDigests["watchdog"] != ack.ArtifactDigest || ack.IssuedNS == 0 || ack.IssuedNS > now || now >= binding.DeadlineNS {
		return errors.New("watchdog custody binding is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(ack.Signature)
	if err != nil || base64.RawURLEncoding.EncodeToString(signature) != ack.Signature || !ed25519.Verify(public, watchdogAckBytes(ack), signature) {
		return errors.New("watchdog custody signature is invalid")
	}
	return nil
}

// WatchdogGuard must call an independent trusted process. A manager-local timer
// cannot supply custody. Check verifies that the same daemon still owns the lease.
type WatchdogGuard interface {
	Reserve(context.Context, Binding, uint64) error
	Arm(context.Context, Binding) (WatchdogAck, error)
	Activate(context.Context, WatchdogAck, uint64) error
	Check(context.Context, WatchdogAck) error
	Forget(Binding)
}
type WatchdogStopEvidence struct {
	Retired                    bool    `json:"retired,omitempty"`
	NoDomain                   bool    `json:"no_domain,omitempty"`
	RightsRemoved              bool    `json:"rights_removed,omitempty"`
	CountersAvailable          bool    `json:"counters_available,omitempty"`
	Binding                    Binding `json:"binding"`
	Reason                     string  `json:"reason"`
	Terminated                 bool    `json:"terminated"`
	Empty                      bool    `json:"empty"`
	PinsRetained               bool    `json:"pins_retained"`
	ReadbackDigest             string  `json:"readback_digest"`
	CurrentRootProofDigest     string  `json:"current_root_proof_digest,omitempty"`
	ReservationRootProofDigest string  `json:"reservation_root_proof_digest,omitempty"`
	Decisions                  uint64  `json:"decisions,string"`
	Lost                       uint64  `json:"lost,string"`
	Digest                     string  `json:"digest"`
}

func WatchdogStopDigest(e WatchdogStopEvidence) string {
	e.Digest = ""
	raw, _ := json.Marshal(e)
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

// Implementations independently verify the protected reservation namespace,
// root-level cgroup depth, inode, boot and exact immutable binding on every call.
// The journal and a caller-supplied CgroupID never establish path ownership.
// Stop kills the complete domain, confirms Empty, and retains enforcement pins.
type WatchdogDomainStopper interface {
	ListOwnedDomains(context.Context) ([]Binding, error)
	StopOwnedDomain(context.Context, Binding, string) (WatchdogStopEvidence, error)
}
type DaemonMonitor interface {
	Alive(context.Context, DaemonIdentity) error
}
type WatchdogLease struct {
	EffectiveDeadlineNS   uint64      `json:"effective_deadline_ns,string,omitempty"`
	NoDomain              bool        `json:"no_domain,omitempty"`
	RetiredBootID         string      `json:"retired_boot_id,omitempty"`
	Ack                   WatchdogAck `json:"ack"`
	PreparationDeadlineNS uint64      `json:"preparation_deadline_ns,string"`
	HeartbeatDeadlineNS   uint64      `json:"heartbeat_deadline_ns,string"`
	Revision              uint64      `json:"revision,string"`
	State                 string      `json:"state"`
}
type WatchdogStore interface {
	LoadWatchdog(context.Context) ([]WatchdogLease, error)
	SaveWatchdog(context.Context, WatchdogLease, uint64) error
	SaveWatchdogStop(context.Context, WatchdogStopEvidence) error
}

// A retired proof is stop-only. Its authenticated reservation and current root
// prove Empty even when concurrent node reconciliation already removed pins.
func confirmedWatchdogStop(e WatchdogStopEvidence) bool {
	if e.Binding.validate(false) != nil || !identifier.MatchString(e.Reason) || !e.Terminated || !e.Empty || !validDigest(e.ReadbackDigest) || e.Digest != WatchdogStopDigest(e) {
		return false
	}
	if e.Retired {
		return validDigest(e.CurrentRootProofDigest) && validDigest(e.ReservationRootProofDigest) && (!e.NoDomain || e.RightsRemoved)
	}
	return e.PinsRetained
}

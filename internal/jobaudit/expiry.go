// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package jobaudit

import (
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"errors"
	"math"
	"time"
)

const MaxGrantExpiryPairingNS = uint64(100 * time.Millisecond)

// GrantExpiry records the conservative node mapping of the signed wall expiry.
// It changes no grant, header or binding field.
type GrantExpiry struct {
	ExpiresAt        int64  `json:"expires_at"`
	WallSampleUnixNS int64  `json:"wall_sample_unix_ns,string"`
	MonoSampleNS     uint64 `json:"mono_sample_ns,string"`
	MonoAfterNS      uint64 `json:"mono_after_ns,string"`
	KernelDeadlineNS uint64 `json:"kernel_deadline_ns,string"`
}

func (g GrantExpiry) Validate(binding lifecycle.Binding, expiresAt int64) error {
	if g.ExpiresAt != expiresAt || expiresAt <= 0 || expiresAt > math.MaxInt64/int64(time.Second) || g.WallSampleUnixNS <= 0 || g.MonoSampleNS == 0 || g.MonoAfterNS < g.MonoSampleNS || g.MonoAfterNS-g.MonoSampleNS > MaxGrantExpiryPairingNS {
		return errors.New("the grant expiry samples are invalid")
	}
	expiresNS := expiresAt * int64(time.Second)
	if g.WallSampleUnixNS >= expiresNS {
		return errors.New("the signed grant wall expiry has elapsed")
	}
	remaining := uint64(expiresNS - g.WallSampleUnixNS)
	if remaining > math.MaxUint64-g.MonoSampleNS {
		return errors.New("the grant expiry cutoff overflows")
	}
	want := g.MonoSampleNS + remaining
	if binding.DeadlineNS < want {
		want = binding.DeadlineNS
	}
	if g.KernelDeadlineNS != want || want <= g.MonoAfterNS || want > binding.DeadlineNS {
		return errors.New("the grant expiry cutoff differs")
	}
	return nil
}

func validGrantExpiry(g GrantExpiry, header Header, grant *jobgrant.Envelope, frameNS uint64) error {
	if grant == nil || g.Validate(header.Binding, grant.Claims.ExpiresAt) != nil || g.MonoSampleNS < header.CreatedMonoNS || g.MonoSampleNS < grant.Claims.IssuedMonoNS || grant.Claims.NotBefore <= 0 || grant.Claims.NotBefore > math.MaxInt64/int64(time.Second) || g.WallSampleUnixNS < grant.Claims.NotBefore*int64(time.Second) || frameNS < g.MonoAfterNS || frameNS >= g.KernelDeadlineNS {
		return errors.New("the grant expiry evidence differs from the signed job")
	}
	return nil
}

func auditExpiry(bundle Bundle) (uint64, uint64, bool) {
	var cutoff, frameNS uint64
	for _, event := range bundle.Events {
		if bound := event.Observation.GrantExpiry; bound != nil {
			if event.Kind != "control" || cutoff != 0 || validGrantExpiry(*bound, bundle.Header, bundle.Grant, event.Observation.TimestampNS) != nil {
				return 0, 0, false
			}
			cutoff, frameNS = bound.KernelDeadlineNS, event.Observation.TimestampNS
		} else if event.Kind != "control" && (cutoff == 0 || event.Observation.TimestampNS < frameNS) {
			return 0, 0, false
		}
	}
	return cutoff, frameNS, cutoff != 0
}

func preparationControl(phase string) bool {
	return phase == "prepared" || phase == "quarantine_readback"
}

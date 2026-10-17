// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/jobgrant"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/syscallrules"
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"math"
	"time"
)

func (r *run) deadline() uint64 {
	if r.kernelDeadline != 0 {
		return r.kernelDeadline
	}
	return r.binding.DeadlineNS
}

type kernelExpired struct{}

func (kernelExpired) Error() string                            { return "the effective kernel grant deadline expired" }
func (kernelExpired) LifecycleStopReason() lifecycle.StopCause { return lifecycle.GrantExpired }

func restrictedDeadline(bound, mono uint64, wall time.Time, expiresAt int64) (uint64, error) {
	remaining := time.Unix(expiresAt, 0).Sub(wall)
	if mono == 0 || bound <= mono || remaining <= 0 || remaining > 24*time.Hour || uint64(remaining) > math.MaxUint64-mono {
		return 0, errors.New("the signed grant expiry cannot bind a current kernel deadline")
	}
	deadline := mono + uint64(remaining)
	if deadline > bound {
		deadline = bound
	}
	return deadline, nil
}

// A signed wall expiry can precede the immutable monotonic binding. Restrict
// every installed plan to both bounds before the held helper starts.
func (b *Backend) bindGrantExpiry(ctx context.Context, r *run, claims jobgrant.Claims) error {
	clock, ok := b.config.Clock.(jobgrant.Clock)
	if !ok {
		return errors.New("the kernel expiry requires the paired node clock")
	}
	wall, mono, err := clock.Now()
	if err != nil || mono < claims.IssuedMonoNS || wall.Unix() < claims.NotBefore {
		return errors.New("the signed grant clock is unavailable")
	}
	after, err := b.config.Clock.NowNS()
	if err != nil || after < mono || after-mono > jobaudit.MaxGrantExpiryPairingNS || wall.UnixNano() <= 0 {
		return errors.New("the signed grant clock samples are inconsistent")
	}
	deadline, err := restrictedDeadline(r.deadline(), mono, wall, claims.ExpiresAt)
	if err != nil {
		return err
	}
	if deadline <= after {
		return errors.New("the signed grant expired during its clock sample")
	}
	bound := jobaudit.GrantExpiry{ExpiresAt: claims.ExpiresAt, WallSampleUnixNS: wall.UnixNano(), MonoSampleNS: mono, MonoAfterNS: after, KernelDeadlineNS: deadline}
	if err = bound.Validate(r.binding, claims.ExpiresAt); err != nil {
		return err
	}
	if r.observation == nil {
		return errors.New("the expiry observation map is absent")
	}
	m := r.observation.Collection.Maps["audit_bindings"]
	if m == nil {
		return errors.New("the expiry observation map is absent")
	}
	var actual syscallrules.Binding
	if err = m.Lookup(r.binding.CgroupID, &actual); err != nil {
		return err
	}
	if actual != (syscallrules.Binding{Generation: r.binding.Generation, ExpiresNS: r.deadline()}) {
		return errors.New("the prior expiry observation binding differs")
	}
	next := syscallrules.Binding{Generation: r.binding.Generation, ExpiresNS: deadline}
	if err = m.Update(r.binding.CgroupID, next, ebpf.UpdateExist); err != nil {
		return err
	}
	if err = m.Lookup(r.binding.CgroupID, &actual); err != nil {
		return err
	}
	if actual != next {
		return errors.New("the restricted expiry readback differs")
	}
	r.kernelDeadline = deadline
	return r.control(ctx, "grant_expiry_bound", bound)
}

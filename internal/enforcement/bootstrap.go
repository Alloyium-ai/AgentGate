// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"alloyium.local/kernel-poc/internal/heldprocess"
	"alloyium.local/kernel-poc/internal/kernel"
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"time"
)

type bootstrapKey struct {
	Domain       uint64
	PID, Padding uint32
}
type bootstrapBinding struct{ Generation, ExpiresNS, StartTicks, PipeInode uint64 }

// BindBootstrap authorizes one exact control pipe for a measured stopped helper.
// Agent exec removes this role. Missing policy, stale identity and expiry still deny.
func (g *Group) BindBootstrap(ctx context.Context, p Plan, h *heldprocess.Held, lease time.Duration) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if h == nil || !p.bootstrapRead || p.bootstrapDigest != h.ArtifactDigest() || lease <= 0 || lease > time.Duration(p.bootstrapMaxHold)*time.Second || p.generation != g.generation || g.Files == nil || g.Files.ID != p.domain {
		return errors.New("an explicit measured bootstrap permission is required")
	}
	if err := h.Verify(ctx, h.Process()); err != nil {
		return err
	}
	if err := g.Files.VerifyMember(h.Process().PID); err != nil {
		return err
	}
	now, err := kernel.MonotonicNS()
	if err != nil {
		return err
	}
	deadline := now + uint64(lease)
	if deadline > p.deadline {
		deadline = p.deadline
	}
	if deadline <= now {
		return errors.New("bootstrap lease expired")
	}
	inode, err := h.BarrierInode()
	if err != nil || inode == 0 {
		return errors.New("bootstrap pipe identity differs")
	}
	key := bootstrapKey{Domain: p.domain, PID: uint32(h.Process().PID)}
	value := bootstrapBinding{p.generation, deadline, h.Process().StartTimeTicks, inode}
	m := g.Files.Collection.Maps["bootstrap"]
	if m == nil {
		return errors.New("bootstrap enforcement map is absent")
	}
	if err = m.Update(key, value, ebpf.UpdateNoExist); err != nil {
		return err
	}
	var got bootstrapBinding
	if err = m.Lookup(key, &got); err != nil {
		return err
	}
	if got != value {
		return errors.New("bootstrap kernel readback differs")
	}
	return h.Verify(ctx, h.Process())
}

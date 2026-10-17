// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/policy"
	"context"
	"encoding/base64"
	"time"
)

func (o *Operations) Inventory(ctx context.Context) (out lifecycle.NodeInventory, err error) {
	target, err := o.Target(ctx)
	if err != nil {
		return out, err
	}
	b := o.config.Backend
	mono, err := b.config.Clock.NowNS()
	if err != nil {
		return out, err
	}
	out = lifecycle.NodeInventory{Protocol: lifecycle.NodeInventoryProtocol, NodeID: b.config.Domain.NodeID, BootID: b.config.Domain.Proof.BootID, SchemaDigest: policy.SchemaDigest(), CompilerDigest: b.config.CompilerDigest, ArtifactDigests: copyValue(b.config.ArtifactDigests), TargetReport: target.Report(), TargetDigest: target.Digest(), WallUnix: time.Now().Unix(), MonoNS: mono, KeyID: b.config.Signer.KeyID()}
	raw, err := lifecycle.NodeInventorySigningBytes(out)
	if err != nil {
		return out, err
	}
	signature, err := b.config.Signer.Sign(ctx, raw)
	if err != nil {
		return out, err
	}
	out.Signature = base64.RawURLEncoding.EncodeToString(signature)
	if _, err = lifecycle.VerifyNodeInventory(out, b.config.NodeKeys, lifecycle.Identity{NodeID: out.NodeID, BootID: out.BootID}, time.Now().Unix(), time.Second); err != nil {
		return out, err
	}
	return out, nil
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"context"
	"crypto/sha256"
	"encoding/hex"
)

func frameDigest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }
func (r *run) retainChildFrames(ctx context.Context, helper string) error {
	d := r.child.Declaration()
	p := nodecontrol.ChildFrames{Process: r.child.Held.Process(), HelperDigest: helper, ManifestDigest: r.binding.JobDigest, JobDigest: frameDigest(d.Job), FilterDigest: frameDigest(d.Filters), JobBytes: uint32(len(d.Job)), FilterBytes: uint32(len(d.Filters)), JobSeals: d.JobSeals, FilterSeals: d.FilterSeals}
	p.FilterAcknowledgement = r.child.Held.FilterAcknowledgement()
	if err := r.control(ctx, "child_frame_custody", p); err != nil {
		return err
	}
	for _, frame := range []struct {
		kind   string
		raw    []byte
		digest string
	}{{"job", d.Job, p.JobDigest}, {"filters", d.Filters, p.FilterDigest}} {
		for offset := 0; offset < len(frame.raw); offset += 4096 {
			chunk := nodecontrol.ChildFrameChunk{Kind: frame.kind, Offset: uint32(offset), Total: uint32(len(frame.raw)), Digest: frame.digest, Bytes: frame.raw[offset:min(offset+4096, len(frame.raw))]}
			if err := r.control(ctx, "child_frame_chunk", chunk); err != nil {
				return err
			}
		}
	}
	return nil
}

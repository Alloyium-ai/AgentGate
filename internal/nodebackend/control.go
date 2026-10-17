// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"context"
)

func (r *run) control(ctx context.Context, phase string, value any) error {
	r.controlMu.Lock()
	defer r.controlMu.Unlock()
	wire, err := nodecontrol.Encode(r.binding, phase, value)
	if err != nil {
		return err
	}
	if err = r.writer.Append(ctx, nodecontrol.Stream, wire); err != nil {
		return err
	}
	r.controlCount++
	return nil
}

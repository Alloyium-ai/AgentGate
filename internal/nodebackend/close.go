// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"alloyium.local/kernel-poc/internal/lifecycle"
	"context"
	"errors"
)

func (b *Backend) Close(ctx context.Context) error {
	b.mu.RLock()
	runs := make([]*run, 0, len(b.runs))
	for _, r := range b.runs {
		runs = append(runs, r)
	}
	b.mu.RUnlock()
	var failures []error
	for _, r := range runs {
		r.mu.Lock()
		binding := copyValue(r.binding)
		r.mu.Unlock()
		e, err := b.Stop(ctx, binding, "node-close")
		if err != nil || !e.Empty || !e.RightsRemoved {
			failures = append(failures, errors.Join(err, errors.New("the node close cannot confirm rights removal")))
		}
	}
	if len(failures) != 0 {
		return errors.Join(failures...)
	}
	return errors.Join(b.artifacts.Close(), b.domains.Close())
}
func (b *Backend) Bindings() []lifecycle.Binding {
	b.mu.RLock()
	runs := make([]*run, 0, len(b.runs))
	for _, r := range b.runs {
		runs = append(runs, r)
	}
	b.mu.RUnlock()
	out := []lifecycle.Binding{}
	for _, r := range runs {
		r.mu.Lock()
		if r.phase != "stopped" {
			out = append(out, copyValue(r.binding))
		}
		r.mu.Unlock()
	}
	return out
}

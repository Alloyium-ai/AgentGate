// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package nodebackend

import (
	"context"
	"errors"
	"reflect"

	"alloyium.local/kernel-poc/internal/dockerplacement"
)

// A Docker container ID and image can remain unchanged across a restart.
// Keep the first measured process, namespaces and mount identities pinned from
// prepare through held placement, guard installation and release.
func matchPreparedPilotTarget(prepared *dockerplacement.Measurement, current dockerplacement.Measurement) error {
	if prepared == nil || prepared.HostPID <= 1 || prepared.StartTimeTicks == "" ||
		!reflect.DeepEqual(*prepared, current) {
		return errors.New("the prepared Docker target changed before release")
	}
	return nil
}

func (b *Backend) verifyPilotTarget(ctx context.Context, r *run) error {
	pilot := r.document.Network != nil && r.document.Network.Pilot != nil
	if !pilot {
		if r.pilotTarget != nil {
			return errors.New("a nonpilot run retained Docker target custody")
		}
		return nil
	}
	if b.config.PilotTarget == nil || r.pilotTarget == nil {
		return errors.New("the prepared Docker target custody is absent")
	}
	current, err := dockerplacement.Measure(ctx, *b.config.PilotTarget)
	if err != nil {
		return err
	}
	return matchPreparedPilotTarget(r.pilotTarget, current)
}

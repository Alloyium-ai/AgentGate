// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"errors"
	"reflect"

	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/noderuntime"
)

// verifyServiceLifecycleSceneMode binds the signed terminal and actual command
// sequence to the compiled scene. A failed scene never reaches this verifier.
func verifyServiceLifecycleSceneMode(scene serviceLifecycleScene) error {
	state := map[string]string{"stop": "cancelled", "expiry": "expired", "revoke": "revoked"}[scene.Mode]
	if state == "" || scene.Stopped.Terminal == nil || scene.Stopped.Terminal.State != state {
		return errors.New("the fixed lifecycle terminal state differs")
	}
	revocations := 0
	for _, call := range scene.AuthorityCalls {
		if call.Operation == "revoke" {
			revocations++
		}
	}
	if scene.Mode == "revoke" && revocations != 1 || scene.Mode != "revoke" && revocations != 0 {
		return errors.New("the fixed lifecycle revocation sequence differs")
	}
	if len(scene.Calls) < 4 || scene.Calls[0].Path != "/fixture/prepare" || scene.Calls[1].Path != "/fixture/start" || scene.Calls[len(scene.Calls)-1].Path != "/fixture/stop" {
		return errors.New("the fixed lifecycle command sequence differs")
	}
	if scene.Mode == "stop" {
		if len(scene.Calls) != 4 || scene.Calls[2].Path != "/fixture/stop" {
			return errors.New("the fixed stop command sequence differs")
		}
		return nil
	}
	for _, call := range scene.Calls[2 : len(scene.Calls)-1] {
		if call.Path != "/fixture/status" {
			return errors.New("the fixed lifecycle polling sequence differs")
		}
	}
	last := scene.Calls[len(scene.Calls)-2]
	var observed noderuntime.QualificationStatus
	if err := lifecycle.DecodeTransport(bytes.NewReader(last.Response), &observed); err != nil || !reflect.DeepEqual(observed, scene.Stopped) {
		return errors.New("the actual polled terminal differs")
	}
	if scene.Mode == "expiry" {
		if len(scene.Active.Record.Evidence) == 0 {
			return errors.New("the actual expiry cutoff is absent")
		}
		cutoff := scene.Active.Record.Evidence[len(scene.Active.Record.Evidence)-1].EffectiveDeadlineNS
		if cutoff == 0 || last.MonoNS < cutoff {
			return errors.New("the actual expiry observation precedes its cutoff")
		}
	}
	return nil
}

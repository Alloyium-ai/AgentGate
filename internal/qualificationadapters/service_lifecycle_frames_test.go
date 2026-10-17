// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"encoding/binary"
	"testing"

	"alloyium.local/kernel-poc/internal/childwire"
	"alloyium.local/kernel-poc/internal/heldprocess"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/runtimeguard"
	"golang.org/x/sys/unix"
)

func lifecycleFramesSceneFixture(t *testing.T) (serviceLifecycleScene, jobaudit.Bundle) {
	t.Helper()
	scene, previous := lifecycleMapSceneFixture(t)
	process := lifecycle.HeldProcess{PID: 123, StartTimeTicks: 456, BarrierID: "unit-held-barrier"}
	scene.Active.Record.Process = &process
	paths := scene.Recipe.Streams.Paths
	job, err := childwire.Encode(scene.Recipe.Spec.Manifest, childwire.IOPaths{Input: paths.Input, Output: paths.Output, Error: paths.Error})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := runtimeguard.Compile(*scene.Recipe.Document.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	filters, err := childwire.EncodeFilters(plan)
	if err != nil {
		t.Fatal(err)
	}
	ack := make([]byte, heldprocess.FilterAcknowledgementBytes)
	copy(ack, "AGFLT002")
	binary.LittleEndian.PutUint64(ack[8:], 7)
	binary.LittleEndian.PutUint32(ack[24:], binary.LittleEndian.Uint32(filters[12:]))
	binary.LittleEndian.PutUint32(ack[28:], binary.LittleEndian.Uint32(filters[16:]))
	binary.LittleEndian.PutUint32(ack[32:], 1)
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	metadata := nodecontrol.ChildFrames{Process: process, HelperDigest: scene.Active.Record.Binding.ArtifactDigests["held-helper"], ManifestDigest: scene.Active.Record.Binding.JobDigest, JobDigest: digestBytes(job), FilterDigest: digestBytes(filters), JobBytes: uint32(len(job)), FilterBytes: uint32(len(filters)), JobSeals: seals, FilterSeals: seals, FilterAcknowledgement: ack}
	bundle := jobaudit.Bundle{}
	add := func(phase string, payload any) {
		raw, err := nodecontrol.Encode(scene.Active.Record.Binding, phase, payload)
		if err != nil {
			t.Fatal(err)
		}
		bundle.Events = append(bundle.Events, jobaudit.Event{Stream: nodecontrol.Stream, Index: uint64(len(bundle.Events)), Raw: raw})
	}
	add("child_frame_custody", metadata)
	for _, item := range []struct {
		kind string
		raw  []byte
	}{{"job", job}, {"filters", filters}} {
		for offset := 0; offset < len(item.raw); offset += 4096 {
			add("child_frame_chunk", nodecontrol.ChildFrameChunk{Kind: item.kind, Offset: uint32(offset), Total: uint32(len(item.raw)), Digest: digestBytes(item.raw), Bytes: item.raw[offset:min(offset+4096, len(item.raw))]})
		}
	}
	add("held", process)
	add("placed", struct{}{})
	actual := previous.Events[1]
	actual.Index = uint64(len(bundle.Events))
	bundle.Events = append(bundle.Events, actual)
	add("release_intent", struct{}{})
	scene.Audit = serviceJSON(bundle)
	return scene, bundle
}
func TestMeasuredFramesRequireBothInstallOutcomesAndExactBytes(t *testing.T) {
	scene, _ := lifecycleFramesSceneFixture(t)
	if err := verifyServiceLifecycleFrames(scene); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing-chunk", "changed-frame", "failed-install", "wrong-count", "unsealed", "release-order"} {
		t.Run(mode, func(t *testing.T) {
			scene, bundle := lifecycleFramesSceneFixture(t)
			if mode == "missing-chunk" {
				bundle.Events = append(bundle.Events[:1], bundle.Events[2:]...)
			} else {
				var control nodecontrol.Record
				if err := lifecycle.DecodeTransport(bytes.NewReader(bundle.Events[0].Raw), &control); err != nil {
					t.Fatal(err)
				}
				var metadata nodecontrol.ChildFrames
				if err := lifecycle.DecodeTransport(bytes.NewReader(control.Payload), &metadata); err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "changed-frame":
					metadata.FilterDigest = digestJSON("substituted")
				case "failed-install":
					binary.LittleEndian.PutUint64(metadata.FilterAcknowledgement[16:], 1)
				case "wrong-count":
					binary.LittleEndian.PutUint32(metadata.FilterAcknowledgement[28:], 1)
				case "unsealed":
					metadata.FilterSeals = 0
				case "release-order":
					bundle.Events[len(bundle.Events)-1].Index = 0
				}
				control.Payload = serviceJSON(metadata)
				bundle.Events[0].Raw = serviceJSON(control)
			}
			scene.Audit = serviceJSON(bundle)
			if verifyServiceLifecycleFrames(scene) == nil {
				t.Fatal("the inherited filter borrowed unmeasured or incomplete frames")
			}
		})
	}
}

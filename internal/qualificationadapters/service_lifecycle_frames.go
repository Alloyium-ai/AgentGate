// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package qualificationadapters

import (
	"bytes"
	"encoding/binary"
	"errors"
	"reflect"

	"alloyium.local/kernel-poc/internal/childwire"
	"alloyium.local/kernel-poc/internal/heldprocess"
	"alloyium.local/kernel-poc/internal/jobauthority"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"alloyium.local/kernel-poc/internal/nodecontrol"
	"alloyium.local/kernel-poc/internal/runtimeguard"
)

func verifyServiceLifecycleFrames(scene serviceLifecycleScene) error {
	bundle, err := jobauthority.DecodeAuditBundle(scene.Audit)
	if err != nil {
		return err
	}
	binding := scene.Active.Record.Binding
	var metadata *nodecontrol.ChildFrames
	frames := map[string][]byte{"job": {}, "filters": {}}
	var custodyIndex, lastChunk uint64
	positions := map[string]uint64{}
	for _, event := range bundle.Events {
		if event.Stream != nodecontrol.Stream {
			continue
		}
		var control nodecontrol.Record
		if lifecycle.DecodeTransport(bytes.NewReader(event.Raw), &control) != nil {
			return errors.New("the inherited filter control encoding differs")
		}
		switch control.Phase {
		case "child_frame_custody":
			var actual nodecontrol.ChildFrames
			if metadata != nil || lifecycle.DecodeTransport(bytes.NewReader(control.Payload), &actual) != nil || actual.Validate(binding) != nil || scene.Active.Record.Process == nil || !reflect.DeepEqual(actual.Process, *scene.Active.Record.Process) {
				return errors.New("the actual helper frame custody differs")
			}
			metadata = &actual
			custodyIndex = event.Index
		case "child_frame_chunk":
			var chunk nodecontrol.ChildFrameChunk
			if metadata == nil || lifecycle.DecodeTransport(bytes.NewReader(control.Payload), &chunk) != nil || chunk.Validate() != nil || event.Index <= custodyIndex || event.Index <= lastChunk {
				return errors.New("the actual helper frame chunk differs")
			}
			total, digest := metadata.JobBytes, metadata.JobDigest
			if chunk.Kind == "filters" {
				total, digest = metadata.FilterBytes, metadata.FilterDigest
			}
			if chunk.Total != total || chunk.Digest != digest || int(chunk.Offset) != len(frames[chunk.Kind]) {
				return errors.New("the actual helper frame chunk scope or offset differs")
			}
			frames[chunk.Kind] = append(frames[chunk.Kind], chunk.Bytes...)
			lastChunk = event.Index
		case "held", "placed", "installed_readback", "release_intent":
			if _, exists := positions[control.Phase]; exists {
				return errors.New("the inherited filter custody phase repeats")
			}
			positions[control.Phase] = event.Index
		}
	}
	if metadata == nil || len(frames["job"]) != int(metadata.JobBytes) || len(frames["filters"]) != int(metadata.FilterBytes) || digestBytes(frames["job"]) != metadata.JobDigest || digestBytes(frames["filters"]) != metadata.FilterDigest {
		return errors.New("the complete measured helper frames are absent")
	}
	previous := lastChunk
	for _, phase := range []string{"held", "placed", "installed_readback", "release_intent"} {
		index, present := positions[phase]
		if !present || index <= previous {
			return errors.New("the actual helper installation and release order differs")
		}
		previous = index
	}
	paths := scene.Recipe.Streams.Paths
	job, err := childwire.Encode(scene.Recipe.Spec.Manifest, childwire.IOPaths{Input: paths.Input, Output: paths.Output, Error: paths.Error})
	if err != nil || !bytes.Equal(job, frames["job"]) {
		return errors.New("the measured helper job frame differs from the executed manifest")
	}
	plan, err := runtimeguard.Compile(*scene.Recipe.Document.Runtime)
	if err != nil {
		return err
	}
	filters, err := childwire.EncodeFilters(plan)
	if err != nil || !bytes.Equal(filters, frames["filters"]) {
		return errors.New("the supplied inherited filter differs from the fixed fixture")
	}
	ack, err := heldprocess.DecodeFilterAcknowledgement(metadata.FilterAcknowledgement)
	if err != nil || len(filters) < 20 || ack.ListenerRequired != 1 || ack.ListenerRequired != binary.LittleEndian.Uint32(filters[8:]) || ack.InitialCount != binary.LittleEndian.Uint32(filters[12:]) || ack.FinalCount != binary.LittleEndian.Uint32(filters[16:]) {
		return errors.New("the actual filter installation acknowledgement differs from its frames")
	}
	return nil
}

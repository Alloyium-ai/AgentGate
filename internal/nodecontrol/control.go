// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package nodecontrol binds node control evidence to the complete signed job.
package nodecontrol

import (
	"alloyium.local/kernel-poc/internal/enforcement"
	"alloyium.local/kernel-poc/internal/jobaudit"
	"alloyium.local/kernel-poc/internal/lifecycle"
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
)

const Protocol = "agentgate.node-control.v1"
const Stream = "node"
const Version = "nodecontrol.v1"

type Record struct {
	Protocol string            `json:"protocol"`
	Binding  lifecycle.Binding `json:"binding"`
	Phase    string            `json:"phase"`
	Payload  json.RawMessage   `json:"payload"`
}

func copyBinding(b lifecycle.Binding) lifecycle.Binding {
	raw, _ := json.Marshal(b)
	var out lifecycle.Binding
	_ = json.Unmarshal(raw, &out)
	return out
}
func Encode(binding lifecycle.Binding, phase string, payload any) ([]byte, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	record := Record{Protocol: Protocol, Binding: copyBinding(binding), Phase: phase, Payload: raw}
	wire, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	if _, err = Decoder(binding)(wire); err != nil {
		return nil, err
	}
	return wire, nil
}
func Decoder(expected lifecycle.Binding) jobaudit.Decoder {
	expected = copyBinding(expected)
	return func(raw []byte) (jobaudit.Observation, error) {
		var c Record
		if err := lifecycle.DecodeTransport(bytes.NewReader(raw), &c); err != nil {
			return jobaudit.Observation{}, err
		}
		if c.Protocol != Protocol || c.Binding.Validate(false) != nil || !reflect.DeepEqual(c.Binding, expected) || c.Phase == "" || len(c.Phase) > 128 || !json.Valid(c.Payload) {
			return jobaudit.Observation{}, errors.New("the complete node control binding differs")
		}
		out := jobaudit.Observation{CgroupID: c.Binding.CgroupID, Generation: c.Binding.Generation, ControlPhase: c.Phase}
		if c.Phase == "observer_binding_readback" {
			var proof ObserverBinding
			if lifecycle.DecodeTransport(bytes.NewReader(c.Payload), &proof) != nil || proof.Validate(expected) != nil {
				return jobaudit.Observation{}, errors.New("the observer map readback control is invalid")
			}
		}
		if c.Phase == "child_frame_custody" {
			var p ChildFrames
			if lifecycle.DecodeTransport(bytes.NewReader(c.Payload), &p) != nil || p.Validate(expected) != nil {
				return jobaudit.Observation{}, errors.New("the child frame custody control differs")
			}
		}
		if c.Phase == "child_frame_chunk" {
			var p ChildFrameChunk
			if lifecycle.DecodeTransport(bytes.NewReader(c.Payload), &p) != nil || p.Validate() != nil {
				return jobaudit.Observation{}, errors.New("the child frame chunk control differs")
			}
		}
		if c.Phase == "installed_readback" {
			var p enforcement.InstalledReadback
			if lifecycle.DecodeTransport(bytes.NewReader(c.Payload), &p) != nil {
				return jobaudit.Observation{}, errors.New("the installed raw control is invalid")
			}
			q, err := p.Resources.Tables()
			if err != nil || q.Files.ExpiresNS > expected.DeadlineNS || p.Validate(expected.CgroupID, expected.Generation, q.Files.ExpiresNS) != nil {
				return jobaudit.Observation{}, errors.New("the installed raw control lifetime differs")
			}
		}
		if c.Phase == "domain_empty_readback" {
			var p DomainEmpty
			if lifecycle.DecodeTransport(bytes.NewReader(c.Payload), &p) != nil || p.Validate() != nil {
				return jobaudit.Observation{}, errors.New("the empty-domain raw control is invalid")
			}
		}
		if c.Phase == "quarantine_readback" {
			var tables enforcement.ResourceReadbackWire
			if lifecycle.DecodeTransport(bytes.NewReader(c.Payload), &tables) != nil || tables.Validate() != nil || tables.Domain != expected.CgroupID {
				return jobaudit.Observation{}, errors.New("the quarantine readback is not a zero-rights baseline")
			}
		}
		if c.Phase == "runtime_files_verified" {
			var proof RuntimeFiles
			if lifecycle.DecodeTransport(bytes.NewReader(c.Payload), &proof) != nil || proof.Validate(c.Binding) != nil {
				return jobaudit.Observation{}, errors.New("the runtime file control payload is invalid")
			}
		}
		if c.Phase == "grant_expiry_bound" {
			var bound jobaudit.GrantExpiry
			if lifecycle.DecodeTransport(bytes.NewReader(c.Payload), &bound) != nil || bound.Validate(c.Binding, bound.ExpiresAt) != nil {
				return jobaudit.Observation{}, errors.New("the grant expiry control payload is invalid")
			}
			out.GrantExpiry = &bound
		}
		return out, nil
	}
}

// Registry returns a copy. Each job receives its own exact binding decoder.
func Registry(base jobaudit.Registry, binding lifecycle.Binding) jobaudit.Registry {
	out := jobaudit.Registry{}
	for name, decode := range base {
		out[name] = decode
	}
	out[Stream+"/"+Version] = Decoder(binding)
	return out
}

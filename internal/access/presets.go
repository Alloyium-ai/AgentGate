// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package access

import (
	_ "embed"
	"errors"
	"fmt"
	"sort"

	"alloyium.local/kernel-poc/internal/hostproto"
	"alloyium.local/kernel-poc/internal/pocpolicy"
)

// These are byte-for-byte copies of poc/ssh-diagnostic/presets.json and
// policy.full.example.json. TestEmbeddedPresetDataMatchesThePOC fails when
// either copy drifts, and the parity test checks that both implementations
// resolve the presets to the same documents.
var (
	//go:embed presets.json
	presetsJSON []byte
	//go:embed policy.full.example.json
	fullExampleJSON []byte
)

// Preset is a named set of web, filesystem and process sections.
type Preset struct {
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Web         []string             `json:"web"`
	Filesystem  pocpolicy.Filesystem `json:"filesystem"`
	Process     pocpolicy.Process    `json:"process"`
}

// FullExample returns the shipped version two example policy.
func FullExample() (pocpolicy.Document, error) {
	return pocpolicy.Parse(fullExampleJSON)
}

type presetItem struct {
	Description string                `json:"description"`
	Web         []string              `json:"web"`
	Filesystem  *pocpolicy.Filesystem `json:"filesystem"`
	Process     *pocpolicy.Process    `json:"process"`
	FromExample string                `json:"from_example"`
}

// Presets returns every named preset.
func Presets() (map[string]Preset, error) {
	var file struct {
		Version string                `json:"version"`
		Presets map[string]presetItem `json:"presets"`
	}
	if err := hostproto.DecodeStrict(presetsJSON, &file); err != nil {
		return nil, fmt.Errorf("presets: %w", err)
	}
	if file.Version != "agentgate.poc-presets.v1" {
		return nil, errors.New("presets: unknown format")
	}
	example, err := FullExample()
	if err != nil {
		return nil, err
	}
	out := map[string]Preset{}
	for name, item := range file.Presets {
		p := Preset{Name: name, Description: item.Description}
		switch {
		case item.FromExample == "policy.full.example.json" && item.Filesystem == nil && item.Process == nil && item.Web == nil:
			p.Filesystem, p.Process = *clone(example).Filesystem, *clone(example).Process
			current := CurrentWeb(example)
			for _, n := range webOrder {
				if current[n] {
					p.Web = append(p.Web, n)
				}
			}
		case item.FromExample == "" && item.Filesystem != nil && item.Process != nil && item.Web != nil:
			p.Web, p.Filesystem, p.Process = item.Web, *item.Filesystem, *item.Process
		default:
			return nil, fmt.Errorf("presets: %s has unknown fields", name)
		}
		if _, err := webProtocols(p.Web); err != nil && len(p.Web) > 0 {
			return nil, err
		}
		if p.Web == nil {
			p.Web = []string{}
		}
		out[name] = p
	}
	return out, nil
}

// PresetNames lists the preset names in order.
func PresetNames() []string {
	presets, err := Presets()
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(presets))
	for n := range presets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// NewFromPreset builds a version two document from the full example's network
// section and the named preset's sections.
func NewFromPreset(name string) (pocpolicy.Document, error) {
	example, err := FullExample()
	if err != nil {
		return example, err
	}
	r, err := Apply(example, Edit{Action: ActionPreset, Values: []string{name}})
	if err != nil {
		return example, err
	}
	return r.Document, nil
}

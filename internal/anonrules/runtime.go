// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
// Package anonrules couples explicit eventfd rights to the file component.
package anonrules

import (
	"errors"
	"fmt"

	"alloyium.local/kernel-poc/internal/kernel"
	"github.com/cilium/ebpf"
)

const Purpose = "agentgate.anonymous-objects-component.v1"
const Delegation = uint64(1) << 63
const EventFDCreate = uint64(8)
const EventFDRead = uint64(16)
const EventFDWrite = uint64(32)

// Grant records an allocation generation and the completed object cookie.
type Grant struct{ Cookie, Domain, Generation uint64 }

var sharedMaps = []string{"owned", "policies", "file_cookies", "events", "stats"}

// Programs returns the complete mandatory anonymous object hook set.
func Programs() []string {
	return []string{"anonymous_alloc", "anonymous_use", "anonymous_receive", "anonymous_free"}
}

// Profile shares the existing file maps and leaves its single audit reader intact.
// It grants no rights. The trusted compiler activates delegation after coupling.
func Profile(access *kernel.Runtime) (kernel.Profile, error) {
	if access == nil || access.Collection == nil || access.ID == 0 || access.Domain == "" {
		return kernel.Profile{}, errors.New("anonymous guard requires a live file component")
	}
	if err := requireHooks(access.Hooks(), "fs_alloc", "fs_free", "fs_use"); err != nil {
		return kernel.Profile{}, err
	}
	replacements := make(map[string]*ebpf.Map, len(sharedMaps))
	for _, name := range sharedMaps {
		m := access.Collection.Maps[name]
		if m == nil {
			return kernel.Profile{}, fmt.Errorf("anonymous guard lacks shared map %s", name)
		}
		replacements[name] = m
	}
	return kernel.Profile{
		Initialize:  func(r *kernel.Runtime) error { return verifyMaps(access, r) },
		LSMPrograms: Programs(), MapReplacements: replacements, NoEventReader: true,
		EventsMap: "events", CountersMap: "stats",
		ProgramOptions: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats, LogSizeStart: 4 << 20},
	}, nil
}

func requireHooks(hooks []string, required ...string) error {
	installed := make(map[string]bool, len(hooks))
	for _, hook := range hooks {
		installed[hook] = true
	}
	for _, hook := range required {
		if !installed[hook] {
			return fmt.Errorf("anonymous guard lacks mandatory hook %s", hook)
		}
	}
	return nil
}

func verifyMaps(access, guard *kernel.Runtime) error {
	if access.ID != guard.ID || access.Domain != guard.Domain || guard.Collection == nil {
		return errors.New("anonymous guard domain differs")
	}
	for _, name := range sharedMaps {
		a, b := access.Collection.Maps[name], guard.Collection.Maps[name]
		if a == nil || b == nil {
			return fmt.Errorf("anonymous guard lacks shared map %s", name)
		}
		ai, err := a.Info()
		if err != nil {
			return err
		}
		bi, err := b.Info()
		if err != nil {
			return err
		}
		aid, aok := ai.ID()
		bid, bok := bi.ID()
		if !aok || !bok || aid != bid {
			return fmt.Errorf("anonymous guard map %s differs", name)
		}
	}
	var marker uint32
	if err := guard.Collection.Maps["owned"].Lookup(guard.ID, &marker); err != nil {
		return err
	}
	if marker != 1 {
		return errors.New("anonymous guard managed marker differs")
	}
	private := guard.Collection.Maps["anonymous_grants"]
	if private == nil {
		return errors.New("anonymous guard private grant map is absent")
	}
	info, err := private.Info()
	if err != nil {
		return err
	}
	if info.Type != ebpf.Hash || info.KeySize != 8 || info.ValueSize != 24 || info.MaxEntries != 65536 {
		return errors.New("anonymous guard private grant map layout differs")
	}
	return nil
}

// VerifyCoupling checks attachments and map identities before delegation enables.
func VerifyCoupling(access, guard *kernel.Runtime) error {
	if access == nil || guard == nil || access.Collection == nil || guard.Collection == nil {
		return errors.New("anonymous guard components are absent")
	}
	if access.Reader == nil || guard.Reader != nil {
		return errors.New("anonymous guard requires one file audit reader")
	}
	if err := requireHooks(guard.Hooks(), Programs()...); err != nil {
		return err
	}
	if err := requireHooks(access.Hooks(), "fs_alloc", "fs_free", "fs_use"); err != nil {
		return err
	}
	return verifyMaps(access, guard)
}

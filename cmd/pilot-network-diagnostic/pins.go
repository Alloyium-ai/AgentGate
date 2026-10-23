// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Pinned links retain kernel enforcement when this fixed diagnostic exits.
// Only an empty owned domain permits normal unpinning.
type guardPins struct {
	dir   string
	maps  []*ebpf.Map
	links []link.Link
}

func pinGuard(domain string, collection *ebpf.Collection, links []link.Link) (*guardPins, error) {
	if !ownedDiagnosticDomain(domain) || collection == nil || len(links) != len(networkAttachments) {
		return nil, errors.New("diagnostic pin binding differs")
	}
	pins := &guardPins{dir: filepath.Join("/sys/fs/bpf", "ag-mvp-net-"+filepath.Base(domain))}
	if err := os.Mkdir(pins.dir, 0700); err != nil {
		return nil, err
	}
	for name, item := range collection.Maps {
		if item == nil || name == "" || strings.ContainsAny(name, "/\\") {
			_ = pins.release()
			return nil, errors.New("diagnostic map name differs")
		}
		if err := item.Pin(filepath.Join(pins.dir, "map-"+name)); err != nil {
			_ = pins.release()
			return nil, fmt.Errorf("pin diagnostic map %s: %w", name, err)
		}
		pins.maps = append(pins.maps, item)
	}
	for index, item := range links {
		if err := item.Pin(filepath.Join(pins.dir, fmt.Sprintf("link-%d", index))); err != nil {
			_ = pins.release()
			return nil, fmt.Errorf("pin diagnostic link %d: %w", index, err)
		}
		pins.links = append(pins.links, item)
	}
	return pins, nil
}

func (pins *guardPins) release() error {
	var failures []error
	for _, item := range pins.links {
		failures = append(failures, item.Unpin())
	}
	for _, item := range pins.maps {
		failures = append(failures, item.Unpin())
	}
	failures = append(failures, os.Remove(pins.dir))
	return errors.Join(failures...)
}

func domainIsEmpty(path string) (bool, error) {
	if !ownedDiagnosticDomain(path) {
		return false, errors.New("diagnostic domain differs")
	}
	data, err := os.ReadFile(filepath.Join(path, "cgroup.events"))
	if err != nil {
		return false, err
	}
	return parsePopulation(data)
}

func parsePopulation(data []byte) (bool, error) {
	var seen, empty bool
	for _, line := range strings.Split(string(data), "\n") {
		if line == "populated 0" || line == "populated 1" {
			if seen {
				return false, errors.New("diagnostic domain population ambiguous")
			}
			seen = true
			empty = line == "populated 0"
		}
	}
	if seen {
		return empty, nil
	}
	return false, errors.New("diagnostic domain population unavailable")
}

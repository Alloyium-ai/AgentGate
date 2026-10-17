// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"alloyium.local/kernel-poc/internal/anonrules"
	"alloyium.local/kernel-poc/internal/fsrules"
	"alloyium.local/kernel-poc/internal/kernel"
	"alloyium.local/kernel-poc/internal/netrules"
	"alloyium.local/kernel-poc/internal/processrules"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"unsafe"
)

// QuarantineReadback retains actual tables and map identities before installation.
type QuarantineReadback struct {
	Domain          uint64              `json:"domain,string"`
	Files           fsrules.State       `json:"files"`
	Peers           netrules.Policy     `json:"peers"`
	Sockets         netrules.SocketPlan `json:"sockets"`
	Custody         [2]uint64           `json:"custody"`
	Process         processrules.State  `json:"process"`
	Markers         map[string]uint32   `json:"markers"`
	MapIDs          map[string]uint32   `json:"map_ids"`
	FileShared      map[string]uint32   `json:"file_shared"`
	AnonymousShared map[string]uint32   `json:"anonymous_shared"`
}

var quarantineMaps = []string{"files/policies", "files/owned", "peers/net_policies", "sockets/sock_policies", "sockets/sock_managed", "custody/cust_bindings", "custody/cust_managed", "process/proc_policies", "process/proc_managed"}
var quarantineMarkers = []string{"files/owned", "sockets/sock_managed", "custody/cust_managed", "process/proc_managed"}

func (q QuarantineReadback) Validate() error {
	if q.Domain == 0 || q.Files != (fsrules.State{}) || q.Peers != (netrules.Policy{}) || q.Sockets != (netrules.SocketPlan{}) || q.Custody != ([2]uint64{}) || q.Process != (processrules.State{}) {
		return errors.New("the quarantine contains resource rights")
	}
	return q.validateIdentities()
}
func (q QuarantineReadback) validateIdentities() error {
	if q.Domain == 0 {
		return errors.New("the resource readback domain is absent")
	}
	if len(q.MapIDs) != len(quarantineMaps) || len(q.Markers) != len(quarantineMarkers) {
		return errors.New("the quarantine map inventory is incomplete")
	}
	seen := map[uint32]bool{}
	for _, name := range quarantineMaps {
		id := q.MapIDs[name]
		if id == 0 || seen[id] {
			return errors.New("the quarantine map identity differs")
		}
		seen[id] = true
	}
	for _, name := range quarantineMarkers {
		if q.Markers[name] != 1 {
			return errors.New("the quarantine managed marker differs")
		}
	}
	if len(q.AnonymousShared) > 0 {
		if len(q.FileShared) != 5 || len(q.AnonymousShared) != 5 {
			return errors.New("the anonymous quarantine coupling is incomplete")
		}
		for _, name := range []string{"owned", "policies", "file_cookies", "events", "stats"} {
			if q.FileShared[name] == 0 || q.FileShared[name] != q.AnonymousShared[name] {
				return errors.New("the anonymous quarantine map differs")
			}
		}
		if q.FileShared["owned"] != q.MapIDs["files/owned"] || q.FileShared["policies"] != q.MapIDs["files/policies"] {
			return errors.New("the anonymous quarantine policy map differs")
		}
	} else if len(q.FileShared) > 0 {
		return errors.New("an anonymous quarantine guard is absent")
	}
	return nil
}
func (q QuarantineReadback) Digest() (string, error) {
	if err := q.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(q)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ReadQuarantine verifies the actual deny tables under the installation lock.
func (g *Group) ReadQuarantine() (QuarantineReadback, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed || g.generation != 0 || g.Files == nil {
		return QuarantineReadback{}, errors.New("the group is not an uninstalled quarantine")
	}
	q, err := g.readResourcesLocked()
	if err != nil {
		return q, err
	}
	return q, q.Validate()
}
func (g *Group) readResourcesLocked() (QuarantineReadback, error) {
	q := QuarantineReadback{Markers: map[string]uint32{}, MapIDs: map[string]uint32{}}
	if g.closed || g.Files == nil {
		return q, errors.New("the resource runtime is closed")
	}
	q.Domain = g.Files.ID
	components := map[string]*kernel.Runtime{"files": g.Files, "peers": g.Peers, "sockets": g.Sockets, "custody": g.Custody, "process": g.Process}
	read := func(component, name string, out any, size uint32) error {
		r := components[component]
		if r == nil || r.Collection == nil || r.ID != q.Domain || r.Domain != g.Files.Domain {
			return errors.New("the quarantine component binding differs")
		}
		m := r.Collection.Maps[name]
		if m == nil {
			return fmt.Errorf("the quarantine map is absent: %s", name)
		}
		info, err := m.Info()
		if err != nil {
			return err
		}
		id, ok := info.ID()
		if !ok || id == 0 || info.KeySize != 8 || info.ValueSize != size {
			return errors.New("the quarantine map layout differs")
		}
		q.MapIDs[component+"/"+name] = uint32(id)
		return m.Lookup(q.Domain, out)
	}
	for _, entry := range []struct {
		component, name string
		value           any
		size            uint32
	}{
		{"files", "policies", &q.Files, uint32(unsafe.Sizeof(q.Files))}, {"peers", "net_policies", &q.Peers, uint32(unsafe.Sizeof(q.Peers))}, {"sockets", "sock_policies", &q.Sockets, uint32(unsafe.Sizeof(q.Sockets))}, {"custody", "cust_bindings", &q.Custody, 16}, {"process", "proc_policies", &q.Process, 24},
	} {
		if err := read(entry.component, entry.name, entry.value, entry.size); err != nil {
			return q, err
		}
	}
	for _, entry := range []struct{ component, name string }{{"files", "owned"}, {"sockets", "sock_managed"}, {"custody", "cust_managed"}, {"process", "proc_managed"}} {
		var marker uint32
		if err := read(entry.component, entry.name, &marker, 4); err != nil {
			return q, err
		}
		q.Markers[entry.component+"/"+entry.name] = marker
	}
	if g.Anonymous != nil {
		if err := anonrules.VerifyCoupling(g.Files, g.Anonymous); err != nil {
			return q, err
		}
		q.FileShared, q.AnonymousShared = map[string]uint32{}, map[string]uint32{}
		for _, name := range []string{"owned", "policies", "file_cookies", "events", "stats"} {
			for _, entry := range []struct {
				r    *kernel.Runtime
				dest map[string]uint32
			}{{g.Files, q.FileShared}, {g.Anonymous, q.AnonymousShared}} {
				info, err := entry.r.Collection.Maps[name].Info()
				if err != nil {
					return q, err
				}
				id, ok := info.ID()
				if !ok {
					return q, errors.New("the shared quarantine map identity is absent")
				}
				entry.dest[name] = uint32(id)
			}
		}
	}
	return q, q.validateIdentities()
}

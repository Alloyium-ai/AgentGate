// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const ResourceReadbackProtocol = "agentgate.resource-table-readback.v1"

// ResourceReadbackWire retains exact little-endian map values within audit bounds.
type ResourceReadbackWire struct {
	Protocol        string            `json:"protocol"`
	Domain          uint64            `json:"domain,string"`
	Files           []byte            `json:"files"`
	Peers           []byte            `json:"peers"`
	Sockets         []byte            `json:"sockets"`
	Custody         []byte            `json:"custody"`
	Process         []byte            `json:"process"`
	Markers         map[string]uint32 `json:"markers"`
	MapIDs          map[string]uint32 `json:"map_ids"`
	FileShared      map[string]uint32 `json:"file_shared"`
	AnonymousShared map[string]uint32 `json:"anonymous_shared"`
}

func copyIDs(in map[string]uint32) map[string]uint32 {
	if in == nil {
		return nil
	}
	out := map[string]uint32{}
	for name, id := range in {
		out[name] = id
	}
	return out
}
func (q QuarantineReadback) Wire() (ResourceReadbackWire, error) {
	w := ResourceReadbackWire{Protocol: ResourceReadbackProtocol, Domain: q.Domain, Markers: copyIDs(q.Markers), MapIDs: copyIDs(q.MapIDs), FileShared: copyIDs(q.FileShared), AnonymousShared: copyIDs(q.AnonymousShared)}
	for _, entry := range []struct {
		value       any
		destination *[]byte
	}{{q.Files, &w.Files}, {q.Peers, &w.Peers}, {q.Sockets, &w.Sockets}, {q.Custody, &w.Custody}, {q.Process, &w.Process}} {
		var buffer bytes.Buffer
		if err := binary.Write(&buffer, binary.LittleEndian, entry.value); err != nil {
			return w, err
		}
		*entry.destination = buffer.Bytes()
	}
	return w, nil
}
func (w ResourceReadbackWire) Tables() (QuarantineReadback, error) {
	q := QuarantineReadback{Domain: w.Domain, Markers: copyIDs(w.Markers), MapIDs: copyIDs(w.MapIDs), FileShared: copyIDs(w.FileShared), AnonymousShared: copyIDs(w.AnonymousShared)}
	if w.Protocol != ResourceReadbackProtocol {
		return q, errors.New("the resource readback protocol differs")
	}
	for _, entry := range []struct {
		raw         []byte
		destination any
		size        int
	}{{w.Files, &q.Files, 544}, {w.Peers, &q.Peers, 5168}, {w.Sockets, &q.Sockets, 12824}, {w.Custody, &q.Custody, 16}, {w.Process, &q.Process, 24}} {
		if len(entry.raw) != entry.size || binary.Size(entry.destination) != entry.size {
			return q, errors.New("the resource readback ABI differs")
		}
		if err := binary.Read(bytes.NewReader(entry.raw), binary.LittleEndian, entry.destination); err != nil {
			return q, err
		}
	}
	return q, nil
}
func (w ResourceReadbackWire) Validate() error {
	q, err := w.Tables()
	if err != nil {
		return err
	}
	return q.Validate()
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package enforcement

import "testing"

func quarantineFixture() QuarantineReadback {
	q := QuarantineReadback{Domain: 42, MapIDs: map[string]uint32{}, Markers: map[string]uint32{}}
	for i, name := range quarantineMaps {
		q.MapIDs[name] = uint32(i + 1)
	}
	for _, name := range quarantineMarkers {
		q.Markers[name] = 1
	}
	return q
}
func TestQuarantineReadbackRejectsRightsMissingMapsAndOwnership(t *testing.T) {
	if _, err := quarantineFixture().Digest(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*QuarantineReadback){
		"files":         func(q *QuarantineReadback) { q.Files.Memory = 32 },
		"file-root":     func(q *QuarantineReadback) { q.Files.Roots[0].ID = 1 },
		"peers":         func(q *QuarantineReadback) { q.Peers.Count = 1 },
		"sockets":       func(q *QuarantineReadback) { q.Sockets.Count = 1 },
		"custody":       func(q *QuarantineReadback) { q.Custody[0] = 1 },
		"process":       func(q *QuarantineReadback) { q.Process.Signals = 1 },
		"missing-map":   func(q *QuarantineReadback) { delete(q.MapIDs, "files/policies") },
		"duplicate-map": func(q *QuarantineReadback) { q.MapIDs["files/policies"] = q.MapIDs["files/owned"] },
		"unmanaged":     func(q *QuarantineReadback) { q.Markers["files/owned"] = 0 },
		"missing-guard": func(q *QuarantineReadback) { q.FileShared = map[string]uint32{"owned": 1} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			q := quarantineFixture()
			change(&q)
			if _, err := q.Digest(); err == nil {
				t.Fatal("an unsafe quarantine passed")
			}
		})
	}
}
func TestQuarantineReadbackBindsAnonymousMapIdentities(t *testing.T) {
	q := quarantineFixture()
	q.FileShared = map[string]uint32{"owned": q.MapIDs["files/owned"], "policies": q.MapIDs["files/policies"], "file_cookies": 20, "events": 21, "stats": 22}
	q.AnonymousShared = map[string]uint32{}
	for name, id := range q.FileShared {
		q.AnonymousShared[name] = id
	}
	if q.Validate() != nil {
		t.Fatal("the coupled quarantine failed")
	}
	q.AnonymousShared["file_cookies"]++
	if q.Validate() == nil {
		t.Fatal("a different cookie map passed")
	}
}

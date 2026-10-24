// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"strconv"
	"strings"

	"alloyium.local/kernel-poc/internal/access"
	"alloyium.local/kernel-poc/internal/pocpolicy"
)

// PolicyChange is one row of the structured difference between two policy
// documents, in the terms the UI's "What can this agent do?" table uses. It
// is exactly what web/src/access-model.ts diffDocuments computes; a web unit
// test compares the two on a response the real service produced.
type PolicyChange struct {
	Area   string `json:"area"`
	Field  string `json:"field"`
	Change string `json:"change"`
	Before string `json:"before,omitempty"`
	After  string `json:"after,omitempty"`
}

// noValue is how a missing scalar is shown.
const noValue = "—"

var changeWeb = []struct {
	name, label, protocol string
	port                  int
}{
	{"http", "HTTP (TCP 80)", "tcp", 80},
	{"https", "HTTPS (TCP 443)", "tcp", 443},
	{"quic", "QUIC / HTTP/3 (UDP 443)", "udp", 443},
}

func webLabels(d *pocpolicy.Document) []string {
	out := []string{}
	if d == nil {
		return out
	}
	for _, w := range changeWeb {
		for _, r := range d.Web.Rules {
			if r.Protocol == w.protocol && r.Port == w.port {
				out = append(out, w.label)
				break
			}
		}
	}
	return out
}

func mountLabels(d *pocpolicy.Document) []string {
	out := []string{}
	if d == nil || d.Filesystem == nil {
		return out
	}
	prefix := access.MountRoot + "/"
	for _, p := range d.Filesystem.ReadOnly {
		if strings.HasPrefix(p, prefix) {
			out = append(out, strings.TrimPrefix(p, prefix)+" (read-only)")
		}
	}
	for _, p := range d.Filesystem.Scratch {
		if strings.HasPrefix(p, prefix) {
			out = append(out, strings.TrimPrefix(p, prefix)+" (read-write)")
		}
	}
	return out
}

func notMounts(list []string) []string {
	out := []string{}
	for _, p := range list {
		if !strings.HasPrefix(p, access.MountRoot+"/") {
			out = append(out, p)
		}
	}
	return out
}

// PolicyChanges lists what changed from a (nil: no parent) to b.
func PolicyChanges(a *pocpolicy.Document, b pocpolicy.Document) []PolicyChange {
	out := []PolicyChange{}
	list := func(area, field string, before, after []string) {
		has := func(l []string, v string) bool {
			for _, x := range l {
				if x == v {
					return true
				}
			}
			return false
		}
		for _, v := range after {
			if !has(before, v) {
				out = append(out, PolicyChange{Area: area, Field: field, Change: "added", After: v})
			}
		}
		for _, v := range before {
			if !has(after, v) {
				out = append(out, PolicyChange{Area: area, Field: field, Change: "removed", Before: v})
			}
		}
	}
	scalar := func(area, field string, before, after *string) {
		show := func(v *string) string {
			if v == nil {
				return noValue
			}
			return *v
		}
		if show(before) != show(after) {
			out = append(out, PolicyChange{Area: area, Field: field, Change: "changed", Before: show(before), After: show(after)})
		}
	}
	str := func(s string) *string { return &s }
	field := func(d *pocpolicy.Document, get func(*pocpolicy.Document) *string) *string {
		if d == nil {
			return nil
		}
		return get(d)
	}
	bp := &b
	for _, s := range []struct {
		area, name string
		get        func(*pocpolicy.Document) *string
	}{
		{"Policy", "version", func(d *pocpolicy.Document) *string { return str(d.Version) }},
		{"Network", "default", func(d *pocpolicy.Document) *string { return str(d.Default) }},
		{"Network", "IPv6", func(d *pocpolicy.Document) *string { return str(d.IPv6) }},
	} {
		scalar(s.area, s.name, field(a, s.get), field(bp, s.get))
	}
	list("Network", "public web", webLabels(a), webLabels(bp))
	resolvers := func(d *pocpolicy.Document) []string {
		if d == nil {
			return nil
		}
		return d.DNS.Resolvers
	}
	list("Network", "DNS resolvers", resolvers(a), resolvers(bp))
	taskboard := func(d *pocpolicy.Document) *string {
		if d.Taskboard == (pocpolicy.Taskboard{}) {
			return nil
		}
		return str(d.Taskboard.Address + ":" + strconv.Itoa(d.Taskboard.Port))
	}
	scalar("Network", "task board", field(a, taskboard), field(bp, taskboard))
	fs := func(d *pocpolicy.Document) *pocpolicy.Filesystem {
		if d == nil {
			return nil
		}
		return d.Filesystem
	}
	fa, fb := fs(a), fs(bp)
	fsField := func(f *pocpolicy.Filesystem, get func(*pocpolicy.Filesystem) []string) []string {
		if f == nil {
			return nil
		}
		return get(f)
	}
	workspace := func(f *pocpolicy.Filesystem) *string {
		if f == nil {
			return nil
		}
		return str(f.Workspace)
	}
	scalar("Files", "workspace", workspace(fa), workspace(fb))
	list("Files", "write", notMounts(fsField(fa, func(f *pocpolicy.Filesystem) []string { return f.Scratch })), notMounts(fsField(fb, func(f *pocpolicy.Filesystem) []string { return f.Scratch })))
	list("Files", "read", notMounts(fsField(fa, func(f *pocpolicy.Filesystem) []string { return f.ReadOnly })), notMounts(fsField(fb, func(f *pocpolicy.Filesystem) []string { return f.ReadOnly })))
	for _, l := range []struct {
		name string
		get  func(*pocpolicy.Filesystem) []string
	}{
		{"execute", func(f *pocpolicy.Filesystem) []string { return f.Execute }},
		{"devices", func(f *pocpolicy.Filesystem) []string { return f.Devices }},
		{"deny", func(f *pocpolicy.Filesystem) []string { return f.Deny }},
	} {
		list("Files", l.name, fsField(fa, l.get), fsField(fb, l.get))
	}
	list("Mounts", "host folder", mountLabels(a), mountLabels(bp))
	signals := func(d *pocpolicy.Document) []string {
		if d == nil || d.Process == nil {
			return nil
		}
		return d.Process.Signals
	}
	list("Processes", "signals", signals(a), signals(bp))
	memory := func(f *pocpolicy.Filesystem) *string {
		if f == nil {
			return nil
		}
		if f.Memory.AnonymousExecute {
			return str("on")
		}
		return str("off")
	}
	scalar("Memory", "executable anonymous memory", memory(fa), memory(fb))
	return out
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// Change is one committed write as the change streams see it: the last audit
// id it covers and the resources it touched, "kind:id" ("launch:ID",
// "target:ID", "secret:ID", "profile:ID", "apitoken:ID", "identity:ID"), or
// a bare name for other records. "launch-log:ID" marks new launch events or
// output lines, which only the launch's own streams follow. All is set when
// the resources could not be determined; a subscriber then treats everything
// as changed. A change with neither All nor resources changed nothing a
// stream shows (for example a host heartbeat) and is never sent.
type Change struct {
	ID        int64
	Resources []string
	All       bool
}

// maxChangeRows bounds the audit rows one change is resolved from; a larger
// change is sent as All.
const maxChangeRows = 256

// changeNotifier remembers the last audit id resolved into a change.
type changeNotifier struct {
	mu       sync.Mutex
	notified int64
	primed   bool
}

// notify announces a committed write ending at audit id, plus extra
// resources the write touched without an audit row (new launch events and
// log lines). The resources are those of the audit rows appended since the
// previous change, with each job resolved to its launch, target and secret.
func (s *Store) notify(id int64, extra ...string) {
	if s.Changed == nil {
		return
	}
	c := s.changeFor(id, extra)
	if c.All || len(c.Resources) > 0 {
		s.Changed(c)
	}
}

func (s *Store) changeFor(id int64, extra []string) Change {
	n := &s.changes
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.primed {
		// The first change after start covers only its own row.
		n.notified, n.primed = id-1, true
	}
	set := map[string]bool{}
	for _, r := range extra {
		if r != "" {
			set[r] = true
		}
	}
	from := n.notified
	if id > n.notified {
		n.notified = id
	}
	if id > from {
		rows, err := s.DB.Query("SELECT resource FROM audit WHERE id>? AND id<=? ORDER BY id LIMIT ?", from, id, maxChangeRows+1)
		if err != nil {
			return Change{ID: id, All: true}
		}
		var resources []string
		for rows.Next() {
			var r string
			if rows.Scan(&r) == nil {
				resources = append(resources, r)
			}
		}
		rows.Close()
		if len(resources) > maxChangeRows {
			return Change{ID: id, All: true}
		}
		for _, r := range resources {
			if job, ok := strings.CutPrefix(r, "job:"); ok {
				var launch, target, secret string
				if s.DB.QueryRow("SELECT launch_id,target_id,secret_id FROM jobs WHERE id=?", job).Scan(&launch, &target, &secret) != nil {
					return Change{ID: id, All: true}
				}
				for _, v := range []string{"launch:" + launch, "target:" + target, "secret:" + secret} {
					if !strings.HasSuffix(v, ":") {
						set[v] = true
					}
				}
				continue
			}
			if r == "" {
				r = "other"
			}
			set[r] = true
		}
	}
	out := make([]string, 0, len(set))
	for r := range set {
		out = append(out, r)
	}
	sort.Strings(out)
	return Change{ID: id, Resources: out}
}

// changeScopes is the read scope each provisioning resource kind needs to be
// named in the change stream. A kind not listed (legacy policy records,
// sessions, keys, the database) is forwarded as the bare name "other" to an
// actor with policy:read, so the views of those records refresh without the
// stream naming them.
var changeScopes = map[string]string{
	"launch":   "launch:read",
	"target":   "target:read",
	"secret":   "secrets:admin",
	"profile":  "policy:read",
	"apitoken": "auth:write",
	"identity": "identities:admin",
}

// auditOnly are resources whose rows change nothing but the audit log:
// denials and sign-ins recorded against the API or the session.
var auditOnly = map[string]bool{"api": true, "session": true}

// visibleChange is what one actor's change stream may name of c: the
// resources whose kind it can read, "other" for the rest, "self" when the
// actor's own account changed (its roles may differ: the client reloads its
// session), and "audit" for an actor that reads the audit log (every change
// appends to it). Launch event and log markers are for the launch's own
// streams and never forwarded.
func visibleChange(a Actor, c Change) (resources []string, all, send bool) {
	if c.All {
		return nil, true, true
	}
	set := map[string]bool{}
	audited := false
	for _, r := range c.Resources {
		kind, _, hasID := strings.Cut(r, ":")
		if kind == "launch-log" {
			continue
		}
		audited = true
		scope, known := changeScopes[kind]
		switch {
		case r == a.Subject && a.Subject != "":
			set["self"] = true
		case auditOnly[r]:
		case known && hasID:
			if require(a, scope, false) == nil {
				set[r] = true
			}
		case require(a, "policy:read", false) == nil:
			set["other"] = true
		}
	}
	if audited && require(a, "audit:read", false) == nil {
		set["audit"] = true
	}
	for r := range set {
		resources = append(resources, r)
	}
	sort.Strings(resources)
	return resources, false, len(resources) > 0
}

// touches reports whether c names one of the resources (or is All).
func (c Change) touches(resources ...string) bool {
	if c.All {
		return true
	}
	for _, have := range c.Resources {
		for _, want := range resources {
			if have == want {
				return true
			}
		}
	}
	return false
}

// changeInterval is the shortest gap between two changed events on one
// stream: changes in between are merged into the next event.
var changeInterval = time.Second

// changeBatch merges changes for one stream between sends. More than
// maxBatchResources distinct resources are sent as All.
type changeBatch struct {
	resources map[string]bool
	all       bool
	id        int64
}

const maxBatchResources = 64

func (b *changeBatch) add(resources []string, all bool, id int64) {
	if b.resources == nil {
		b.resources = map[string]bool{}
	}
	if id > b.id {
		b.id = id
	}
	if all {
		b.all = true
		return
	}
	for _, r := range resources {
		b.resources[r] = true
	}
	if len(b.resources) > maxBatchResources {
		b.all = true
	}
}

func (b *changeBatch) pending() bool { return b.all || len(b.resources) > 0 }

// take returns the merged change and empties the batch.
func (b *changeBatch) take() (int64, []string, bool) {
	var out []string
	if !b.all {
		for r := range b.resources {
			out = append(out, r)
		}
		sort.Strings(out)
	}
	id, all := b.id, b.all
	b.resources, b.all = nil, false
	return id, out, all
}

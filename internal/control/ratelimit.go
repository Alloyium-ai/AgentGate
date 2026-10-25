// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"container/list"
	"net/netip"
	"time"
)

// Request rate limits: one-minute fixed windows per key, kept in bounded
// tables. Each family of keys has its own table, so a flood of one family
// cannot evict another's buckets: API requests from many client addresses
// never push out sign-in or password buckets, and the buckets of
// authenticated hosts (keyed by host id, reachable only with a valid host
// signature) live apart from every unauthenticated key. A full table never
// refuses a new key. It evicts its least recently used bucket, so a client
// it has not seen still gets a fresh window; a flood spread over many keys
// mostly evicts the flooder's own idle buckets. An IPv6 client is keyed by
// its /56 (a common customer allocation), and one /48 holds at most
// rateGroupLimit buckets in a table: the further /56s of that /48 share one
// bucket for the /48, so a single /48 tunnel allocation cannot fill a table.
const (
	rateWindow     = time.Minute
	rateGroupLimit = 16
)

type rateFamily struct {
	ceiling, size int
	// byAddress marks a family keyed by client address (IPv6 /56 keys are
	// grouped by /48).
	byAddress bool
}

// rateFamilies are the client-keyed families: requests per window and table
// size. Total memory is bounded by the sum of the sizes.
var rateFamilies = map[string]rateFamily{
	"ip":       {ceiling: 1200, size: 4096, byAddress: true},
	"auth":     {ceiling: 120, size: 2048, byAddress: true},
	"password": {ceiling: 10, size: 2048, byAddress: true},
	"hostfail": {ceiling: 120, size: 1024, byAddress: true},
	"enroll":   {ceiling: 10, size: 1024, byAddress: true},
	"actor":    {ceiling: 120, size: 2048},
}

// hostFamilies are keyed by an authenticated host id, in one table of
// hostTableSize buckets.
var hostFamilies = map[string]int{"host": 1200, "resync": 10}

const hostTableSize = 2048

type rateBucket struct {
	key, group string
	count      int
	reset      time.Time
}

type rateTable struct {
	size   int
	byKey  map[string]*list.Element
	order  *list.List // front: most recently used
	groups map[string]int
}

func newRateTable(size int) *rateTable {
	return &rateTable{size: size, byKey: map[string]*list.Element{}, order: list.New(), groups: map[string]int{}}
}

// take counts one request for key, whose IPv6 /48 is group ("" for none),
// and reports whether its window is over ceiling. The caller holds the lock.
func (t *rateTable) take(key, group string, ceiling int, now time.Time) bool {
	if e, ok := t.byKey[key]; ok {
		b := e.Value.(*rateBucket)
		t.order.MoveToFront(e)
		if now.After(b.reset) {
			b.count, b.reset = 0, now.Add(rateWindow)
		}
		b.count++
		return b.count > ceiling
	}
	if group != "" && t.groups[group] >= rateGroupLimit {
		return t.take("group:"+group, "", ceiling, now)
	}
	for len(t.byKey) >= t.size {
		t.evict()
	}
	t.byKey[key] = t.order.PushFront(&rateBucket{key: key, group: group, count: 1, reset: now.Add(rateWindow)})
	if group != "" {
		t.groups[group]++
	}
	return 1 > ceiling
}

func (t *rateTable) evict() {
	e := t.order.Back()
	if e == nil {
		return
	}
	b := t.order.Remove(e).(*rateBucket)
	delete(t.byKey, b.key)
	if b.group != "" {
		if t.groups[b.group]--; t.groups[b.group] <= 0 {
			delete(t.groups, b.group)
		}
	}
}

func (t *rateTable) len() int { return len(t.byKey) }

// addressGroup is the /48 of an IPv6 client key ("" for anything else).
func addressGroup(client string) string {
	p, err := netip.ParsePrefix(client)
	if err != nil || !p.Addr().Is6() {
		return ""
	}
	g, _ := p.Addr().Prefix(48)
	return g.String()
}

// limited counts one request of family for client (an address key from
// clientIP, or an actor subject) and reports whether it is over the limit.
// An unknown family is always limited.
func (s *Server) limited(family, client string) bool {
	f, ok := rateFamilies[family]
	if !ok {
		return true
	}
	group := ""
	if f.byAddress {
		group = addressGroup(client)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.limits[family]
	if t == nil {
		t = newRateTable(f.size)
		s.limits[family] = t
	}
	return t.take(client, group, f.ceiling, time.Now())
}

// limitedHost counts one authenticated request of family for hostID: a host
// polls every heartbeat and uploads job events, so "host" is generous, and
// "resync" (a host restoring its state) is tight. These buckets are reached
// only after the host's signature verifies, so no unauthenticated flood can
// crowd them out.
func (s *Server) limitedHost(family, hostID string) bool {
	ceiling, ok := hostFamilies[family]
	if !ok {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hostLimits == nil {
		s.hostLimits = newRateTable(hostTableSize)
	}
	return s.hostLimits.take(family+":"+hostID, "", ceiling, time.Now())
}

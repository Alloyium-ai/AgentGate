// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Dan Metcalf
package control

import (
	"database/sql"
	"sort"
	"time"
)

// Anonymous denials (a request that never authenticated: no session, a bad
// token, an unsigned or forged host request) are audited, but never
// unboundedly: each source (client address) gets at most
// anonymousDenialsPerMinute rows per minute. Further denials from it in that
// minute are counted, and one audit.denials.suppressed row records how many
// were left out once the minute is over (on the next denial from that source
// or the next sweep). At most maxDenialSources sources are tracked; the rest
// share the source "other". An authenticated actor's denials are always
// audited (its own rate limit bounds them).
const (
	anonymousDenialsPerMinute = 20
	maxDenialSources          = 1024
)

type denialWindow struct {
	minute     int64
	count      int
	suppressed int
}

func anonymous(a Actor) bool { return a.Kind == "unknown" || a.Subject == "" }

// sampleDenial decides whether op's denial gets its own audit row, and writes
// the suppression row of a finished minute. Callers hold s.mu.
func (s *Store) sampleDenial(tx *sql.Tx, op Operation) (bool, error) {
	if !anonymous(op.Actor) || op.ProofNonce != "" {
		return true, nil
	}
	if s.denials == nil {
		s.denials = map[string]*denialWindow{}
	}
	source := op.Source
	if source == "" {
		source = "unknown"
	}
	minute := s.now().Unix() / 60
	w := s.denials[source]
	if w == nil {
		if len(s.denials) >= maxDenialSources {
			source = "other"
			w = s.denials[source]
		}
		if w == nil {
			w = &denialWindow{minute: minute}
			s.denials[source] = w
		}
	}
	if w.minute != minute {
		if err := writeSuppressed(tx, source, w); err != nil {
			return false, err
		}
		*w = denialWindow{minute: minute}
	}
	w.count++
	if w.count > anonymousDenialsPerMinute {
		w.suppressed++
		return false, nil
	}
	return true, nil
}

func writeSuppressed(tx *sql.Tx, source string, w *denialWindow) error {
	if w.suppressed == 0 {
		return nil
	}
	start := time.Unix(w.minute*60, 0).UTC().Format(time.RFC3339)
	_, err := appendAudit(tx, Operation{Actor: Actor{Subject: "agentgate-audit", Kind: "system"}, Action: "audit.denials.suppressed", Resource: "api",
		Reason: "Further anonymous denials from one source within a minute were counted, not recorded one by one", RequestID: "audit-" + newID(),
		After: map[string]any{"source": source, "suppressed": w.suppressed, "recorded": anonymousDenialsPerMinute, "minute_start": start}}, "denied")
	return err
}

// flushDenials writes the suppression rows of every finished minute and
// forgets those sources. Callers hold s.mu.
func (s *Store) flushDenials(tx *sql.Tx) error {
	minute := s.now().Unix() / 60
	sources := make([]string, 0, len(s.denials))
	for source, w := range s.denials {
		if w.minute != minute {
			sources = append(sources, source)
		}
	}
	sort.Strings(sources)
	for _, source := range sources {
		if err := writeSuppressed(tx, source, s.denials[source]); err != nil {
			return err
		}
		delete(s.denials, source)
	}
	return nil
}
